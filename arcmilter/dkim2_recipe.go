package arcmilter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/masa23/mmauth/dkim2"
)

type dkim2RecipeStep struct {
	Copy    []int    `json:"c,omitempty"`
	Data    []string `json:"d,omitempty"`
	Encoded []string `json:"u,omitempty"`
}

type dkim2Recipe struct {
	Headers map[string][]dkim2RecipeStep `json:"h,omitempty"`
	Body    *[]dkim2RecipeStep           `json:"b,omitempty"`
}

// dkim2RecipeDisclosesData reports whether a Recipe embeds bytes from the
// message before forwarding. Such d/u steps let a recipient recover content
// that an intermediate filter removed or redacted, so they require an
// explicit forwarding policy opt-in.
func dkim2RecipeDisclosesData(encoded []byte) bool {
	var recipe dkim2Recipe
	if json.Unmarshal(encoded, &recipe) != nil {
		return true // An unexpected internal encoding must fail closed.
	}
	discloses := func(steps []dkim2RecipeStep) bool {
		for _, step := range steps {
			if len(step.Data) != 0 || len(step.Encoded) != 0 {
				return true
			}
		}
		return false
	}
	for _, steps := range recipe.Headers {
		if discloses(steps) {
			return true
		}
	}
	return recipe.Body != nil && discloses(*recipe.Body)
}

// The resulting Message-Instance field is limited to 64 KiB. Leave room for
// base64 expansion, folding, the instance number, and SHA-256 hash tags.
const maxDKIM2RecipeBytes = 45 << 10

// Draft-09 uses d for UTF-8 and u for arbitrary octets. Keep adjacent values
// of the same kind together without changing their reconstruction order.
type dkim2RecipeDataBuilder struct {
	steps []dkim2RecipeStep
	bytes int
}

func (b *dkim2RecipeDataBuilder) append(value string) error {
	if len(value) > maxDKIM2RecipeBytes {
		return fmt.Errorf("data exceeds the Message-Instance field limit")
	}
	encoded := !utf8.ValidString(value)
	if encoded {
		if base64.StdEncoding.EncodedLen(len(value)) > maxDKIM2RecipeBytes {
			return fmt.Errorf("data exceeds the Message-Instance field limit")
		}
		value = base64.StdEncoding.EncodeToString([]byte(value))
	}
	quoted, err := json.Marshal(value)
	if err != nil {
		return err
	}
	newStep := len(b.steps) == 0
	if !newStep {
		last := b.steps[len(b.steps)-1]
		newStep = encoded != (len(last.Encoded) > 0)
	}
	size := b.bytes
	if size == 0 {
		size = 2 // Outer array brackets.
	}
	if newStep {
		size += 8 // {"d":[]} or {"u":[]} around the encoded strings.
		if len(b.steps) > 0 {
			size++ // Separator between steps.
		}
	} else {
		size++ // Separator between strings in a step.
	}
	size += len(quoted)
	if size > maxDKIM2RecipeBytes {
		return fmt.Errorf("data exceeds the Message-Instance field limit")
	}
	if newStep {
		b.steps = append(b.steps, dkim2RecipeStep{})
	}
	last := &b.steps[len(b.steps)-1]
	if encoded {
		last.Encoded = append(last.Encoded, value)
	} else {
		last.Data = append(last.Data, value)
	}
	b.bytes = size
	return nil
}

// dkim2ForwardRecipe builds the inverse transformation from the forwarded
// message to its received instance. Trace fields are excluded by DKIM2.
func dkim2ForwardRecipe(original, modified []byte) ([]byte, error) {
	before, err := dkim2.Parse(original)
	if err != nil {
		return nil, fmt.Errorf("DKIM2 original message: %w", err)
	}
	after, err := dkim2.Parse(modified)
	if err != nil {
		return nil, fmt.Errorf("DKIM2 forwarded message: %w", err)
	}
	oldHeaders := dkim2RecipeHeaders(before.Headers)
	newHeaders := dkim2RecipeHeaders(after.Headers)
	names := make(map[string]bool, len(oldHeaders)+len(newHeaders))
	for name := range oldHeaders {
		names[name] = true
	}
	for name := range newHeaders {
		names[name] = true
	}
	recipe := dkim2Recipe{Headers: make(map[string][]dkim2RecipeStep)}
	for name := range names {
		oldFields, newFields := oldHeaders[name], newHeaders[name]
		if equalDKIM2RecipeHeaders(oldFields, newFields) {
			continue
		}
		data := dkim2RecipeDataBuilder{}
		if len(oldFields) > 0 {
			// A header Recipe enumerates each group from the bottom upward.
			for i := len(oldFields) - 1; i >= 0; i-- {
				_, value, _ := strings.Cut(oldFields[i], ":")
				value = strings.ReplaceAll(strings.TrimSuffix(value, "\r\n"), "\r\n", "")
				if err := data.append(value); err != nil {
					return nil, fmt.Errorf("DKIM2 header Recipe %s: %w", name, err)
				}
			}
		}
		// An empty array removes a newly added header group.
		if data.steps == nil {
			data.steps = make([]dkim2RecipeStep, 0)
		}
		recipe.Headers[name] = data.steps
	}
	if !bytes.Equal(dkim2RecipeCanonicalBody(before.Body), dkim2RecipeCanonicalBody(after.Body)) {
		steps, err := dkim2BodyRecipe(before.Body, after.Body)
		if err != nil {
			return nil, err
		}
		recipe.Body = &steps
	}
	if len(recipe.Headers) == 0 && recipe.Body == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(recipe)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxDKIM2RecipeBytes {
		return nil, fmt.Errorf("DKIM2 Recipe exceeds the Message-Instance field limit")
	}
	return encoded, nil
}

func dkim2RecipeHeaders(fields []string) map[string][]string {
	groups := make(map[string][]string)
	for _, field := range fields {
		name, _, _ := strings.Cut(field, ":")
		name = strings.ToLower(name)
		if !dkim2RecipeUnsignedHeader(name) {
			groups[name] = append(groups[name], field)
		}
	}
	return groups
}

// Keep this list aligned with mmauth/dkim2's unsigned fields (draft-09).
func dkim2RecipeUnsignedHeader(name string) bool {
	if strings.HasPrefix(name, "x-") || strings.HasPrefix(name, "received-") {
		return true
	}
	switch name {
	case "apparently-to", "arc-authentication-results", "arc-message-signature", "arc-seal",
		"authentication-results", "delivered-to", "dkim-signature", "dl-expansion-history",
		"original-recipient", "received", "return-path", "sio-label-history", "x400-received",
		"x400-trace", "message-instance", "dkim2-signature":
		return true
	}
	return false
}

func equalDKIM2RecipeHeaders(before, after []string) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if canonicalDKIM2RecipeHeader(before[i]) != canonicalDKIM2RecipeHeader(after[i]) {
			return false
		}
	}
	return true
}

func canonicalDKIM2RecipeHeader(field string) string {
	name, value, _ := strings.Cut(field, ":")
	value = strings.ReplaceAll(strings.TrimSuffix(value, "\r\n"), "\r\n", "")
	var canonical strings.Builder
	canonical.WriteString(strings.ToLower(name))
	canonical.WriteByte(':')
	space := false
	value = strings.Trim(value, " \t")
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space {
			canonical.WriteByte(' ')
			space = false
		}
		canonical.WriteByte(c)
	}
	return canonical.String()
}

func dkim2RecipeCanonicalBody(body []byte) []byte {
	for bytes.HasSuffix(body, []byte("\r\n")) {
		body = body[:len(body)-2]
	}
	return body
}

// Copy shared leading/trailing lines and disclose only the replaced portion.
// Scan offsets instead of indexing every line in CRLF-dense bounded messages.
func dkim2BodyRecipe(before, after []byte) ([]dkim2RecipeStep, error) {
	oldStart, newStart, prefix := 0, 0, 0
	for oldStart < len(before) && newStart < len(after) {
		oldLine, oldNext := dkim2RecipeFirstLine(before, oldStart)
		newLine, newNext := dkim2RecipeFirstLine(after, newStart)
		if !bytes.Equal(oldLine, newLine) {
			break
		}
		oldStart, newStart = oldNext, newNext
		prefix++
	}
	oldEnd, newEnd, suffix := len(before), len(after), 0
	for oldEnd > oldStart && newEnd > newStart {
		oldLine, oldPrevious := dkim2RecipeLastLine(before, oldEnd)
		newLine, newPrevious := dkim2RecipeLastLine(after, newEnd)
		if !bytes.Equal(oldLine, newLine) {
			break
		}
		oldEnd, newEnd = oldPrevious, newPrevious
		suffix++
	}
	steps := make([]dkim2RecipeStep, 0, 3)
	if prefix > 0 {
		steps = append(steps, dkim2RecipeStep{Copy: []int{1, prefix}})
	}
	if oldStart < oldEnd {
		data := dkim2RecipeDataBuilder{}
		for oldStart < oldEnd {
			line, next := dkim2RecipeFirstLine(before[:oldEnd], oldStart)
			if err := data.append(string(line)); err != nil {
				return nil, fmt.Errorf("DKIM2 body Recipe: %w", err)
			}
			oldStart = next
		}
		steps = append(steps, data.steps...)
	}
	if suffix > 0 {
		total := bytes.Count(after, []byte("\r\n"))
		if len(after) > 0 && !bytes.HasSuffix(after, []byte("\r\n")) {
			total++
		}
		steps = append(steps, dkim2RecipeStep{Copy: []int{total - suffix + 1, total}})
	}
	// Recipe operations always terminate reconstructed lines with CRLF. DKIM2
	// simple body canonicalization makes that equivalent for an unterminated
	// last line; the forwarded message's own body bytes remain untouched.
	return steps, nil
}

func dkim2RecipeFirstLine(body []byte, offset int) ([]byte, int) {
	if end := bytes.Index(body[offset:], []byte("\r\n")); end >= 0 {
		return body[offset : offset+end], offset + end + 2
	}
	return body[offset:], len(body)
}

func dkim2RecipeLastLine(body []byte, end int) ([]byte, int) {
	contentEnd := end
	if bytes.HasSuffix(body[:end], []byte("\r\n")) {
		contentEnd -= 2
	}
	start := 0
	if previous := bytes.LastIndex(body[:contentEnd], []byte("\r\n")); previous >= 0 {
		start = previous + 2
	}
	return body[start:contentEnd], start
}
