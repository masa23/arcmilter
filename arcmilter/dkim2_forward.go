package arcmilter

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"syscall"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/dkim2"
)

const dkim2ContextHeader = "X-ARCMilter-DKIM2-Context"

type dkim2ForwardResult uint8

const (
	dkim2ForwardNotApplicable dkim2ForwardResult = iota
	dkim2ForwardSigned
	dkim2ForwardSkipped
)

var errDKIM2CaptureLimit = errors.New("forwarding message capture limit exceeded or message unavailable")

// Only cache availability failures may downgrade optional forwarding signing.
// Integrity, protocol, cryptographic and Milter modification errors must not be
// mistaken for a missing cache entry.
func isDKIM2CacheAvailabilityError(err error) bool {
	return errors.Is(err, errDKIM2CacheMiss) || errors.Is(err, errDKIM2CacheExpired) ||
		errors.Is(err, errDKIM2CacheCapacity) || errors.Is(err, errDKIM2CaptureLimit) ||
		errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) ||
		errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EROFS)
}

func (s *Session) handleDKIM2CacheFailure(m milter.Modifier, operation string, err error) (dkim2ForwardResult, error) {
	if s.conf.DKIM2Forwarding.CacheFailureAction == "tempfail" || !isDKIM2CacheAvailabilityError(err) {
		return dkim2ForwardNotApplicable, err
	}
	// Without the saved receiving envelope the next system cannot fully
	// verify the old chain. Draft-09 section 13.1 requires removing it before
	// forwarding when no separate arrangement exists.
	if err := s.removeDKIM2Fields(m); err != nil {
		return dkim2ForwardNotApplicable, err
	}
	log.Printf("arcmilter: DKIM2 forwarding signing skipped operation=%s reason=%v", operation, err)
	if s.conf.EnableDKIM2 && s.conf.DKIM2Forwarding.Mode == "send" {
		// The incoming chain cannot be verified against its receiving envelope
		// without this context. Do not report an absent signature or a pass.
		s.dkim2Result = "dkim2=temperror"
	}
	return dkim2ForwardSkipped, nil
}

func dkim2ForwardingEnabled(conf *config.Config) bool {
	return conf.DKIM2Forwarding.Mode == "receive" || conf.DKIM2Forwarding.Mode == "send"
}

func hasDKIM2Fields(headers []string) bool {
	for _, field := range headers {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, "DKIM2-Signature") || strings.EqualFold(name, "Message-Instance") {
			return true
		}
	}
	return false
}

// 共有ストアの内部参照トークンは受信段で置き換え、転送先へは配送しない。
func (s *Session) removeDKIM2Contexts(m milter.Modifier) ([]string, error) {
	var values []string
	for _, field := range s.mmauth.Headers {
		name, value, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	for index := len(values); index > 0; index-- {
		if err := m.ChangeHeader(index, dkim2ContextHeader, ""); err != nil {
			return nil, fmt.Errorf("remove forwarding context: %w", err)
		}
	}
	if len(values) > 0 {
		headers := s.mmauth.Headers[:0]
		for _, field := range s.mmauth.Headers {
			name, _, _ := strings.Cut(field, ":")
			if !strings.EqualFold(name, dkim2ContextHeader) {
				headers = append(headers, field)
			}
		}
		s.mmauth.Headers = headers
	}
	return values, nil
}

// removeDKIM2Fields discards a chain that cannot be fully verified at the
// next hop. Header deletion uses per-name one-based occurrence indices and
// descends so earlier indices do not shift during removal.
func (s *Session) removeDKIM2Fields(m milter.Modifier) error {
	counts := map[string]int{"DKIM2-Signature": 0, "Message-Instance": 0}
	for _, field := range s.mmauth.Headers {
		name, _, _ := strings.Cut(field, ":")
		for canonical := range counts {
			if strings.EqualFold(name, canonical) {
				counts[canonical]++
			}
		}
	}
	for _, name := range []string{"DKIM2-Signature", "Message-Instance"} {
		for index := counts[name]; index > 0; index-- {
			if err := m.ChangeHeader(index, name, ""); err != nil {
				return fmt.Errorf("remove unverified %s field: %w", name, err)
			}
		}
	}
	if counts["DKIM2-Signature"]+counts["Message-Instance"] > 0 {
		headers := s.mmauth.Headers[:0]
		for _, field := range s.mmauth.Headers {
			name, _, _ := strings.Cut(field, ":")
			if !strings.EqualFold(name, "DKIM2-Signature") && !strings.EqualFold(name, "Message-Instance") {
				headers = append(headers, field)
			}
		}
		s.mmauth.Headers = headers
	}
	return nil
}

func (s *Session) dkim2ForwardSigningDomains() []string {
	domains := make(map[string]bool)
	for _, recipient := range s.rcptTo {
		if !s.selectedDKIM2ForwardRecipient(recipient) {
			continue
		}
		name, err := mmauth.ParseAddressDomain(recipient)
		if err != nil {
			continue
		}
		name, err = normalizeDKIM2Domain(name)
		if err != nil {
			continue
		}
		if domain, ok := s.conf.GetMatchingDomain(name); ok && domain.DKIM2 {
			domains[domain.Domain] = true
		}
	}
	names := make([]string, 0, len(domains))
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func canonicalDKIM2ForwardRecipient(path string) (string, string, error) {
	path = strings.TrimSuffix(strings.TrimPrefix(path, "<"), ">")
	at := strings.LastIndexByte(path, '@')
	if at <= 0 || at == len(path)-1 || strings.ContainsAny(path, "\r\n\x00") {
		return "", "", errors.New("invalid forwarding recipient")
	}
	domain, err := normalizeDKIM2Domain(path[at+1:])
	if err != nil {
		return "", "", err
	}
	return path[:at], domain, nil
}

func (s *Session) selectedDKIM2ForwardRecipient(recipient string) bool {
	local, domain, err := canonicalDKIM2ForwardRecipient(recipient)
	if err != nil {
		return false
	}
	for _, configured := range s.conf.DKIM2Forwarding.ForwardRecipients {
		configuredLocal, configuredDomain, err := canonicalDKIM2ForwardRecipient(configured)
		if err == nil && domain == configuredDomain && (configuredLocal == "*" || local == configuredLocal) {
			return true
		}
	}
	return false
}

// The receive Milter runs before Postfix alias expansion, so forwarding
// recipients must be explicitly mirrored from the MTA configuration. A
// context header is message-wide and cannot be added to only one RCPT. To
// avoid leaking its bearer token to an ordinary local delivery, mixed SMTP
// transactions are therefore not captured at all.
func (s *Session) allDKIM2ForwardRecipientsSelected() bool {
	if len(s.rcptTo) == 0 {
		return false
	}
	for _, recipient := range s.rcptTo {
		if !s.selectedDKIM2ForwardRecipient(recipient) {
			return false
		}
	}
	return true
}

func (s *Session) dkim2ForwardRaw() ([]byte, error) {
	if s.dkim2Message == nil || s.dkim2Message.overflow {
		return nil, errDKIM2CaptureLimit
	}
	return s.dkim2Message.raw.Bytes(), nil
}

// receive は書換前の実エンベロープと原文を保存する。
// send は再投入後の実エンベロープで署名し、mf=/rt= から受信情報を推測しない。
func (s *Session) processDKIM2Forwarding(m milter.Modifier) (dkim2ForwardResult, error) {
	if !dkim2ForwardingEnabled(s.conf) {
		return dkim2ForwardNotApplicable, nil
	}
	contexts, err := s.removeDKIM2Contexts(m)
	if err != nil {
		return dkim2ForwardNotApplicable, err
	}
	if s.conf.DKIM2Forwarding.Mode == "receive" {
		return s.saveDKIM2IncomingContext(m)
	}
	if len(contexts) == 0 && !hasDKIM2Fields(s.mmauth.Headers) {
		if s.conf.EnableDKIM2 {
			s.dkim2Result = "dkim2=none"
		}
		return dkim2ForwardNotApplicable, nil
	}
	if !s.conf.IsMyNetwork(s.remoteAddr) {
		return dkim2ForwardNotApplicable, errors.New("forwarding requires a trusted MTA reinjection source in MyNetworks")
	}
	if len(contexts) == 0 {
		return s.handleDKIM2CacheFailure(m, "load", fmt.Errorf("%w: receiving context was not saved", errDKIM2CacheMiss))
	}
	if len(contexts) != 1 {
		return dkim2ForwardNotApplicable, errors.New("forwarding requires exactly one saved receiving context")
	}
	context, err := loadDKIM2ForwardContext(s.conf.DKIM2Forwarding, contexts[0])
	if err != nil {
		return s.handleDKIM2CacheFailure(m, "load", err)
	}
	raw, err := s.dkim2ForwardRaw()
	if err != nil {
		return s.handleDKIM2CacheFailure(m, "capture", err)
	}
	if err := validateDKIM2ForwardFields(context.Raw, raw); err != nil {
		return dkim2ForwardNotApplicable, err
	}
	domain, err := s.dkim2ForwardSigningDomain(context.SigningDomains)
	if err != nil {
		return dkim2ForwardNotApplicable, err
	}
	selector := domain.DKIM2Selector
	if selector == "" {
		selector = domain.Selector
	}
	options := dkim2.SignOptions{Domain: domain.Domain, Selector: selector, Key: domain.PrivateKeySigner, Envelope: s.dkim2Envelope()}
	if !visibleDKIM2Recipients(s.mmauth.Headers, s.rcptTo) {
		if len(s.rcptTo) != 1 {
			return dkim2ForwardNotApplicable, errors.New("split forwarding with hidden recipients into separate one-recipient SMTP transactions")
		}
		options.BCCRecipients = append([]string(nil), s.rcptTo...)
	}
	if s.conf.DKIM2Forwarding.MultipleDeliveries || multipleDKIM2Recipients(s.rcptTo) {
		options.Flags = []string{"exploded"}
	}
	recipe, err := dkim2ForwardRecipe(context.Raw, raw)
	if err != nil {
		return dkim2ForwardNotApplicable, fmt.Errorf("forwarding Recipe: %w", err)
	}
	if recipe != nil && dkim2RecipeDisclosesData(recipe) && !s.conf.DKIM2Forwarding.AllowRecipeDisclosure {
		return dkim2ForwardNotApplicable, errors.New("forwarding Recipe would disclose removed or redacted message content")
	}
	var signed []byte
	if recipe == nil {
		signed, err = dkim2.ForwardChecked(raw, context.Envelope, dkim2.VerifyOptions{}, options)
	} else {
		signed, err = dkim2.ReviseChecked(context.Raw, raw, context.Envelope, dkim2.VerifyOptions{}, recipe, options)
	}
	if err != nil {
		return dkim2ForwardNotApplicable, fmt.Errorf("checked forwarding signature: %w", err)
	}
	if err := insertDKIM2Headers(s, m, raw, signed); err != nil {
		return dkim2ForwardNotApplicable, err
	}
	if s.conf.EnableDKIM2 {
		s.dkim2Result = "dkim2=pass"
	}
	log.Printf("arcmilter: DKIM2 forwarding signed domain=%s revised=%t", domain.Domain, recipe != nil)
	return dkim2ForwardSigned, nil
}

func validateDKIM2ForwardFields(original, modified []byte) error {
	before, err := dkim2.Parse(original)
	if err != nil {
		return err
	}
	after, err := dkim2.Parse(modified)
	if err != nil {
		return err
	}
	if len(before.Instances) != len(after.Instances) || len(before.Signatures) != len(after.Signatures) {
		return errors.New("forwarded message changed prior DKIM2 fields")
	}
	for i := range before.Instances {
		if before.Instances[i].Raw != after.Instances[i].Raw {
			return errors.New("forwarded message changed a prior Message-Instance field")
		}
	}
	for i := range before.Signatures {
		if before.Signatures[i].Raw != after.Signatures[i].Raw {
			return errors.New("forwarded message changed a prior DKIM2-Signature field")
		}
	}
	return nil
}

func (s *Session) saveDKIM2IncomingContext(m milter.Modifier) (dkim2ForwardResult, error) {
	if !hasDKIM2Fields(s.mmauth.Headers) {
		return dkim2ForwardNotApplicable, nil
	}
	selected := s.allDKIM2ForwardRecipientsSelected()
	raw, err := s.dkim2ForwardRaw()
	if err != nil {
		if !selected {
			// A message outside the forwarding cache can still be relayed by
			// the MTA. An oversized or unavailable capture cannot establish a
			// Fully Verified chain, so remove it even in strict cache mode.
			if err := s.removeDKIM2Fields(m); err != nil {
				return dkim2ForwardNotApplicable, err
			}
			log.Printf("arcmilter: DKIM2 fields removed: incoming message could not be verified: %v", err)
			return dkim2ForwardNotApplicable, nil
		}
		return s.handleDKIM2CacheFailure(m, "capture", err)
	}
	// EndOfMessage has already called MMAuth.Verify. Reuse its complete
	// DKIM2 result when enabled, including failures, so DNS and cryptographic
	// checks are not repeated for every incoming signed message. A receive
	// stage may also run with EnableDKIM2 disabled, in which case it must
	// still verify the chain before saving a forwarding context.
	verification := s.mmauth.GetDKIM2Verification()
	result := verification.Result
	if !verification.Checked || verification.Err != nil {
		result = dkim2.Verify(raw, s.dkim2Envelope(), dkim2.VerifyOptions{})
	}
	if result.Status != dkim2.Pass {
		// The message comes from an untrusted SMTP client. A bad DKIM2 field
		// must not let that client hold the delivery queue in TEMPFAIL forever.
		// Keep the incoming verification result, but do not create a context
		// that the send stage could use to vouch for this message.
		if err := s.removeDKIM2Fields(m); err != nil {
			return dkim2ForwardNotApplicable, err
		}
		log.Printf("arcmilter: DKIM2 forwarding context not saved: incoming verification %s: %v", result.Status, result.Err)
		return dkim2ForwardNotApplicable, nil
	}
	if !selected {
		return dkim2ForwardNotApplicable, nil
	}
	domains := s.dkim2ForwardSigningDomains()
	if len(domains) == 0 {
		return dkim2ForwardNotApplicable, nil
	}
	id, err := saveDKIM2ForwardContext(s.conf.DKIM2Forwarding, s.dkim2Envelope(), domains, raw)
	if err != nil {
		return s.handleDKIM2CacheFailure(m, "save", err)
	}
	if err := m.InsertHeader(1, dkim2ContextHeader, id); err != nil {
		return dkim2ForwardNotApplicable, errors.Join(fmt.Errorf("insert receiving context: %w", err),
			removeDKIM2ForwardContext(s.conf.DKIM2Forwarding, id))
	}
	s.mmauth.Headers = append(s.mmauth.Headers, dkim2ContextHeader+": "+id+"\r\n")
	return dkim2ForwardNotApplicable, nil
}

func (s *Session) dkim2ForwardSigningDomain(names []string) (*config.Domain, error) {
	var senderDomain string
	if from := smtpPath(s.mailFrom); from != "<>" {
		var err error
		senderDomain, err = mmauth.ParseAddressDomain(from)
		if err != nil {
			return nil, fmt.Errorf("forwarding MAIL FROM: %w", err)
		}
		senderDomain, err = normalizeDKIM2Domain(senderDomain)
		if err != nil {
			return nil, fmt.Errorf("forwarding MAIL FROM: %w", err)
		}
	}
	preferred := strings.ToLower(s.conf.DKIM2Forwarding.SigningDomain)
	var candidates []*config.Domain
	seen := make(map[string]bool)
	for _, name := range names {
		name, err := normalizeDKIM2Domain(name)
		if err != nil {
			return nil, fmt.Errorf("forwarding receiving domain: %w", err)
		}
		if seen[name] || (preferred != "" && name != preferred) {
			continue
		}
		seen[name] = true
		if senderDomain != "" && senderDomain != name && !strings.HasSuffix(senderDomain, "."+name) {
			continue
		}
		if domain, ok := s.conf.GetMatchingDomain(name); ok && domain.DKIM2 {
			candidates = append(candidates, domain)
		}
	}
	if senderDomain != "" && preferred == "" && len(candidates) > 1 {
		// 親子の受信ドメインが一致する場合は、送信元に最も近いものを使う。
		sort.Slice(candidates, func(i, j int) bool { return len(candidates[i].Domain) > len(candidates[j].Domain) })
		return candidates[0], nil
	}
	if len(candidates) != 1 {
		return nil, errors.New("forwarding MAIL FROM must select one enabled receiving domain; set DKIM2Forwarding.SigningDomain to resolve ambiguous null senders")
	}
	return candidates[0], nil
}

func multipleDKIM2Recipients(recipients []string) bool {
	seen := make(map[string]bool)
	for _, recipient := range recipients {
		mailbox, err := dkim2Mailbox(recipient)
		if err != nil {
			// Invalid paths are rejected by mmauth; do not coalesce them here.
			return true
		}
		seen[mailbox] = true
		if len(seen) > 1 {
			return true
		}
	}
	return false
}
