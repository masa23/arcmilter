package arcmilter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/masa23/mmauth/dkim2"
)

func TestDKIM2ForwardRecipe(t *testing.T) {
	key, _ := signingKey(t)
	incoming := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@relay.example>"}}
	outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	verification := dkim2.VerifyOptions{Resolver: dkim2Records{
		"s._domainkey.example.jp":          {record},
		"forward._domainkey.relay.example": {record},
	}}
	for _, tc := range []struct {
		name, body, extraHeaders string
		modify                   func([]byte) []byte
		unchanged                bool
		usesEncoded              bool
		mixedData                bool
	}{
		{name: "subject changed", body: "first\r\nlast\r\n", modify: func(wire []byte) []byte {
			return bytes.Replace(wire, []byte("Subject: original\r\n"), []byte("Subject: revised\r\n"), 1)
		}},
		{name: "header added", body: "body\r\n", modify: func(wire []byte) []byte {
			return append([]byte("Reply-To: relay@relay.example\r\n"), wire...)
		}},
		{name: "header removed", body: "body\r\n", modify: func(wire []byte) []byte {
			return bytes.Replace(wire, []byte("Subject: original\r\n"), nil, 1)
		}},
		{name: "repeated and folded headers", body: "body\r\n", modify: func(wire []byte) []byte {
			wire = bytes.Replace(wire, []byte("Comments: earlier\r\n"), []byte("Comments: changed\r\n"), 1)
			return bytes.Replace(wire, []byte("Comments: later\r\n\tcontinued\r\n"), nil, 1)
		}},
		{name: "footer appended", body: "first\r\nlast\r\n", modify: func(wire []byte) []byte {
			return append(wire, []byte("footer\r\n")...)
		}},
		{name: "body prefix inserted", body: "first\r\nlast\r\n", modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("notice\r\nfirst\r\nlast\r\n"))
		}},
		{name: "body middle replaced", body: "first\r\noriginal\r\nlast\r\n", modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("first\r\nchanged\r\nlast\r\n"))
		}},
		{name: "body middle removed", body: "first\r\noriginal\r\nlast\r\n", modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("first\r\nlast\r\n"))
		}},
		{name: "body deleted", body: "first\r\nlast\r\n", modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, nil)
		}},
		{name: "empty body changed", body: "", modify: func(wire []byte) []byte {
			return append(wire, []byte("footer\r\n")...)
		}},
		{name: "original without final CRLF", body: "first\r\nlast", modify: func(wire []byte) []byte {
			return append(wire, []byte(" plus footer\r\n")...)
		}},
		{name: "forwarded without final CRLF", body: "first\r\nlast\r\n", modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("first\r\nchanged"))
		}},
		{name: "unchanged non UTF8 copied", body: "\xff\r\nlast\r\n", modify: func(wire []byte) []byte {
			return append(wire, []byte("footer\r\n")...)
		}},
		{name: "non UTF8 body replaced", body: "caf\xe9\r\n", usesEncoded: true, modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("changed\r\n"))
		}},
		{name: "non UTF8 body deleted", body: "caf\xe9\r\n", usesEncoded: true, modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, nil)
		}},
		{name: "mixed UTF8 and non UTF8 body", body: "prefix\r\nplain\r\ncaf\xe9\r\n日本語\r\n\xff\r\nsuffix\r\n", usesEncoded: true, mixedData: true, modify: func(wire []byte) []byte {
			return replaceDKIM2RecipeBody(wire, []byte("prefix\r\nchanged\r\nsuffix\r\n"))
		}},
		{name: "non UTF8 header replaced", body: "body\r\n", usesEncoded: true, modify: func(wire []byte) []byte {
			return bytes.Replace(wire, []byte("Subject: caf\xe9\r\n"), []byte("Subject: changed\r\n"), 1)
		}},
		{name: "mixed UTF8 and non UTF8 headers", body: "body\r\n", extraHeaders: "Comments: caf\xe9\r\n", usesEncoded: true, mixedData: true, modify: func(wire []byte) []byte {
			return bytes.Replace(wire, []byte("Comments: caf\xe9\r\n"), []byte("Comments: changed\r\n"), 1)
		}},
		{name: "trace headers only", body: "body\r\n", unchanged: true, modify: func(wire []byte) []byte {
			return append([]byte("Received: by relay.example\r\nReceived-SPF: pass\r\nAuthentication-Results: relay.example; dkim2=pass\r\nX-ARCMilter-DKIM2-Context: opaque\r\nDKIM-Signature: ignored\r\nARC-Seal: ignored\r\nARC-Message-Signature: ignored\r\nARC-Authentication-Results: ignored\r\n"), wire...)
		}},
		{name: "header canonicalization only", body: "body\r\n", unchanged: true, modify: func(wire []byte) []byte {
			return bytes.Replace(wire, []byte("Subject: original\r\n"), []byte("subject:\t original  \r\n"), 1)
		}},
		{name: "trailing CRLF canonicalization only", body: "body", unchanged: true, modify: func(wire []byte) []byte {
			return append(wire, []byte("\r\n\r\n")...)
		}},
		{name: "unchanged", body: "body\r\n", unchanged: true, modify: func(wire []byte) []byte { return wire }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject := "original"
			if tc.name == "non UTF8 header replaced" {
				subject = "caf\xe9"
			}
			original, err := dkim2.Sign([]byte("From: alice@example.jp\r\nTo: bob@relay.example\r\nSubject: "+subject+"\r\nComments: earlier\r\nComments: later\r\n\tcontinued\r\n"+tc.extraHeaders+"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"+tc.body), dkim2.SignOptions{
				Domain: "example.jp", Selector: "s", Key: key, Envelope: incoming,
			})
			if err != nil {
				t.Fatal(err)
			}
			modified := tc.modify(bytes.Clone(original))
			recipe, err := dkim2ForwardRecipe(original, modified)
			if err != nil {
				t.Fatal(err)
			}
			if (recipe == nil) != tc.unchanged {
				t.Fatalf("recipe=%s, want unchanged=%v", recipe, tc.unchanged)
			}
			if bytes.Contains(recipe, []byte(`"u":`)) != tc.usesEncoded {
				t.Fatalf("unexpected use of non-UTF8 Recipe data: %s", recipe)
			}
			if tc.mixedData && !bytes.Contains(recipe, []byte(`"d":`)) {
				t.Fatalf("UTF8 Recipe values were unnecessarily base64-encoded: %s", recipe)
			}
			options := dkim2.SignOptions{Domain: "relay.example", Selector: "forward", Key: key, Envelope: outgoing}
			var forwarded []byte
			if recipe == nil {
				forwarded, err = dkim2.ForwardChecked(modified, incoming, verification, options)
			} else {
				forwarded, err = dkim2.ReviseChecked(original, modified, incoming, verification, recipe, options)
			}
			if err != nil {
				t.Fatalf("forward signing: %v; recipe=%s", err, recipe)
			}
			if result := dkim2.Verify(forwarded, outgoing, verification); result.Status != dkim2.Pass {
				t.Fatalf("forwarded verification: %s: %v; recipe=%s", result.Status, result.Err, recipe)
			}
			parsed, err := dkim2.Parse(forwarded)
			if err != nil {
				t.Fatal(err)
			}
			modifiedParsed, err := dkim2.Parse(modified)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(parsed.Body, modifiedParsed.Body) {
				t.Fatal("forward signing changed the forwarded body bytes")
			}
		})
	}
}

func replaceDKIM2RecipeBody(wire, body []byte) []byte {
	separator := bytes.Index(wire, []byte("\r\n\r\n")) + 4
	return append(bytes.Clone(wire[:separator]), body...)
}

func TestDKIM2ForwardRecipeCompactBodyCopies(t *testing.T) {
	// A large unchanged body must not be embedded in the Message-Instance Recipe.
	original := []byte("From: a@example.jp\r\n\r\n" + strings.Repeat("unchanged content\r\n", 10000))
	modified := append(bytes.Clone(original), []byte("footer\r\n")...)
	recipe, err := dkim2ForwardRecipe(original, modified)
	if err != nil {
		t.Fatal(err)
	}
	if string(recipe) != `{"b":[{"c":[1,10000]}]}` {
		t.Fatalf("footer Recipe copied original body as data: %s", recipe)
	}
	if dkim2RecipeDisclosesData(recipe) {
		t.Fatalf("copy-only Recipe was classified as disclosing: %s", recipe)
	}
}

func TestDKIM2ForwardRecipeDisclosureDetection(t *testing.T) {
	for _, recipe := range [][]byte{
		[]byte(`{"h":{"subject":[{"d":[" secret"]}]}}`),
		[]byte(`{"b":[{"u":["/w=="]}]}`),
	} {
		if !dkim2RecipeDisclosesData(recipe) {
			t.Fatalf("embedded old content was not detected: %s", recipe)
		}
	}
	for _, recipe := range [][]byte{
		[]byte(`{"h":{"d":[{"c":[1,1]}]}}`),
		[]byte(`{"b":[{"c":[1,2]}]}`),
	} {
		if dkim2RecipeDisclosesData(recipe) {
			t.Fatalf("copy-only Recipe was classified as disclosing: %s", recipe)
		}
	}
}

func TestDKIM2ForwardRecipeRejectsMalformedMessage(t *testing.T) {
	valid := []byte("From: a@example.jp\r\n\r\nbody\r\n")
	invalid := bytes.ReplaceAll(valid, []byte("\r\n"), []byte("\n"))
	for _, pair := range [][2][]byte{{invalid, valid}, {valid, invalid}} {
		if _, err := dkim2ForwardRecipe(pair[0], pair[1]); err == nil {
			t.Fatal("malformed message accepted for a forward Recipe")
		}
	}
}

func TestDKIM2ForwardRecipeRejectsOversizeData(t *testing.T) {
	for _, body := range []string{
		strings.Repeat("a", 50000) + "\r\n",
		strings.Repeat("\r\n", 20000),
		strings.Repeat("\xff", maxDKIM2RecipeBytes*3/4+1) + "\r\n",
		strings.Repeat("<", 8000) + "\r\n",
	} {
		original := []byte("From: a@example.jp\r\n\r\n" + body)
		modified := []byte("From: a@example.jp\r\n\r\nchanged\r\n")
		if _, err := dkim2ForwardRecipe(original, modified); err == nil || !strings.Contains(err.Error(), "field limit") {
			t.Fatalf("Recipe data exceeding a Message-Instance field was accepted: %v", err)
		}
	}
}
