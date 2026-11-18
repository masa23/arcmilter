package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim2"
)

type dkim2TXTRecords map[string][]string

func (r dkim2TXTRecords) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := r[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

func TestExecDKIM2(t *testing.T) {
	f := newExecTest(t)
	f.configure = func(conf map[string]interface{}) {
		conf["EnableDKIM2"] = true
		conf["Domains"].(map[string]interface{})["example.jp"].(map[string]interface{})["DKIM2"] = true
	}
	if !t.Run("build", f.build) || !t.Run("exec", f.start) {
		return
	}
	conf, err := config.Load(filepath.Join(f.dir, "test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := conf.Domains["example.jp"].PrivateKeySigner.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA fixture key")
	}
	resolver := dkim2TXTRecords{
		"default._domainkey.example.jp": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(publicKey))},
	}
	client := milter.NewClient("unix", filepath.Join(f.dir, "arcmilter.sock"))
	for _, tc := range []struct {
		name, address, authn string
		sender, from, to, cc string
		recipients           []string
		wantSign             bool
	}{
		{"MyNetworks", "127.0.0.1", "", "a@example.jp", "a@example.jp", "b@outside.example", "c@outside.example", []string{"b@outside.example", "c@outside.example"}, true},
		{"SMTP authentication", "192.0.2.1", "login-user", "a@example.jp", "a@example.jp", "b@outside.example", "c@outside.example", []string{"b@outside.example", "c@outside.example"}, true},
		{"unsigned incoming", "192.0.2.1", "", "a@outside.invalid", "a@outside.invalid", "b@example.jp", "", []string{"b@example.jp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			macros := milter.NewMacroBag()
			macros.Set(milter.MacroAuthAuthen, tc.authn)
			session, err := client.Session(macros)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			}()
			if session.ProtocolOption(milter.OptRcptRej) {
				t.Fatal("DKIM2 must not request rejected recipients")
			}
			check := func(action *milter.Action, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				if action.StopProcessing() || action.Type == milter.ActionDiscard {
					t.Fatalf("unexpected Milter action: %v", action)
				}
			}
			check(session.Conn("remote.invalid", milter.FamilyInet, 25, tc.address))
			check(session.Helo("remote.invalid"))
			check(session.Mail(tc.sender, ""))
			for _, recipient := range tc.recipients {
				check(session.Rcpt(recipient, ""))
			}
			check(session.DataStart())
			headers := [][2]string{{"From", tc.from}, {"To", tc.to}, {"Subject", "DKIM2\n integration"}}
			if tc.cc != "" {
				headers = append(headers, [2]string{"Cc", tc.cc})
			}
			var fields []string
			for _, header := range headers {
				check(session.HeaderField(header[0], header[1], nil))
				fields = append(fields, rawMilterHeader(header[0], header[1]))
			}
			check(session.HeaderEnd())
			body := "DKIM2 integration body\r\n"
			mods, action, err := session.BodyReadFrom(strings.NewReader(body))
			check(action, err)
			counts := map[string]int{}
			var authenticationResults *arc.ARCAuthenticationResults
			for _, mod := range mods {
				if mod.Type != milter.ActionInsertHeader {
					t.Fatalf("unexpected modification: %v", mod)
				}
				counts[mod.HeaderName]++
				raw := rawMilterHeader(mod.HeaderName, mod.HeaderValue)
				index := int(mod.HeaderIndex)
				if index < 0 || index > len(fields) {
					t.Fatalf("header insertion index %d exceeds %d fields", mod.HeaderIndex, len(fields))
				}
				fields = slices.Insert(fields, index, raw)
				if strings.EqualFold(mod.HeaderName, "ARC-Authentication-Results") {
					authenticationResults, err = arc.ParseARCAuthenticationResults(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if !tc.wantSign {
				if counts["DKIM2-Signature"] != 0 || counts["Message-Instance"] != 0 {
					t.Fatalf("incoming message received DKIM2 signing fields: %v", counts)
				}
				if authenticationResults == nil || !slices.Contains(authenticationResults.Results, "dkim2=none") {
					t.Fatalf("missing DKIM2 verification result: %+v", authenticationResults)
				}
				return
			}
			if counts["DKIM2-Signature"] != 1 || counts["Message-Instance"] != 1 || counts["DKIM-Signature"] != 1 {
				t.Fatalf("missing signing fields: %v", counts)
			}
			wire := []byte(strings.Join(fields, "") + "\r\n" + body)
			envelope := dkim2.Envelope{MailFrom: "<" + tc.sender + ">"}
			for _, recipient := range tc.recipients {
				envelope.RcptTo = append(envelope.RcptTo, "<"+recipient+">")
			}
			parsed, err := dkim2.Parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 1 || !slices.Equal(parsed.Signatures[0].Recipients, envelope.RcptTo) {
				t.Fatalf("signature did not retain all SMTP recipients: %+v", parsed.Signatures)
			}
			if result := dkim2.Verify(wire, envelope, dkim2.VerifyOptions{Resolver: resolver}); result.Status != dkim2.Pass {
				t.Fatalf("DKIM2 verification: %s: %v", result.Status, result.Err)
			}
		})
	}
}
