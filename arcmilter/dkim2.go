package arcmilter

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/dkim2"
)

// 受信検証用の保持は mmauth が行う。ここでは送信署名用の原文だけを保持する。
type dkim2Message struct {
	raw      bytes.Buffer
	overflow bool
}

func hasDKIM2Signing(conf *config.Config) bool {
	for _, domain := range conf.Domains {
		if domain.DKIM2 {
			return true
		}
	}
	return false
}

// go-milter は SMTP パスの山括弧を除去する。空の MAIL FROM は <> に戻す。
func smtpPath(path string) string {
	if strings.HasPrefix(path, "<") && strings.HasSuffix(path, ">") {
		return path
	}
	return "<" + path + ">"
}

func (s *Session) dkim2Envelope() dkim2.Envelope {
	return dkim2.Envelope{MailFrom: smtpPath(s.mailFrom), RcptTo: s.rcptTo}
}

func normalizeHeaderValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\n", "\r\n")
}

func (s *Session) trustedSigningSender() bool {
	return s.authn != "" || s.conf.IsMyNetwork(s.remoteAddr)
}

func (s *Session) eligibleForDKIM2InitialSigning() bool {
	if dkim2ForwardingEnabled(s.conf) || !s.trustedSigningSender() {
		return false
	}
	fromDomain, err := normalizeDKIM2Domain(s.fromDomain)
	if err != nil {
		return false
	}
	domain, ok := s.conf.GetMatchingDomain(fromDomain)
	return ok && domain.DKIM2
}

func (s *Session) captureDKIM2(p []byte) {
	if s.dkim2Message == nil {
		if (!s.trustedSigningSender() && s.conf.DKIM2Forwarding.Mode != "receive") ||
			(!hasDKIM2Signing(s.conf) && !dkim2ForwardingEnabled(s.conf)) {
			return
		}
		s.dkim2Message = &dkim2Message{}
	}
	message := s.dkim2Message
	if message.overflow {
		return
	}
	limit := s.conf.DKIM2MaxMessageBytes
	if limit == 0 {
		limit = config.DefaultDKIM2MaxMessageBytes
	}
	if int64(len(p)) > limit-int64(message.raw.Len()) {
		message.overflow = true
		message.raw = bytes.Buffer{}
		return
	}
	_, _ = message.raw.Write(p)
}

func (s *Session) logDKIM2Verification() {
	if s.dkim2Result != "" {
		log.Printf("arcmilter: DKIM2 verification: %s", strings.TrimPrefix(s.dkim2Result, "dkim2="))
		return
	}
	result := s.mmauth.GetDKIM2Verification()
	if result.Err != nil {
		s.logError("DKIM2 verification: %v", result.Err)
	} else if result.Checked {
		log.Printf("arcmilter: DKIM2 verification: %s", result.Result.Status)
	}
}

// DKIM2 の rt= は宛先を含む。BCC メタデータを得られない Milter では、
// To/Cc に明示されている宛先だけのトランザクションに初回署名を限定する。
func visibleDKIM2Recipients(headers, recipients []string) bool {
	visible := make(map[string]bool)
	for _, field := range headers {
		name, value, _ := strings.Cut(field, ":")
		if !strings.EqualFold(name, "To") && !strings.EqualFold(name, "Cc") {
			continue
		}
		addresses, err := mail.ParseAddressList(strings.ReplaceAll(value, "\r\n", ""))
		if err != nil {
			return false
		}
		for _, address := range addresses {
			mailbox, err := dkim2Mailbox(address.Address)
			if err != nil {
				return false
			}
			visible[mailbox] = true
		}
	}
	if len(recipients) == 0 {
		return false
	}
	for _, recipient := range recipients {
		address, err := mail.ParseAddress(strings.TrimSuffix(strings.TrimPrefix(recipient, "<"), ">"))
		if err != nil {
			return false
		}
		mailbox, err := dkim2Mailbox(address.Address)
		if err != nil || !visible[mailbox] {
			return false
		}
	}
	return true
}

func hasPopulatedDKIM2BlindRecipientField(headers []string) bool {
	for _, field := range headers {
		name, value, _ := strings.Cut(field, ":")
		if (strings.EqualFold(name, "Bcc") || strings.EqualFold(name, "Resent-Bcc")) &&
			strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "")) != "" {
			return true
		}
	}
	return false
}

func dkim2Mailbox(address string) (string, error) {
	if strings.HasPrefix(address, "<") && strings.HasSuffix(address, ">") {
		address = address[1 : len(address)-1]
	}
	if len(address) == len("Postmaster") && strings.EqualFold(address, "Postmaster") {
		return "postmaster", nil
	}
	at := strings.LastIndexByte(address, '@')
	if at <= 0 {
		return "", errors.New("DKIM2 mailbox has no domain")
	}
	domain := address[at+1:]
	if strings.HasPrefix(domain, "[") {
		// Preserve the existing address-literal comparison. mmauth validates
		// literal SMTP paths before signing; IDNA applies only to DNS names.
		return address[:at+1] + strings.ToLower(domain), nil
	}
	domain, err := normalizeDKIM2Domain(domain)
	if err != nil {
		return "", err
	}
	return address[:at+1] + domain, nil
}

// DKIM2Sign は未署名の送信原文に初回署名を作る。
// 既存チェーンへの追加は processDKIM2Forwarding が受信時情報を使って行う。
func DKIM2Sign(s *Session, m milter.Modifier) error {
	// The send stage also sees forwarded external mail whose context was not
	// saved. It cannot distinguish that mail from locally originated mail.
	if dkim2ForwardingEnabled(s.conf) {
		return nil
	}
	fromDomain, err := normalizeDKIM2Domain(s.fromDomain)
	if err != nil {
		return nil
	}
	domain, ok := s.conf.GetMatchingDomain(fromDomain)
	if !ok || !domain.DKIM2 || !s.trustedSigningSender() {
		return nil
	}
	for _, field := range s.mmauth.Headers {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, "DKIM2-Signature") || strings.EqualFold(name, "Message-Instance") {
			return errors.New("existing DKIM2 fields prevent initial signing")
		}
	}
	if s.dkim2Message == nil || s.dkim2Message.overflow {
		s.logError("DKIM2 signing skipped: message capture limit exceeded or message unavailable")
		return nil
	}
	if hasPopulatedDKIM2BlindRecipientField(s.mmauth.Headers) {
		s.logError("DKIM2 signing skipped: populated Bcc or Resent-Bcc field")
		return nil
	}
	if !visibleDKIM2Recipients(s.mmauth.Headers, s.rcptTo) {
		s.logError("DKIM2 signing skipped: recipients are not all visible in To/Cc")
		return nil
	}
	selector := domain.DKIM2Selector
	if selector == "" {
		selector = domain.Selector
	}
	raw := s.dkim2Message.raw.Bytes()
	signed, err := dkim2.Sign(raw, dkim2.SignOptions{
		Domain: domain.Domain, Selector: selector, Key: domain.PrivateKeySigner,
		Envelope: s.dkim2Envelope(),
	})
	if err != nil {
		return fmt.Errorf("create DKIM2 signature: %w", err)
	}
	if err := insertDKIM2Headers(s, m, raw, signed); err != nil {
		return fmt.Errorf("apply DKIM2 signed message: %w", err)
	}
	return nil
}

var errDKIM2HeaderInsertion = errors.New("DKIM2 header insertion failed")

// insertDKIM2Headers は原文を変更していないことを確認し、追加フィールドだけを挿入する。
// 初回署名・転送署名・変更後の署名で追加フィールド数が異なっても同じ処理を使う。
func insertDKIM2Headers(s *Session, m milter.Modifier, original, signed []byte) error {
	if len(signed) <= len(original) || !bytes.HasSuffix(signed, original) {
		return errors.New("DKIM2 signing changed the original message")
	}
	before, err := dkim2.Parse(original)
	if err != nil {
		return fmt.Errorf("parse original DKIM2 message: %w", err)
	}
	after, err := dkim2.Parse(signed)
	if err != nil {
		return fmt.Errorf("parse signed DKIM2 message: %w", err)
	}
	added := len(after.Headers) - len(before.Headers)
	if added <= 0 {
		return errors.New("DKIM2 signing did not add header fields")
	}
	for i, field := range before.Headers {
		if after.Headers[added+i] != field {
			return errors.New("DKIM2 signing changed an existing header field")
		}
	}
	fields := after.Headers[:added]
	for _, field := range fields {
		name, _, _ := strings.Cut(field, ":")
		if !strings.EqualFold(name, "DKIM2-Signature") && !strings.EqualFold(name, "Message-Instance") {
			return fmt.Errorf("DKIM2 signing added unexpected header field %q", name)
		}
	}
	for i := len(fields) - 1; i >= 0; i-- {
		name, value, _ := strings.Cut(fields[i], ":")
		if err := m.InsertHeader(1, name, strings.TrimSuffix(strings.TrimPrefix(value, " "), "\r\n")); err != nil {
			return fmt.Errorf("%w: %w", errDKIM2HeaderInsertion, err)
		}
	}
	s.mmauth.Headers = append(s.mmauth.Headers, fields...)
	return nil
}
