package arcmilter

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"strings"
	"time"

	"github.com/d--j/go-milter"
	"github.com/k0kubun/pp/v3"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
)

var debug bool

type ARCMilter struct {
	ctrl *rpc.Client
}

type Session struct {
	milter.NoOpMilter
	isARCSign    bool
	isDKIMSign   bool
	helo         string
	remoteAddr   net.IP
	rcptToDomain string
	mailFrom     string
	from         string
	fromDomain   string
	rcptTo       []string
	conf         *config.Config
	mmauth       *mmauth.MMAuth
	dkim2Message *dkim2Message
	dkim2Result  string
	authn        string
}

func (a *ARCMilter) Serve(l net.Listener, conf *config.Config) error {
	protocol := milter.OptNoHeaderReply |
		milter.OptNoUnknown | milter.OptNoData | milter.OptSkip |
		milter.OptRcptRej | milter.OptNoConnReply | milter.OptNoHeloReply |
		milter.OptNoMailReply | milter.OptNoRcptReply | milter.OptNoDataReply |
		milter.OptNoUnknownReply | milter.OptNoEOHReply | milter.OptNoBodyReply
	if conf.EnableDKIM2 || hasDKIM2Signing(conf) || dkim2ForwardingEnabled(conf) {
		// DKIM2 のエンベロープには受理された宛先だけを含める。
		protocol &^= milter.OptRcptRej
	}
	server := milter.NewServer(
		milter.WithMilter(func() milter.Milter {
			return &Session{conf: conf}
		}),
		milter.WithProtocol(protocol),
		milter.WithAction(milter.OptChangeFrom|milter.OptAddRcpt|milter.OptRemoveRcpt|milter.OptChangeHeader),
		milter.WithMacroRequest(milter.StageMail, []milter.MacroName{milter.MacroAuthAuthen}),
		milter.WithReadTimeout(5*time.Minute),
		milter.WithWriteTimeout(5*time.Minute),
	)
	stopCacheGC := startDKIM2CacheGC(conf)
	defer stopCacheGC()
	defer server.Close()
	log.Printf("Start milter server")
	return server.Serve(l)
}

func New(ctrl *rpc.Client) *ARCMilter {
	return &ARCMilter{
		ctrl: ctrl,
	}
}

func (a *ARCMilter) SetDebug(dbg bool) {
	debug = dbg
}

func (s *Session) logError(format string, v ...interface{}) {
	log.Printf("arcmilter: "+format, v...)
}

func (s *Session) debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf("arcmilter: "+format, v...)
	}
}

func (s *Session) closeMMAuth() {
	if s.mmauth == nil {
		return
	}
	if err := s.mmauth.Close(); err != nil {
		s.logError("s.mmauth.Close: %v", err)
	}
	s.mmauth = nil
}

func (s *Session) resetMessageState() {
	s.closeMMAuth()
	s.isARCSign = false
	s.isDKIMSign = false
	s.rcptToDomain = ""
	s.mailFrom = ""
	s.from = ""
	s.fromDomain = ""
	s.authn = ""
	s.rcptTo = nil
	s.dkim2Message = nil
	s.dkim2Result = ""
	if !s.conf.EnableDKIM2 {
		s.mmauth = mmauth.NewMMAuth()
	}
}

func (s *Session) ensureMMAuth() {
	if s.mmauth == nil {
		// DKIM2 は全 RCPT TO が揃った最初のヘッダで初期化する。
		if s.conf.EnableDKIM2 && s.conf.DKIM2Forwarding.Mode != "send" {
			var err error
			s.mmauth, err = mmauth.NewMMAuthWithOptions(mmauth.MMAuthOptions{
				EnableDKIM2: true, DKIM2Envelope: s.dkim2Envelope(),
				DKIM2MaxMessageBytes: s.conf.DKIM2MaxMessageBytes,
			})
			if err != nil {
				s.logError("DKIM2 initialization: %v", err)
			}
		}
		if s.mmauth == nil {
			s.mmauth = mmauth.NewMMAuth()
		}
		if domain, ok := s.conf.GetMatchingDomain(s.rcptToDomain); ok && s.isARCSign {
			s.mmauth.AddBodyHash(createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0))
		}
	}
}

// A Milter connection may be reused for a different SMTP connection. Neither
// its SMTP-client trust nor its authentication and message state may survive
// that boundary.
func (s *Session) NewConnection(_ milter.Modifier) error {
	s.closeMMAuth()
	conf := s.conf
	*s = Session{conf: conf}
	return nil
}

func (s *Session) Connect(host string, family string, port uint16, addr string, m milter.Modifier) (*milter.Response, error) {
	s.debugLog("Connect: %s", addr)
	s.remoteAddr = nil
	// go-milter supplies tcp4/tcp6, unix or unknown. A Unix path that happens
	// to resemble an IP address is not an SMTP-client IP address.
	if family == "tcp4" || family == "tcp6" {
		s.remoteAddr = net.ParseIP(addr)
	}
	return milter.RespContinue, nil
}

func (s *Session) Helo(name string, m milter.Modifier) (*milter.Response, error) {
	s.debugLog("Helo: %s", name)
	s.helo = name
	return milter.RespContinue, nil
}

func (s *Session) MailFrom(from string, esmtpArgs string, m milter.Modifier) (*milter.Response, error) {
	s.resetMessageState()
	s.authn = m.Get(milter.MacroAuthAuthen)
	s.mailFrom = from
	s.debugLog("MailFrom: %s", from)
	return milter.RespContinue, nil
}

func (s *Session) RcptTo(rcptTo string, esmtpArgs string, m milter.Modifier) (*milter.Response, error) {
	s.debugLog("RcptTo: %s", rcptTo)
	s.rcptTo = append(s.rcptTo, smtpPath(rcptTo))
	if !s.conf.EnableDKIM2 {
		s.ensureMMAuth()
	}

	// SMTP 認証済みもしくは IP アドレスが MyNetworks に含まれている場合は署名を行わない
	if s.authn != "" || s.conf.IsMyNetwork(s.remoteAddr) {
		return milter.RespContinue, nil
	}

	rpctToDomain, err := mmauth.ParseAddressDomain(rcptTo)
	if err != nil {
		s.logError("util.ParseAddressDomain: %v", err)
		return milter.RespContinue, nil
	}

	// 宛先が対象ドメインなら ARC 署名と BodyHash を設定
	if domain, ok := s.conf.GetMatchingDomain(rpctToDomain); ok && domain.ARC && !s.isARCSign {
		s.isARCSign = true
		s.rcptToDomain = rpctToDomain
		if s.mmauth != nil {
			s.mmauth.AddBodyHash(createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0))
		}
		return milter.RespContinue, nil
	}

	return milter.RespContinue, nil
}

func (s *Session) Header(name, value string, m milter.Modifier) (*milter.Response, error) {
	s.ensureMMAuth()
	header := []byte(name + ": " + normalizeHeaderValue(value) + "\r\n")
	s.captureDKIM2(header)
	if _, err := s.mmauth.Write(header); err != nil {
		s.logError("s.mmauth.Write: %v", err)
	}

	if strings.ToLower(name) != "from" {
		return milter.RespContinue, nil
	}

	s.from = value
	fromDomain, err := mmauth.ParseAddressDomain(value)
	if err != nil {
		s.logError("util.ParseAddressDomain: %v", err)
		s.isDKIMSign = false
		return milter.RespContinue, nil
	}
	s.fromDomain = fromDomain

	// 送信元が対象ドメインなら DKIM 署名設定
	if domain, ok := s.conf.GetMatchingDomain(s.fromDomain); ok && domain.DKIM {
		s.mmauth.AddBodyHash(createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0))
		s.isDKIMSign = true
	} else {
		s.isDKIMSign = false
	}

	return milter.RespContinue, nil
}

func (s *Session) Headers(m milter.Modifier) (*milter.Response, error) {
	s.debugLog("Headers")
	s.ensureMMAuth()
	s.captureDKIM2([]byte("\r\n"))
	if _, err := s.mmauth.Write([]byte("\r\n")); err != nil {
		s.logError("s.mmauth.Write: %v", err)
	}
	return milter.RespContinue, nil
}

func (s *Session) BodyChunk(chunk []byte, m milter.Modifier) (*milter.Response, error) {
	s.ensureMMAuth()
	s.captureDKIM2(chunk)
	if _, err := s.mmauth.Write(chunk); err != nil {
		s.logError("s.mmauth.Write: %v", err)
	}
	return milter.RespContinue, nil
}

// getKeyTypeAlgo は公開鍵のタイプから DKIM 署名アルゴリズムを判定する
func getKeyTypeAlgo(pub interface{}) (dkim.SignatureAlgorithm, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return dkim.SignatureAlgorithmRSA_SHA256, nil
	case ed25519.PublicKey:
		return dkim.SignatureAlgorithmED25519_SHA256, nil
	default:
		return "", fmt.Errorf("unknown key type: %T", pub)
	}
}

// createBodyHashConfig は BodyHash の設定用構造体を生成する
func createBodyHashConfig(canonicalization string, hashAlgo crypto.Hash, limit int64) mmauth.BodyCanonicalizationAndAlgorithm {
	return mmauth.BodyCanonicalizationAndAlgorithm{
		Body:      mmauth.Canonicalization(canonicalization),
		Algorithm: hashAlgo,
		Limit:     limit,
	}
}

// extractDKIMSigningHeaders は署名対象を選び、同名ヘッダをメール内の順序に戻す。
// mmauth の Sign が同名ヘッダを末尾から抽出するため、ここでは抽出済みの
// 署名順を渡さず、各ヘッダ名の選択数と設定順を維持して渡す。
func extractDKIMSigningHeaders(headers, keys []string) []string {
	selected := mmauth.ExtractHeadersDKIM(headers, keys)
	positions := make(map[string][]int)
	for i, h := range selected {
		name, _, _ := strings.Cut(h, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		positions[name] = append(positions[name], i)
	}
	for _, indices := range positions {
		for left, right := 0, len(indices)-1; left < right; left, right = left+1, right-1 {
			i, j := indices[left], indices[right]
			selected[i], selected[j] = selected[j], selected[i]
		}
	}
	return selected
}

func DKIMSign(s *Session, m milter.Modifier) {
	// From alone is not authorization to use a local signing key. The
	// forwarding send stage also receives reinjected external mail, so it
	// cannot be used for an initial DKIM signature even from MyNetworks.
	if !s.isDKIMSign || !s.trustedSigningSender() || s.conf.DKIM2Forwarding.Mode == "send" {
		return
	}

	if h := mmauth.ExtractHeadersDKIM(s.mmauth.Headers, []string{"DKIM-Signature"}); len(h) > 0 {
		// すでに DKIM 署名がある場合は DKIM 署名しない
		s.logError("DKIM-Signature found Skip")
		return
	}

	// 対応するドメインのキーがある場合は DKIM 署名を行う
	if domain, ok := s.conf.GetMatchingDomain(s.fromDomain); ok && domain.DKIM {
		bodyHash := s.mmauth.GetBodyHash(createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0))
		if bodyHash == "" {
			s.logError("DKIM body hash is empty")
			return
		}

		algo, err := getKeyTypeAlgo(domain.PrivateKeySigner.Public())
		if err != nil {
			s.logError("%v", err)
			return
		}

		// DKIM 署名
		dkim := dkim.Signature{
			Algorithm:        algo,
			Signature:        "",
			BodyHash:         bodyHash,
			Canonicalization: domain.HeaderCanonicalization + "/" + domain.BodyCanonicalization,
			Domain:           domain.Domain,
			Selector:         domain.Selector,
			Version:          1,
		}

		if err := dkim.Sign(extractDKIMSigningHeaders(s.mmauth.Headers, s.conf.DKIMSignHeaders),
			domain.PrivateKeySigner); err != nil {
			s.logError("dkim.Sign: %v", err)
			return
		}

		if err := m.InsertHeader(1, "DKIM-Signature", dkim.String()); err != nil {
			s.logError("DKIM Signature Insert Error: %v", err)
			return
		}
		s.mmauth.Headers = append(s.mmauth.Headers, "DKIM-Signature: "+dkim.String())
	}
}

func ARCSign(s *Session, m milter.Modifier) {
	if !s.isARCSign {
		return
	}

	if domain, ok := s.conf.GetMatchingDomain(s.rcptToDomain); ok && domain.ARC {
		if s.mmauth.AuthenticationHeaders == nil {
			s.logError("AuthenticationHeaders is nil")
			return
		}
		ah := s.mmauth.AuthenticationHeaders.ARCSignatures

		maxInstance := ah.GetMaxInstance()
		// RFC 8617 §5.1: 最新の ARC-Seal がすでに cv=fail なら追加しない。
		// 不正なチェーンでも判定できるよう、受信ヘッダから直接確認する。
		for _, h := range s.mmauth.Headers {
			seal, err := arc.ParseARCSeal(h)
			if err == nil && seal.InstanceNumber == maxInstance && seal.ChainValidation == arc.ChainValidationResultFail {
				s.logError("latest ARC-Seal has cv=fail skip ARC signing")
				return
			}
		}
		if maxInstance >= 50 {
			s.logError("ARC instance limit reached skip ARC signing")
			return
		}
		chainValidation := ah.GetARCChainValidation()

		// 署名アルゴリズムの判定
		var arcAlgo arc.SignatureAlgorithm
		switch domain.PrivateKeySigner.Public().(type) {
		case *rsa.PublicKey:
			arcAlgo = arc.SignatureAlgorithmRSA_SHA256
		case ed25519.PublicKey:
			arcAlgo = arc.SignatureAlgorithmED25519_SHA256
		default:
			s.logError("unknown key type: %T", domain.PrivateKeySigner)
			return
		}

		instanceNumber := maxInstance + 1
		signature := arc.ARCMessageSignature{
			InstanceNumber:   instanceNumber,
			Algorithm:        arcAlgo,
			Domain:           s.rcptToDomain,
			Selector:         domain.ARCSelector,
			Canonicalization: domain.HeaderCanonicalization + "/" + domain.BodyCanonicalization,
			BodyHash:         s.mmauth.GetBodyHash(createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0)),
		}
		if signature.BodyHash == "" {
			s.logError("ARC body hash is empty")
			return
		}

		if err := signature.Sign(mmauth.ExtractHeadersDKIM(s.mmauth.Headers, s.conf.ARCSignHeaders),
			domain.PrivateKeySigner); err != nil {
			s.logError("signature.Sign: %v", err)
			return
		}

		results := s.mmauth.GetAuthenticationHeader(s.remoteAddr, s.helo, s.mailFrom)
		if s.dkim2Result != "" {
			results = append(results, s.dkim2Result)
		}
		result := arc.ARCAuthenticationResults{
			InstanceNumber: instanceNumber,
			AuthServId:     s.rcptToDomain,
			Results:        results,
		}

		// ARC-Seal 署名
		seal := arc.ARCSeal{
			InstanceNumber:  instanceNumber,
			Algorithm:       arcAlgo,
			Domain:          s.rcptToDomain,
			Selector:        domain.ARCSelector,
			ChainValidation: chainValidation,
		}
		// cv=fail の署名では mmauth が今回のセットだけを署名対象にする。
		// パースできなかった受信ヘッダも含め、元のヘッダをそのまま渡す。
		headers := append([]string(nil), s.mmauth.Headers...)
		headers = append(headers, "ARC-Authentication-Results: "+result.String())
		headers = append(headers, "ARC-Message-Signature: "+signature.String())

		if err := seal.Sign(headers, domain.PrivateKeySigner); err != nil {
			s.logError("seal.Sign: %v", err)
			return
		}

		if err := m.InsertHeader(1, "ARC-Authentication-Results", result.String()); err != nil {
			s.logError("ARC-Authentication-Results Insert Error: %v", err)
			return
		}
		if err := m.InsertHeader(1, "ARC-Message-Signature", signature.String()); err != nil {
			s.logError("ARC-Message-Signature Insert Error: %v", err)
			return
		}
		if err := m.InsertHeader(1, "ARC-Seal", seal.String()); err != nil {
			s.logError("ARC-Seal Insert Error: %v", err)
			return
		}
	}
}

func (s *Session) EndOfMessage(m milter.Modifier) (*milter.Response, error) {
	s.debugLog("EndOfMessage")
	if s.mmauth == nil {
		return milter.RespContinue, nil
	}
	defer func() {
		s.mmauth = nil
		s.rcptTo = nil
		s.dkim2Message = nil
		s.dkim2Result = ""
	}()
	if err := s.mmauth.Close(); err != nil {
		s.logError("s.mmauth.Close: %v", err)
		if s.conf.EnableDKIM2 {
			// 従来ヘッダの解析失敗時も DKIM2 は独立して検証できる。
			s.mmauth.Verify()
		}
		forwarded, forwardingErr := s.processDKIM2Forwarding(m)
		if forwardingErr != nil {
			s.logError("DKIM2 forwarding: %v", forwardingErr)
			return milter.RespTempFail, nil
		}
		if forwarded == dkim2ForwardNotApplicable && s.eligibleForDKIM2InitialSigning() {
			s.logError("DKIM2 signing requires a valid parsed message: %v", err)
			return milter.RespTempFail, nil
		}
		s.logDKIM2Verification()
		return milter.RespContinue, nil
	}

	// Verify
	s.mmauth.Verify()
	forwarded, err := s.processDKIM2Forwarding(m)
	if err != nil {
		s.logError("DKIM2 forwarding: %v", err)
		return milter.RespTempFail, nil
	}
	s.logDKIM2Verification()

	// DKIM 署名
	DKIMSign(s, m)
	if forwarded == dkim2ForwardNotApplicable {
		if err := DKIM2Sign(s, m); err != nil {
			s.logError("DKIM2 signing: %v", err)
			return milter.RespTempFail, nil
		}
	}

	// ARC 署名
	ARCSign(s, m)

	s.dkim2Message = nil
	if debug {
		// MMAuth 内部のパイプや鍵を走査せず、セッション所有の値だけを表示する。
		s.debugLog("session: %s", pp.Sprint(map[string]interface{}{
			"remoteAddr": s.remoteAddr.String(), "helo": s.helo,
			"mailFrom": s.mailFrom, "fromDomain": s.fromDomain,
			"rcptToDomain": s.rcptToDomain, "isDKIMSign": s.isDKIMSign,
			"isARCSign": s.isARCSign, "dkim2Result": s.dkim2Result,
		}))
	}

	return milter.RespContinue, nil
}

func (s *Session) Abort(_ milter.Modifier) error {
	s.debugLog("Abort")

	s.closeMMAuth()
	s.isARCSign = false
	s.isDKIMSign = false
	s.rcptToDomain = ""
	s.mailFrom = ""
	s.from = ""
	s.fromDomain = ""
	s.authn = ""
	s.rcptTo = nil
	s.dkim2Message = nil
	s.dkim2Result = ""
	return nil
}

func (s *Session) Cleanup(_ milter.Modifier) {
	s.debugLog("Cleanup")

	s.closeMMAuth()
	s.rcptTo = nil
	s.dkim2Message = nil
	s.dkim2Result = ""
}
