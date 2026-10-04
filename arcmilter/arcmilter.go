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
	conf         *config.Config
	mmauth       *mmauth.MMAuth
	authn        string
}

func (a *ARCMilter) Serve(l net.Listener, conf *config.Config) error {
	server := milter.NewServer(
		milter.WithMilter(func() milter.Milter {
			return &Session{conf: conf}
		}),
		milter.WithProtocol(milter.OptNoHeaderReply|
			milter.OptNoUnknown|milter.OptNoData|milter.OptSkip|
			milter.OptRcptRej|milter.OptNoConnReply|milter.OptNoHeloReply|
			milter.OptNoMailReply|milter.OptNoRcptReply|milter.OptNoDataReply|
			milter.OptNoUnknownReply|milter.OptNoEOHReply|milter.OptNoBodyReply),
		milter.WithAction(milter.OptChangeFrom|milter.OptAddRcpt|milter.OptRemoveRcpt|milter.OptChangeHeader),
		milter.WithMacroRequest(milter.StageMail, []milter.MacroName{milter.MacroAuthAuthen}),
	)
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
	s.mmauth = mmauth.NewMMAuth()
}

func (s *Session) ensureMMAuth() {
	if s.mmauth == nil {
		s.mmauth = mmauth.NewMMAuth()
	}
}

func (s *Session) Connect(host string, family string, port uint16, addr string, m milter.Modifier) (*milter.Response, error) {
	s.debugLog("Connect: %s", addr)
	if ip := net.ParseIP(addr); ip != nil {
		s.remoteAddr = ip
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
	s.ensureMMAuth()

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
		s.mmauth.AddBodyHash(
			createBodyHashConfig(domain.BodyCanonicalization, domain.HashAlgo, 0),
		)
		return milter.RespContinue, nil
	}

	return milter.RespContinue, nil
}

func (s *Session) Header(name, value string, m milter.Modifier) (*milter.Response, error) {
	s.ensureMMAuth()
	if _, err := s.mmauth.Write([]byte(name + ": " + value + "\r\n")); err != nil {
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
	if _, err := s.mmauth.Write([]byte("\r\n")); err != nil {
		s.logError("s.mmauth.Write: %v", err)
	}
	return milter.RespContinue, nil
}

func (s *Session) BodyChunk(chunk []byte, m milter.Modifier) (*milter.Response, error) {
	s.ensureMMAuth()
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
	if !s.isDKIMSign {
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
	if err := s.mmauth.Close(); err != nil {
		s.logError("s.mmauth.Close: %v", err)
		s.mmauth = nil
		return milter.RespContinue, nil
	}

	// Verify
	s.mmauth.Verify()

	// DKIM 署名
	DKIMSign(s, m)

	// ARC 署名
	ARCSign(s, m)

	s.debugLog("session: %s", pp.Sprint(s))
	s.mmauth = nil

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
	return nil
}

func (s *Session) Cleanup(_ milter.Modifier) {
	s.debugLog("Cleanup")

	s.closeMMAuth()
}
