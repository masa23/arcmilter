package arcmilter

import (
	"context"
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
	"github.com/masa23/arcmilter/mmauth"
	"github.com/masa23/arcmilter/mmauth/arc"
	"github.com/masa23/arcmilter/mmauth/dkim"
	"github.com/wttw/spf"
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
		milter.WithMacroRequest(milter.StageHelo, []milter.MacroName{milter.MacroAuthAuthen}),
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

func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf(format, v...)
	}
}

func (s *Session) Connect(host string, family string, port uint16, addr string, m *milter.Modifier) (*milter.Response, error) {
	debugLog("Connect: %s", addr)
	s.mmauth = mmauth.NewMMAuth()
	if ip := net.ParseIP(addr); ip != nil {
		s.remoteAddr = ip
	}
	return milter.RespContinue, nil
}

func (s *Session) Helo(name string, m *milter.Modifier) (*milter.Response, error) {
	debugLog("Helo: %s", name)
	s.helo = name
	return milter.RespContinue, nil
}

func (s *Session) MailFrom(from string, esmtpArgs string, m *milter.Modifier) (*milter.Response, error) {
	s.authn = m.Macros.Get(milter.MacroAuthAuthen)
	s.mailFrom = from
	debugLog("MailFrom: %s", from)
	return milter.RespContinue, nil
}

func (s *Session) RcptTo(rcptTo string, esmtpArgs string, m *milter.Modifier) (*milter.Response, error) {
	debugLog("RcptTo: %s", rcptTo)
	// SMTP認証済みもしくはIPアドレスがMyNetworksに含まれている場合はARC署名を行わない
	if s.authn != "" || s.conf.IsMyNetwork(s.remoteAddr) {
		return milter.RespContinue, nil
	}
	rpctToDomain, err := mmauth.ParseAddressDomain(rcptTo)
	if err != nil {
		log.Printf("util.ParseAddressDomain: %v", err)
		return milter.RespContinue, nil
	}
	s.rcptToDomain = rpctToDomain
	// 署名の準備
	if domain, ok := (s.conf.Domains)[rpctToDomain]; ok {
		// 宛先が対象ドメインならARC署名を行う
		s.isARCSign = true
		s.mmauth.AddBodyHash(mmauth.BodyCanonicalizationAndAlgorithm{
			Body:      mmauth.Canonicalization(domain.BodyCanonicalization),
			Algorithm: domain.HashAlgo,
			Limit:     0,
		})
		return milter.RespContinue, nil
	}
	return milter.RespContinue, nil
}

func (s *Session) Header(name, value string, m *milter.Modifier) (*milter.Response, error) {
	s.mmauth.Write([]byte(name + ": " + value + "\r\n"))
	switch strings.ToLower(name) {
	case "from":
		s.from = value
		fromDomain, err := mmauth.ParseAddressDomain(value)
		if err != nil {
			log.Printf("util.ParseAddressDomain: %v", err)
			s.isDKIMSign = false
			return milter.RespContinue, nil
		}
		s.fromDomain = fromDomain

		if domain, ok := (s.conf.Domains)[s.fromDomain]; ok {
			// 送信元が対象ドメインなら正規化とハッシュアルゴリズムを設定
			s.mmauth.AddBodyHash(mmauth.BodyCanonicalizationAndAlgorithm{
				Body:      mmauth.Canonicalization(domain.BodyCanonicalization),
				Algorithm: domain.HashAlgo,
				Limit:     0,
			})
			// DKIM署名を行う
			s.isDKIMSign = true
		}
		return milter.RespContinue, nil
	}

	return milter.RespContinue, nil
}

func (s *Session) Headers(m *milter.Modifier) (*milter.Response, error) {
	debugLog("Headers")
	if _, err := s.mmauth.Write([]byte("\r\n")); err != nil {
		log.Printf("s.mmauth.Write: %v", err)
	}
	return milter.RespContinue, nil
}

func (s *Session) BodyChunk(chunk []byte, m *milter.Modifier) (*milter.Response, error) {
	if _, err := s.mmauth.Write(chunk); err != nil {
		log.Printf("s.mmauth.Write: %v", err)
	}
	return milter.RespContinue, nil
}

func DKIMSign(s *Session, m *milter.Modifier) {
	if !s.isDKIMSign {
		return
	}

	if h := mmauth.ExtractHeadersDKIM(s.mmauth.Headers, []string{"DKIM-Signature"}); len(h) > 0 {
		// すでにDKIM署名がある場合はDKIM署名しない
		log.Print("DKIM-Signature found Skip")
		return
	}

	// 対応するドメインのキーがある場合はDKIM署名を行う
	if domain, ok := (s.conf.Domains)[s.fromDomain]; ok && domain.DKIM {
		bodyHash := s.mmauth.GetBodyHash(mmauth.BodyCanonicalizationAndAlgorithm{
			Body:      mmauth.Canonicalization(domain.BodyCanonicalization),
			Algorithm: domain.HashAlgo,
			Limit:     0,
		})

		var algo dkim.SignatureAlgorithm
		switch domain.PrivateKeySigner.Public().(type) {
		case *rsa.PublicKey:
			algo = dkim.SignatureAlgorithmRSA_SHA256
		case ed25519.PublicKey:
			algo = dkim.SignatureAlgorithmED25519_SHA256
		default:
			log.Printf("unknown key type: %T", domain.PrivateKeySigner)
			return
		}

		// DKIM署名
		dkim := dkim.Signature{
			Algorithm:        algo,
			Signature:        "",
			BodyHash:         bodyHash,
			Canonicalization: domain.HeaderCanonicalization + "/" + domain.BodyCanonicalization,
			Domain:           domain.Domain,
			Selector:         domain.Selector,
			Version:          1,
		}

		if err := dkim.Sign(mmauth.ExtractHeadersDKIM(s.mmauth.Headers, s.conf.DKIMSignHeaders),
			domain.PrivateKeySigner); err != nil {
			log.Printf("dkim.Sign: %v", err)
			return
		}

		if err := m.InsertHeader(1, "DKIM-Signature", dkim.String()); err != nil {
			log.Printf("DKIM Signature Insert Error: %v", err)
			return
		}
		s.mmauth.Headers = append(s.mmauth.Headers, "DKIM-Signature: "+dkim.String())
	}
}

func ARCSign(s *Session, m *milter.Modifier) {
	if !s.isARCSign {
		return
	}

	if domain, ok := (s.conf.Domains)[s.rcptToDomain]; ok && domain.ARC {
		ah := s.mmauth.AuthenticationHeaders.ARCSignatures

		// ARC-Chain-Validation-Resultがfailの場合はARC署名を行わない
		if ah.GetARCChainValidation() == arc.ChainValidationResultFail {
			log.Printf("ARC-Chain-Validation-Result is fail skip ARC signing")
			return
		}

		var algo arc.SignatureAlgorithm
		switch domain.PrivateKeySigner.Public().(type) {
		case *rsa.PublicKey:
			algo = arc.SignatureAlgorithmRSA_SHA256
		case ed25519.PublicKey:
			algo = arc.SignatureAlgorithmED25519_SHA256
		default:
			log.Printf("unknown key type: %T", domain.PrivateKeySigner)
			return
		}

		instanceNumber := ah.GetMaxInstance() + 1
		signature := arc.ARCMessageSignature{
			InstanceNumber:   instanceNumber,
			Algorithm:        algo,
			Domain:           s.rcptToDomain,
			Selector:         domain.ARCSelector,
			Canonicalization: domain.HeaderCanonicalization + "/" + domain.BodyCanonicalization,
			BodyHash: s.mmauth.GetBodyHash(
				mmauth.BodyCanonicalizationAndAlgorithm{
					Body:      mmauth.CanonicalizationRelaxed,
					Algorithm: crypto.SHA256,
					Limit:     0,
				},
			),
		}

		if err := signature.Sign(mmauth.ExtractHeadersARC(s.mmauth.Headers, s.conf.ARCSignHeaders),
			domain.PrivateKeySigner); err != nil {
			log.Printf("signature.Sign: %v", err)
			return
		}

		// SPF Check
		var results []string
		if s.remoteAddr != nil {
			res, _ := spf.Check(context.Background(), s.remoteAddr, s.mailFrom, s.helo)
			results = append(results,
				fmt.Sprintf("spf=%s smtp.mailfrom=%s smtp.helo=%s", res.String(), s.mailFrom, s.helo))
		}

		// DKIM
		ad := s.mmauth.AuthenticationHeaders.DKIMSignatures
		for _, d := range *ad {
			results = append(results, d.ResultString())
		}

		// ARC
		aa := s.mmauth.AuthenticationHeaders.ARCSignatures
		if aa != nil {
			results = append(results, aa.GetVerifyResultString())
		}

		result := arc.ARCAuthenticationResults{
			InstanceNumber: instanceNumber,
			AuthServId:     s.rcptToDomain,
			Results:        results,
		}

		// ARC-Seal署名
		seal := arc.ARCSeal{
			InstanceNumber: instanceNumber,
			Algorithm:      algo,
			Domain:         s.rcptToDomain,
			Selector:       domain.ARCSelector,
			ChainValidation: arc.ChainValidationResult(
				s.mmauth.AuthenticationHeaders.ARCSignatures.GetVerifyResult(),
			),
		}
		headers := s.mmauth.AuthenticationHeaders.ARCSignatures.GetARCHeaders()
		headers = append(headers, "ARC-Authentication-Results: "+result.String())
		headers = append(headers, "ARC-Message-Signature: "+signature.String())

		if err := seal.Sign(headers, domain.PrivateKeySigner); err != nil {
			log.Printf("seal.Sign: %v", err)
			return
		}

		if err := m.InsertHeader(1, "ARC-Authentication-Results", result.String()); err != nil {
			log.Printf("ARC-Authentication-Results Insert Error: %v", err)
			return
		}
		if err := m.InsertHeader(1, "ARC-Message-Signature", signature.String()); err != nil {
			log.Printf("ARC-Message-Signature Insert Error: %v", err)
			return
		}
		if err := m.InsertHeader(1, "ARC-Seal", seal.String()); err != nil {
			log.Printf("ARC-Seal Insert Error: %v", err)
			return
		}
	}
}

func (s *Session) EndOfMessage(m *milter.Modifier) (*milter.Response, error) {
	debugLog("EndOfMessage")
	if s.mmauth == nil {
		return milter.RespContinue, nil
	}
	if err := s.mmauth.Close(); err != nil {
		log.Printf("s.mmauth.Close: %v", err)
		return milter.RespContinue, nil
	}

	// Verify
	s.mmauth.Verify()

	// DKIM署名
	DKIMSign(s, m)

	// ARC署名
	ARCSign(s, m)

	debugLog("session: %s", pp.Sprint(s))

	return milter.RespContinue, nil
}
