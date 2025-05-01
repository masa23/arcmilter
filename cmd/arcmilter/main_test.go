package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/d--j/go-milter"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
)

// Testの初期化
func TestMain(m *testing.M) {
	// tmpディレクトリの作成
	if err := os.MkdirAll("./t/tmp", 0755); err != nil {
		log.Fatalf("failed to create tmp dir: %v", err)
	}

	// テスト実行
	code := m.Run()

	// tmpディレクトリの削除
	if err := os.RemoveAll("./t/tmp"); err != nil {
		log.Fatalf("failed to remove tmp dir: %v", err)
	}

	// テストコードに応じた終了コードを返す
	os.Exit(code)
}

var testExecCmd *exec.Cmd

var testCreateFile = []struct {
	path       string
	permission os.FileMode
	stopExist  bool
}{
	{
		path:       "./t/tmp/arcmilter.log",
		permission: 0600,
		stopExist:  true,
	},
	{
		path:       "./t/tmp/arcmilter.pid",
		permission: 0644,
		stopExist:  false,
	},
	{
		path:       "./t/tmp/arcmilter.sock",
		permission: 0600,
		stopExist:  true,
	},
	{
		path:       "./t/tmp/arcmilterctl.sock",
		permission: 0600,
		stopExist:  true,
	},
}

func TestExec(t *testing.T) {
	t.Run("build", testBuild)
	t.Run("version", testVersion)
	t.Run("exec", testExec)
	t.Run("milter", testMilter)
	t.Run("stop", testStop)
}

func testBuild(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "./t/tmp/arcmilter", ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build arcmilter: %v", err)
	}
}

func testVersion(t *testing.T) {
	cmd := exec.Command("./t/tmp/arcmilter", "-version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get version: %v", err)
	}
	t.Logf("version: %s", out)
}

func testExec(t *testing.T) {
	testExecCmd = exec.Command("./t/tmp/arcmilter", "-conf", "t/test.yaml")
	if err := testExecCmd.Start(); err != nil {
		t.Fatalf("failed to start arcmilter: %v", err)
	}
	// 起動待ち
	time.Sleep(500 * time.Millisecond)

	// プロセスが存在するか確認
	if testExecCmd.Process == nil {
		t.Fatalf("arcmilter process not running")
	}
	if err := testExecCmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("arcmilter process not running: %v", err)
	}

	// ファイルの作成とパーミッションの確認
	for _, f := range testCreateFile {
		info, err := os.Stat(f.path)
		if err != nil {
			t.Fatalf("failed to stat %s: %v", f.path, err)
		}
		if info.Mode().Perm() != f.permission {
			t.Fatalf("unexpected permission %s: %v", f.path, info.Mode().Perm())
		}
	}
}

func testMilter(t *testing.T) {
	client := milter.NewClient("unix", "./t/tmp/arcmilter.sock")
	globalMacros := milter.NewMacroBag()
	globalMacros.Set(milter.MacroMTAFQDN, "example.jp")
	globalMacros.Set(milter.MacroMTAPid, strconv.Itoa(os.Getpid()))

	testCase := []struct {
		name          string
		connAddr      string
		connHostname  string
		connFamily    milter.ProtoFamily
		connPort      uint16
		heloHostname  string
		authUser      string
		mailSender    string
		mailEsmtpArgs string
		rcptRcpt      string
		rcptEsmtpArgs string
		headers       []struct {
			field string
			value string
		}
		body               string
		expectDKIM         *dkim.Signature
		expectARCSignature *arc.ARCMessageSignature
		expectARCResults   *arc.ARCAuthenticationResults
		expectARCSeal      *arc.ARCSeal
	}{
		{
			// DKIMの署名だけを行うテスト
			// Fromが署名対象である
			// connAddrが127.0.0.1のためARC署名は行われない
			name:         "DKIM sign only with MyNetworks",
			connAddr:     "127.0.0.1",
			connHostname: "localhost",
			connFamily:   milter.FamilyInet,
			connPort:     10025,
			heloHostname: "localhost",
			mailSender:   "<test@example.jp>",
			rcptRcpt:     "<outside@example.com>",
			headers: []struct {
				field string
				value string
			}{
				{
					field: "From",
					value: "test@example.jp",
				},
				{
					field: "To",
					value: "outside@example.com",
				},
			},
			body: "test\r\n",
			expectDKIM: &dkim.Signature{
				Algorithm:        "rsa-sha256",
				BodyHash:         "g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=",
				Domain:           "example.jp",
				Selector:         "default",
				Canonicalization: "relaxed/relaxed",
				Headers:          "from:to",
				Version:          1,
			},
		},
		{
			// DKIMの署名だけを行うテスト
			// Fromが署名対象である
			// SMTP Auth認証がされているためARC署名は行われない
			name:         "DKIM sign only with SMTP Auth",
			connAddr:     "192.0.2.1",
			connHostname: "mail.example.net",
			connFamily:   milter.FamilyInet,
			connPort:     10025,
			heloHostname: "mail.example.net",
			authUser:     "login-user",
			mailSender:   "<test@example.jp>",
			rcptRcpt:     "<outside@example.com>",
			headers: []struct {
				field string
				value string
			}{
				{
					field: "From",
					value: "test@example.jp",
				},
				{
					field: "To",
					value: "outside@example.com",
				},
			},
			body: "test\r\n",
			expectDKIM: &dkim.Signature{
				Algorithm:        "rsa-sha256",
				BodyHash:         "g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=",
				Domain:           "example.jp",
				Selector:         "default",
				Canonicalization: "relaxed/relaxed",
				Headers:          "from:to",
				Version:          1,
			},
		},
		{
			// ARC署名だけを行うテスト
			// RcptToがARC署名対象である
			// MyNetworksに含まれないためARC署名対象である
			name:         "ARC sign only",
			connAddr:     "192.0.2.1",
			connHostname: "example.com",
			connFamily:   milter.FamilyInet,
			connPort:     10025,
			heloHostname: "example.com",
			mailSender:   "<test@example.com>",
			rcptRcpt:     "<recive@example.jp>",
			headers: []struct {
				field string
				value string
			}{
				{
					field: "From",
					value: "test@example.com",
				},
				{
					field: "To",
					value: "recive@example.jp",
				},
			},
			body: "test\r\n",
			expectARCSignature: &arc.ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        "rsa-sha256",
				BodyHash:         "g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.jp",
				Selector:         "default",
				Headers:          "from:to",
			},
			expectARCResults: &arc.ARCAuthenticationResults{
				InstanceNumber: 1,
				AuthServId:     "example.jp",
				Results: []string{
					"spf=fail smtp.mailfrom=<test@example.com> smtp.helo=example.com",
					"arc=none",
				},
			},
			expectARCSeal: &arc.ARCSeal{
				InstanceNumber:  1,
				Algorithm:       "rsa-sha256",
				ChainValidation: arc.ChainValidationResultNone,
				Domain:          "example.jp",
				Selector:        "default",
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			macros := globalMacros.Copy()
			session, err := client.Session(macros)
			if err != nil {
				log.Fatalf("failed to create milter session: %v", err)
			}
			handleMilterResponse := func(act *milter.Action, err error) {
				if err != nil {
					t.Fatalf("failed to handle milter response: %v", err)
				}
				if act.StopProcessing() {
					t.Fatalf("unexpected stop processing: %s", act.SMTPReply)
				}
				if act.Type == milter.ActionDiscard {
					t.Fatalf("unexpected discard: %s", act.SMTPReply)
				}
			}

			handleMilterResponse(session.Conn(tc.connHostname, tc.connFamily, tc.connPort, tc.connAddr))
			handleMilterResponse(session.Helo(tc.heloHostname))
			if tc.authUser != "" {
				macros.Set(milter.MacroAuthAuthen, tc.authUser)
			}
			handleMilterResponse(session.Mail(tc.mailSender, tc.mailEsmtpArgs))
			handleMilterResponse(session.Rcpt(tc.rcptRcpt, tc.rcptEsmtpArgs))
			handleMilterResponse(session.DataStart())
			for _, header := range tc.headers {
				handleMilterResponse(session.HeaderField(header.field, header.value, nil))
			}
			handleMilterResponse(session.HeaderEnd())
			mActs, act, err := session.BodyReadFrom(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			if act.StopProcessing() {
				t.Fatalf("unexpected stop processing: %s", act.SMTPReply)
			}

			for _, header := range []string{"DKIM-Signature", "ARC-Message-Signature", "ARC-Authentication-Results", "ARC-Seal"} {
				found := false
				for _, mAct := range mActs {
					if strings.EqualFold(mAct.HeaderName, header) {
						found = true
						break
					}
				}
				switch header {
				case "DKIM-Signature":
					if !found && tc.expectDKIM != nil {
						t.Fatalf("missing header: %s", header)
					}
				case "ARC-Message-Signature":
					if !found && tc.expectARCSignature != nil {
						t.Fatalf("missing header: %s", header)
					}
				case "ARC-Authentication-Results":
					if !found && tc.expectARCResults != nil {
						t.Fatalf("missing header: %s", header)
					}
				case "ARC-Seal":
					if !found && tc.expectARCSeal != nil {
						t.Fatalf("missing header: %s", header)
					}
				}
			}

			for _, mAct := range mActs {
				if mAct.Type == milter.ActionInsertHeader {
					if strings.EqualFold(mAct.HeaderName, "DKIM-Signature") {
						if tc.expectDKIM == nil {
							t.Fatalf("unexpected DKIM-Signature: %s", mAct.HeaderValue)
						}
						d, err := dkim.ParseSignature(fmt.Sprintf("%s: %s", mAct.HeaderName, mAct.HeaderValue))
						if err != nil {
							t.Fatalf("failed to parse DKIM-Signature: %v", err)
						}
						e := tc.expectDKIM
						if d.Algorithm != e.Algorithm {
							t.Fatalf("algorithm mismatch: %s != %s", d.Algorithm, e.Algorithm)
						}
						if d.BodyHash != e.BodyHash {
							t.Fatalf("body hash mismatch: %s != %s", d.BodyHash, e.BodyHash)
						}
						if !strings.EqualFold(d.Domain, e.Domain) {
							t.Fatalf("domain mismatch: %s != %s", d.Domain, e.Domain)
						}
						if !strings.EqualFold(d.Selector, e.Selector) {
							t.Fatalf("selector mismatch: %s != %s", d.Selector, e.Selector)
						}
						if d.Canonicalization != e.Canonicalization {
							t.Fatalf("canonicalization mismatch: %s != %s", d.Canonicalization, e.Canonicalization)
						}
						if !strings.EqualFold(d.Headers, e.Headers) {
							t.Fatalf("headers mismatch: %s != %s", d.Headers, e.Headers)
						}
						if d.Version != e.Version {
							t.Fatalf("version mismatch: %d != %d", d.Version, e.Version)
						}
					}
					if strings.EqualFold(mAct.HeaderName, "ARC-Message-Signature") {
						if tc.expectARCSignature == nil {
							t.Fatalf("unexpected ARC-Message-Signature: %s", mAct.HeaderValue)
						}
						d, err := arc.ParseARCMessageSignature(fmt.Sprintf("%s: %s", mAct.HeaderName, mAct.HeaderValue))
						if err != nil {
							t.Fatalf("failed to parse ARC-Message-Signature: %v", err)
						}
						e := tc.expectARCSignature
						if d.InstanceNumber != e.InstanceNumber {
							t.Fatalf("instance number mismatch: %d != %d", d.InstanceNumber, e.InstanceNumber)
						}
						if d.Algorithm != e.Algorithm {
							t.Fatalf("algorithm mismatch: %s != %s", d.Algorithm, e.Algorithm)
						}
						if d.BodyHash != e.BodyHash {
							t.Fatalf("body hash mismatch: %s != %s", d.BodyHash, e.BodyHash)
						}
						if d.Canonicalization != e.Canonicalization {
							t.Fatalf("canonicalization mismatch: %s != %s", d.Canonicalization, e.Canonicalization)
						}
						if !strings.EqualFold(d.Domain, e.Domain) {
							t.Fatalf("domain mismatch: %s != %s", d.Domain, e.Domain)
						}
						if !strings.EqualFold(d.Selector, e.Selector) {
							t.Fatalf("selector mismatch: %s != %s", d.Selector, e.Selector)
						}
						if !strings.EqualFold(d.Headers, e.Headers) {
							t.Fatalf("headers mismatch: %s != %s", d.Headers, e.Headers)
						}
					}
					if strings.EqualFold(mAct.HeaderName, "ARC-Authentication-Results") {
						if tc.expectARCResults == nil {
							t.Fatalf("unexpected ARC-Authentication-Results: %s", mAct.HeaderValue)
						}
						d, err := arc.ParseARCAuthenticationResults(fmt.Sprintf("%s: %s", mAct.HeaderName, mAct.HeaderValue))
						if err != nil {
							t.Fatalf("failed to parse ARC-Authentication-Results: %v", err)
						}
						e := tc.expectARCResults
						if d.InstanceNumber != e.InstanceNumber {
							t.Fatalf("instance number mismatch: %d != %d", d.InstanceNumber, e.InstanceNumber)
						}
						if !strings.EqualFold(d.AuthServId, e.AuthServId) {
							t.Fatalf("domain mismatch: %s != %s", d.AuthServId, e.AuthServId)
						}
						for i, r := range d.Results {
							if !strings.EqualFold(r, e.Results[i]) {
								t.Fatalf("result mismatch: %s != %s", r, e.Results[i])
							}
						}
					}
					if strings.EqualFold(mAct.HeaderName, "ARC-Seal") {
						if tc.expectARCSeal == nil {
							t.Fatalf("unexpected ARC-Seal: %s", mAct.HeaderValue)
						}
						d, err := arc.ParseARCSeal(fmt.Sprintf("%s: %s", mAct.HeaderName, mAct.HeaderValue))
						if err != nil {
							t.Fatalf("failed to parse ARC-Seal: %v", err)
						}
						e := tc.expectARCSeal
						if d.InstanceNumber != e.InstanceNumber {
							t.Fatalf("instance number mismatch: %d != %d", d.InstanceNumber, e.InstanceNumber)
						}
						if d.Algorithm != e.Algorithm {
							t.Fatalf("algorithm mismatch: %s != %s", d.Algorithm, e.Algorithm)
						}
						if d.ChainValidation != e.ChainValidation {
							t.Fatalf("chain validation mismatch: %s != %s", d.ChainValidation, e.ChainValidation)
						}
						if !strings.EqualFold(d.Domain, e.Domain) {
							t.Fatalf("domain mismatch: %s != %s", d.Domain, e.Domain)
						}
						if !strings.EqualFold(d.Selector, e.Selector) {
							t.Fatalf("selector mismatch: %s != %s", d.Selector, e.Selector)
						}
					}
				}
			}
			session.Close()
		})
	}
}

func testStop(t *testing.T) {
	defer func() {
		// テスト終了時に強制終了
		testExecCmd.Process.Signal(syscall.SIGKILL)
	}()
	if testExecCmd.Process != nil {
		if err := testExecCmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("failed to kill arcmilter: %v", err)
		}
		if err := testExecCmd.Wait(); err != nil {
			t.Fatalf("failed to wait arcmilter: %v", err)
		}
	}

	// 終了後のファイルの確認
	for _, f := range testCreateFile {
		_, err := os.Stat(f.path)
		if f.stopExist {
			if err != nil {
				t.Fatalf("file not found: %s", f.path)
			}
		} else {
			if err == nil {
				t.Fatalf("file exists: %s", f.path)
			}
		}
	}
}

func Test_checkPidFile(t *testing.T) {
	pidFile := "test.pid"
	defer func() {
		if err := os.Remove(pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to remove pid file: %v", err)
		}
	}()
	// remove pid file
	if err := os.Remove(pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed to remove pid file: %v", err)
	}
	testCases := []struct {
		name      string
		fileExist bool
		pidExist  bool
		expectErr bool
	}{
		{
			name:      "no pid file",
			fileExist: false,
			pidExist:  false,
			expectErr: false,
		},
		{
			name:      "pid file exists no process",
			fileExist: true,
			pidExist:  false,
			expectErr: false,
		},
		{
			name:      "pid file exists process exists",
			fileExist: true,
			pidExist:  true,
			expectErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fileExist {
				var pidStr string

				// PIDがある場合のテストは、test実行のpidを書き込む
				if tt.pidExist {
					pid := os.Getpid()
					pidStr = strconv.Itoa(pid)
				} else {
					for {
						randPid := rand.Intn(9000) + 1000
						if err := syscall.Kill(randPid, 0); err == nil {
							continue
						}
						pidStr = strconv.Itoa(randPid)
						break
					}
				}

				if err := os.WriteFile(pidFile, []byte(pidStr), 0644); err != nil {
					t.Fatalf("failed to write pid file: %v", err)
				}
			}
			err := checkPidFile(pidFile)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
