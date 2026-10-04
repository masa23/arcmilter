package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/d--j/go-milter"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"gopkg.in/yaml.v3"
)

type execTest struct {
	dir      string
	cmd      *exec.Cmd
	done     chan struct{}
	waitErr  error // doneを閉じた後にだけ参照する
	stopped  bool
	coverDir string
	childPID int
}

var testCreateFile = []struct {
	name       string
	permission os.FileMode
	stopExist  bool
}{
	{
		name:       "arcmilter.log",
		permission: 0600,
		stopExist:  true,
	},
	{
		name:       "arcmilter.pid",
		permission: 0644,
		stopExist:  false,
	},
	{
		name:       "arcmilter.sock",
		permission: 0600,
		stopExist:  true,
	},
	{
		name:       "arcmilterctl.sock",
		permission: 0600,
		stopExist:  true,
	},
}

func TestExec(t *testing.T) {
	// UNIXソケットのパス長制限を超えないよう、TMPDIRに依存しない短いパスを使う。
	dir, err := os.MkdirTemp("/tmp", "arcmilter-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("failed to remove test directory: %v", err)
		}
	})
	f := &execTest{dir: dir}
	if dir := os.Getenv("ARCMILTER_TEST_COVERDIR"); dir != "" {
		var err error
		f.coverDir, err = filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(f.coverDir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.stop(t)
		if t.Failed() {
			for _, name := range []string{"arcmilter.log", "output.log"} {
				if buf, err := os.ReadFile(filepath.Join(f.dir, name)); err == nil {
					t.Logf("%s:\n%s", name, buf)
				}
			}
		}
	})
	if !t.Run("build", f.build) || !t.Run("version", f.version) || !t.Run("exec", f.start) {
		return
	}
	t.Run("milter", func(t *testing.T) { testMilter(t, filepath.Join(f.dir, "arcmilter.sock")) })
	// 最初の子を正常終了させ、Milterの全ケースのカウンターを回収してから強制終了を検証する。
	if !t.Run("reload", f.reload) || !t.Run("restart", f.restart) || !t.Run("reload-invalid", f.reloadInvalid) || !t.Run("reload-timeout", f.reloadTimeout) {
		return
	}
	t.Run("stop", func(t *testing.T) {
		f.stop(t)
		for _, file := range testCreateFile {
			path := filepath.Join(f.dir, file.name)
			_, err := os.Stat(path)
			if file.stopExist && err != nil {
				t.Errorf("file not found: %s: %v", path, err)
			} else if !file.stopExist && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("expected file removal: %s: %v", path, err)
			}
		}
	})
}

func (f *execTest) build(t *testing.T) {
	args := []string{"build"}
	if testRaceEnabled {
		args = append(args, "-race")
	}
	if f.coverDir != "" {
		args = append(args, "-cover", "-covermode=atomic", "-coverpkg=github.com/masa23/arcmilter/...")
	}
	args = append(args, "-o", filepath.Join(f.dir, "arcmilter"), ".")
	cmd := exec.Command("go", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build arcmilter: %v\n%s", err, out)
	}
}

func (f *execTest) version(t *testing.T) {
	cmd := exec.Command(filepath.Join(f.dir, "arcmilter"), "-version")
	if f.coverDir != "" {
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+f.coverDir)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get version: %v", err)
	}
	if got, want := string(out), "arcmilter version "+version+"\n"; got != want {
		t.Fatalf("version: got %q, want %q", got, want)
	}
}

func (f *execTest) start(t *testing.T) {
	buf, err := os.ReadFile("t/test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var conf map[string]interface{}
	if err := yaml.Unmarshal(buf, &conf); err != nil {
		t.Fatal(err)
	}
	for section, file := range map[string]string{
		"MilterListen": "arcmilter.sock", "ControlSocketFile": "arcmilterctl.sock",
		"PIDFile": "arcmilter.pid", "LogFile": "arcmilter.log",
	} {
		field := "Path"
		if section == "MilterListen" {
			field = "Address"
		}
		conf[section].(map[string]interface{})[field] = filepath.Join(f.dir, file)
	}
	keyPath, err := filepath.Abs("t/key")
	if err != nil {
		t.Fatal(err)
	}
	conf["Domains"].(map[string]interface{})["example.jp"].(map[string]interface{})["PrivateKeyFile"] = keyPath
	buf, err = yaml.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(f.dir, "test.yaml")
	if err := os.WriteFile(confPath, buf, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(filepath.Join(f.dir, "output.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	f.cmd = exec.Command(filepath.Join(f.dir, "arcmilter"), "-conf", confPath)
	f.cmd.Stdout, f.cmd.Stderr = output, output
	if f.coverDir != "" {
		f.cmd.Env = append(os.Environ(), "GOCOVERDIR="+f.coverDir)
	}
	// 異常終了時も、このテストで起動した子プロセスだけを終了できるようにする。
	f.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := f.cmd.Start(); err != nil {
		t.Fatalf("failed to start arcmilter: %v", err)
	}
	f.done = make(chan struct{})
	go func() {
		f.waitErr = f.cmd.Wait()
		close(f.done)
	}()

	// ソケットの作成だけでなく、Milterのネゴシエーション完了まで待つ。
	client := milter.NewClient("unix", filepath.Join(f.dir, "arcmilter.sock"),
		milter.WithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}),
		milter.WithReadTimeout(100*time.Millisecond), milter.WithWriteTimeout(100*time.Millisecond))
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-f.done:
			t.Fatalf("arcmilter exited before readiness: %v", f.waitErr)
		default:
		}
		session, err := client.Session(nil)
		if err == nil {
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for milter: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.childPID = f.waitLogPID(t, "child process ready", 0)

	// ファイルの作成とパーミッションの確認
	for _, file := range testCreateFile {
		info, err := os.Stat(filepath.Join(f.dir, file.name))
		if err != nil {
			t.Fatalf("failed to stat %s: %v", file.name, err)
		}
		if info.Mode().Perm() != file.permission {
			t.Fatalf("unexpected permission %s: %v", file.name, info.Mode().Perm())
		}
	}
}

func testMilter(t *testing.T, socketPath string) {
	client := milter.NewClient("unix", socketPath)
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
		extraRcpts    []string
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
			extraRcpts:   []string{"<outside@example.com>"},
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
				t.Fatalf("failed to create milter session: %v", err)
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Errorf("failed to close milter session: %v", err)
				}
			})
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
			for _, rcpt := range tc.extraRcpts {
				handleMilterResponse(session.Rcpt(rcpt, tc.rcptEsmtpArgs))
			}
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
						if len(d.Results) != len(e.Results) {
							t.Fatalf("result count mismatch: %d != %d", len(d.Results), len(e.Results))
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
		})
	}
}

func (f *execTest) stop(t *testing.T) {
	t.Helper()
	if f.cmd == nil || f.cmd.Process == nil || f.stopped {
		return
	}
	f.stopped = true
	// 親プロセスが先に終了していても、残った子プロセスを回収する。
	defer syscall.Kill(-f.cmd.Process.Pid, syscall.SIGKILL)
	if err := f.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("failed to stop arcmilter process group: %v", err)
	}
	if f.coverDir != "" && f.childPID != 0 {
		f.waitCoverage(t, f.childPID)
	}
	select {
	case <-f.done:
		if f.waitErr != nil {
			t.Errorf("arcmilter exited with error: %v", f.waitErr)
		}
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(-f.cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-f.done:
		case <-time.After(5 * time.Second):
			t.Errorf("timed out reaping arcmilter")
		}
		t.Errorf("timed out stopping arcmilter")
	}
	if testRaceEnabled {
		for _, name := range []string{"arcmilter.log", "output.log"} {
			if buf, err := os.ReadFile(filepath.Join(f.dir, name)); err == nil && strings.Contains(string(buf), "WARNING: DATA RACE") {
				t.Errorf("race detected in arcmilter:\n%s", buf)
			}
		}
	}
}

func (f *execTest) waitCoverage(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		matches, err := filepath.Glob(filepath.Join(f.coverDir, fmt.Sprintf("covcounters.*.%d.*", pid)))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("no coverage counters from child %d", pid)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *execTest) logOffset(t *testing.T) int {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join(f.dir, "arcmilter.log"))
	if err != nil {
		t.Fatal(err)
	}
	return len(buf)
}

func (f *execTest) waitLogPID(t *testing.T, event string, offset int) int {
	t.Helper()
	pattern := regexp.MustCompile(regexp.QuoteMeta(event) + ` pid=(\d+)`)
	var pid int
	f.waitLog(t, offset, func(log string) bool {
		match := pattern.FindStringSubmatch(log)
		if match == nil {
			return false
		}
		pid, _ = strconv.Atoi(match[1])
		return true
	})
	return pid
}

func (f *execTest) waitLog(t *testing.T, offset int, found func(string) bool) {
	t.Helper()
	deadline := time.Now().Add(childReadyTimeout + 10*time.Second)
	for {
		buf, err := os.ReadFile(filepath.Join(f.dir, "arcmilter.log"))
		if err == nil && len(buf) >= offset && found(string(buf[offset:])) {
			return
		}
		select {
		case <-f.done:
			t.Fatalf("arcmilter exited while waiting for event: %v\n%s", f.waitErr, buf)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for process event:\n%s", buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *execTest) restart(t *testing.T) {
	offset, oldPID := f.logOffset(t), f.childPID
	if err := syscall.Kill(oldPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	f.childPID = f.waitLogPID(t, "child process ready", offset)
	if f.childPID == oldPID {
		t.Fatal("child was not replaced after abnormal exit")
	}
	f.checkSelector(t, "reloaded")
}

func (f *execTest) reload(t *testing.T) {
	path := filepath.Join(f.dir, "test.yaml")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]interface{}
	if err := yaml.Unmarshal(buf, &c); err != nil {
		t.Fatal(err)
	}
	c["Domains"].(map[string]interface{})["example.jp"].(map[string]interface{})["Selector"] = "reloaded"
	buf, err = yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	offset, oldPID := f.logOffset(t), f.childPID
	if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	f.childPID = f.waitLogPID(t, "child process ready", offset)
	if f.childPID == oldPID {
		t.Fatal("reload did not start a new child")
	}
	f.waitLog(t, offset, func(log string) bool { return strings.Contains(log, fmt.Sprintf("child process exit pid=%d", oldPID)) })
	if f.coverDir != "" {
		f.waitCoverage(t, oldPID)
	}
	f.checkSelector(t, "reloaded")
}

func (f *execTest) reloadInvalid(t *testing.T) {
	path := filepath.Join(f.dir, "test.yaml")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, valid, 0600); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(path, []byte("MilterListen: ["), 0600); err != nil {
		t.Fatal(err)
	}
	offset := f.logOffset(t)
	if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	f.waitLog(t, offset, func(log string) bool { return strings.Contains(log, "failed to load config:") })
	// 新しい子も設定を読めないためタイムアウトする。旧プロセスは処理を継続する。
	f.waitLog(t, offset, func(log string) bool { return strings.Contains(log, "timed out waiting for child process readiness") })
	f.checkSelector(t, "reloaded")
}

func (f *execTest) reloadTimeout(t *testing.T) {
	binary := filepath.Join(f.dir, "arcmilter")
	realBinary := binary + ".real"
	if err := os.Rename(binary, realBinary); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			if err := os.Rename(realBinary, binary); err != nil {
				t.Error(err)
				return
			}
			restored = true
		}
	}
	t.Cleanup(restore)
	// 再読み込み時だけ、準備完了を通知しない子プロセスを起動する。
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	offset, oldPID := f.logOffset(t), f.childPID
	if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	stalledPID := f.waitLogPID(t, "child process started", offset)
	f.waitLog(t, offset, func(log string) bool { return strings.Contains(log, "timed out waiting for child process readiness") })
	f.waitLog(t, offset, func(log string) bool {
		return strings.Contains(log, fmt.Sprintf("child process exit pid=%d", stalledPID))
	})
	f.checkSelector(t, "reloaded")
	if err := syscall.Kill(oldPID, 0); err != nil {
		t.Fatalf("old child stopped after readiness timeout: %v", err)
	}
	restore()
	// タイムアウト後でも、次の正常な再読み込みを完了できる。
	f.reload(t)
}

func (f *execTest) checkSelector(t *testing.T, selector string) {
	t.Helper()
	client := milter.NewClient("unix", filepath.Join(f.dir, "arcmilter.sock"))
	session, err := client.Session(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	}()
	check := func(action *milter.Action, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if action.StopProcessing() || action.Type == milter.ActionDiscard {
			t.Fatalf("unexpected action: %v", action)
		}
	}
	check(session.Conn("localhost", milter.FamilyInet, 25, "127.0.0.1"))
	check(session.Helo("localhost"))
	check(session.Mail("<a@example.jp>", ""))
	check(session.Rcpt("<a@outside.example>", ""))
	check(session.DataStart())
	check(session.HeaderField("From", "a@example.jp", nil))
	check(session.HeaderField("To", "a@outside.example", nil))
	check(session.HeaderEnd())
	mods, action, err := session.BodyReadFrom(strings.NewReader("reload body\r\n"))
	check(action, err)
	count := 0
	for _, mod := range mods {
		if strings.EqualFold(mod.HeaderName, "DKIM-Signature") {
			count++
			sig, err := dkim.ParseSignature(mod.HeaderName + ": " + mod.HeaderValue)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Selector != selector {
				t.Fatalf("got selector %q, want %q", sig.Selector, selector)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected one DKIM signature after process transition, got %d", count)
	}
}

func Test_checkPidFile(t *testing.T) {
	testCases := []struct {
		name      string
		fileExist bool
		pidExist  bool
		pidStr    string
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
		{
			name:      "pid file contains zero",
			fileExist: true,
			pidStr:    "0",
			expectErr: true,
		},
		{
			name:      "pid file contains negative pid",
			fileExist: true,
			pidStr:    "-1",
			expectErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "test.pid")
			if tt.fileExist {
				pidStr := tt.pidStr

				// PIDがある場合のテストは、test実行のpidを書き込む
				if pidStr == "" {
					if tt.pidExist {
						pid := os.Getpid()
						pidStr = strconv.Itoa(pid)
					} else {
						for {
							randPid := rand.Intn(9000) + 1000
							if err := syscall.Kill(randPid, 0); !errors.Is(err, syscall.ESRCH) {
								continue
							}
							pidStr = strconv.Itoa(randPid)
							break
						}
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
