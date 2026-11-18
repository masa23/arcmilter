package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
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
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"gopkg.in/yaml.v3"
)

type execTest struct {
	dir       string
	cmd       *exec.Cmd
	done      chan struct{}
	waitErr   error // doneを閉じた後にだけ参照する
	stopped   bool
	coverDir  string
	childPID  int
	configure func(map[string]interface{})
}

type milterPeerTestAddr string

func (a milterPeerTestAddr) Network() string { return "test" }
func (a milterPeerTestAddr) String() string  { return string(a) }

type milterPeerTestConn struct {
	remote net.Addr
	closed bool
}

func (c *milterPeerTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *milterPeerTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *milterPeerTestConn) Close() error                     { c.closed = true; return nil }
func (c *milterPeerTestConn) LocalAddr() net.Addr              { return milterPeerTestAddr("local") }
func (c *milterPeerTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *milterPeerTestConn) SetDeadline(time.Time) error      { return nil }
func (c *milterPeerTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *milterPeerTestConn) SetWriteDeadline(time.Time) error { return nil }

type milterPeerTestListener struct {
	connections []net.Conn
	err         error
}

func (l *milterPeerTestListener) Accept() (net.Conn, error) {
	if len(l.connections) == 0 {
		return nil, l.err
	}
	conn := l.connections[0]
	l.connections = l.connections[1:]
	return conn, nil
}

func (l *milterPeerTestListener) Close() error   { return nil }
func (l *milterPeerTestListener) Addr() net.Addr { return milterPeerTestAddr("listener") }

func TestListenPrivateUnix(t *testing.T) {
	// A permissive caller umask makes the test prove that listenPrivateUnix
	// applies its own restriction at bind time and then restores the caller's
	// setting. Top-level tests in this package do not run in parallel.
	path := filepath.Join(t.TempDir(), "milter.sock")
	previous := syscall.Umask(0)
	defer syscall.Umask(previous)
	listener, err := listenPrivateUnix(path)
	if err != nil {
		t.Fatalf("listenPrivateUnix() error = %v", err)
	}
	defer listener.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("socket permissions = %#o, want no group or other permissions", got)
	}

	got := syscall.Umask(0)
	syscall.Umask(got)
	if got != 0 {
		t.Fatalf("process umask after listenPrivateUnix() = %#o, want 0", got)
	}
}

func TestPrivateRuntimeDirectoryAndSocketPaths(t *testing.T) {
	dir := t.TempDir()
	unsafe := filepath.Join(dir, "writable")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateRuntimeDirectory(filepath.Join(unsafe, "daemon.sock")); err == nil {
		t.Fatal("group/world-writable runtime directory was accepted")
	}
	link := filepath.Join(dir, "indirect")
	if err := os.Symlink(unsafe, link); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateRuntimeDirectory(filepath.Join(link, "daemon.sock")); err == nil {
		t.Fatal("symlink into an unsafe runtime directory was accepted")
	}

	path := filepath.Join(dir, "daemon.sock")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleUnixSocket(path, os.Geteuid()); err == nil {
		t.Fatal("regular file was removed as a stale socket")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "preserve" {
		t.Fatalf("regular file changed: %q, %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := listenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := configureUnixSocket(path, 0600, -1, -1); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %v, %v", info, err)
	}
	if err := removeStaleUnixSocket(path, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket still exists: %v", err)
	}
}

func TestDropChildPrivilegesClearsSupplementaryGroups(t *testing.T) {
	const childMarker = "ARCMILTER_TEST_DROP_GROUPS"
	if os.Getenv(childMarker) == "1" {
		before, err := os.Getgroups()
		if err != nil || len(before) == 0 {
			t.Fatalf("test child did not inherit supplementary groups: %v, %v", before, err)
		}
		if err := dropChildPrivileges(os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
		after, err := os.Getgroups()
		if err != nil || len(after) != 0 {
			t.Fatalf("supplementary groups survived privilege drop: %v, %v", after, err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("test requires root to set supplementary groups in a subprocess")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropChildPrivilegesClearsSupplementaryGroups$")
	cmd.Env = append(os.Environ(), childMarker+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{1, 2}}}
	output, err := cmd.CombinedOutput()
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("process cannot assign supplementary groups: %v", err)
	}
	if err != nil {
		t.Fatalf("privilege drop subprocess failed: %v\n%s", err, output)
	}
}

func TestMilterAcceptLockSerializesOpeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accept.lock")
	if err := prepareMilterAcceptLock(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareMilterAcceptLock(path); err != nil {
		t.Fatalf("reuse existing lock: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("preparing an existing accept lock replaced its inode")
	}
	first, err := openMilterAcceptLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openMilterAcceptLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("second independent opener acquired held lock: %v", err)
	}
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("unlock first: %v", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("second lock after release: %v", err)
	}

	link := filepath.Join(t.TempDir(), "accept-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openMilterAcceptLock(link); err == nil {
		file.Close()
		t.Fatal("symbolic-link accept lock was opened")
	}
	if err := prepareMilterAcceptLock(link); err == nil {
		t.Fatal("symbolic-link accept lock was prepared")
	}
	other := filepath.Join(t.TempDir(), "accept-hardlink")
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	if file, err := openMilterAcceptLock(other); err == nil {
		file.Close()
		t.Fatal("multiply-linked accept lock was opened")
	}
	if err := prepareMilterAcceptLock(other); err == nil {
		t.Fatal("multiply-linked accept lock was prepared")
	}
}

func TestMilterAcceptLockWaitCanBeCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accept.lock")
	if err := prepareMilterAcceptLock(path); err != nil {
		t.Fatal(err)
	}
	first, err := openMilterAcceptLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openMilterAcceptLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- acquireMilterAcceptLock(ctx, second) }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled lock wait returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled child remained blocked on the accept lock")
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("lock holder was disturbed by cancellation: %v", err)
	}
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := acquireMilterAcceptLock(context.Background(), second); err != nil {
		t.Fatalf("released accept lock could not be acquired: %v", err)
	}
}

func TestNotifyChildReadyStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	notifyChildReady(ctx, time.Millisecond, func() error {
		t.Fatal("canceled child sent a readiness notification")
		return nil
	})
}

func TestDebugConfigSummaryDoesNotExposePrivateKey(t *testing.T) {
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c := &config.Config{
		Path: "config.yaml", EnableDKIM2: true,
		Domains:         map[string]config.Domain{"example.test": {PrivateKeySigner: key, PrivateKeyFile: "secret-key.pem"}},
		DKIM2Forwarding: config.DKIM2ForwardingConfig{Mode: "receive"},
	}
	c.MilterListen.Network, c.MilterListen.Address, c.MilterListen.MaxConnections = "unix", "milter.sock", 4
	summary := debugConfigSummary(c)
	for _, secret := range []string{fmt.Sprint(key), "PrivateKeySigner", "secret-key.pem"} {
		if strings.Contains(summary, secret) {
			t.Fatalf("debug configuration contains a private-key field: %s", summary)
		}
	}
	for _, expected := range []string{`path="config.yaml"`, `network="unix"`, `address="milter.sock"`, "max_connections=4", "domains=1", "dkim2_verify=true", `forwarding="receive"`} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("missing %s from safe debug summary: %s", expected, summary)
		}
	}
}

func TestParentConfigReloadRollsBackLogger(t *testing.T) {
	oldConf, oldParentLog, oldWriter := conf, parentLogFile, log.Writer()
	t.Cleanup(func() {
		if conf != nil && conf.LogFd != nil && conf.LogFd != os.Stderr && conf.LogFd != os.Stdout {
			_ = conf.LogFd.Close()
		}
		conf, parentLogFile = oldConf, oldParentLog
		log.SetOutput(oldWriter)
	})
	dir := t.TempDir()
	current := &config.Config{}
	current.LogFile.Path = filepath.Join(dir, "current.log")
	current.LogFile.Mode = 0600
	conf = current
	if err := openLogFile(); err != nil {
		t.Fatal(err)
	}
	next := &config.Config{}
	next.LogFile.Path = filepath.Join(dir, "next.log")
	next.LogFile.Mode = 0600
	previous, err := switchParentConfig(next)
	if err != nil || previous != current || conf != next {
		t.Fatalf("staging reload: previous=%p conf=%p err=%v", previous, conf, err)
	}
	if err := rollbackParentConfig(previous); err != nil || conf != current {
		t.Fatalf("rollback reload: conf=%p err=%v", conf, err)
	}
	log.Print("rollback marker")
	data, err := os.ReadFile(current.LogFile.Path)
	if err != nil || !strings.Contains(string(data), "rollback marker") {
		t.Fatalf("old log was not restored: %q, %v", data, err)
	}
	data, err = os.ReadFile(next.LogFile.Path)
	if err != nil || strings.Contains(string(data), "rollback marker") {
		t.Fatalf("new log retained writes after rollback: %q, %v", data, err)
	}

	invalid := &config.Config{}
	invalid.LogFile.Path = filepath.Join(dir, "missing", "invalid.log")
	invalid.LogFile.Mode = 0600
	if _, err := switchParentConfig(invalid); err == nil || conf != current {
		t.Fatalf("failed log open committed reload: conf=%p err=%v", conf, err)
	}
}

func TestOpenPrivateLogFileRejectsRedirection(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openPrivateLogFile(link, 0600); err == nil {
		file.Close()
		t.Fatal("symlink log path was opened")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "preserve" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
	hardlink := filepath.Join(dir, "hardlink.log")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if file, err := openPrivateLogFile(hardlink, 0600); err == nil {
		file.Close()
		t.Fatal("multiply-linked log path was opened")
	}
	if file, err := openPrivateLogFile(dir, 0600); err == nil {
		file.Close()
		t.Fatal("directory log path was opened")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if file, err := openPrivateLogFile(target, 0600); err == nil {
		file.Close()
		t.Fatal("log path with broader permissions was opened")
	}
}

func TestValidateReloadConfig(t *testing.T) {
	var current config.Config
	current.MilterListen.Network, current.MilterListen.Address, current.MilterListen.Mode = "unix", "milter.sock", 0600
	current.MilterListen.Uid, current.MilterListen.Gid = 100, 100
	current.ControlSocketFile.Path, current.ControlSocketFile.Mode = "control.sock", 0600
	current.PidFile.Path = "arcmilter.pid"
	for _, tc := range []struct {
		name  string
		edit  func(*config.Config)
		field string
	}{
		{"network", func(c *config.Config) { c.MilterListen.Network = "tcp" }, "MilterListen.Network"},
		{"address", func(c *config.Config) { c.MilterListen.Address = "other.sock" }, "MilterListen.Address"},
		{"socket mode", func(c *config.Config) { c.MilterListen.Mode = 0660 }, "MilterListen.Mode"},
		{"socket owner", func(c *config.Config) { c.MilterListen.Uid++ }, "MilterListen.Owner"},
		{"socket group", func(c *config.Config) { c.MilterListen.Gid++ }, "MilterListen.Group"},
		{"control path", func(c *config.Config) { c.ControlSocketFile.Path = "other-control.sock" }, "ControlSocketFile.Path"},
		{"control mode", func(c *config.Config) { c.ControlSocketFile.Mode = 0660 }, "ControlSocketFile.Mode"},
		{"PID path", func(c *config.Config) { c.PidFile.Path = "other.pid" }, "PIDFile.Path"},
		{"worker limits and identities", func(c *config.Config) { c.MilterListen.MaxConnections = 8; c.Uid++; c.Gid++ }, ""},
		{"signing and cache policy", func(c *config.Config) {
			c.EnableDKIM2 = true
			c.DKIM2Forwarding.Mode = "receive"
			c.DKIM2Forwarding.MaxAgeSeconds = 86400
		}, ""},
		{"log file", func(c *config.Config) { c.LogFile.Path = "new.log" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := current
			tc.edit(&next)
			err := validateReloadConfig(&current, &next)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("reloadable setting rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "restart required") {
				t.Fatalf("startup setting change accepted: %v", err)
			}
		})
	}
}

func TestExecRejectsReloadOfParentBoundSettings(t *testing.T) {
	f := newExecTest(t)
	f.build(t)
	f.start(t)
	path := filepath.Join(f.dir, "test.yaml")
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, base, 0600); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		section, field string
		value          interface{}
	}{
		{"MilterListen", "Network", "tcp"},
		{"MilterListen", "Address", filepath.Join(f.dir, "other.sock")},
		{"MilterListen", "Mode", 0660},
		{"ControlSocketFile", "Path", filepath.Join(f.dir, "other-control.sock")},
		{"ControlSocketFile", "Mode", 0660},
		{"PIDFile", "Path", filepath.Join(f.dir, "other.pid")},
	} {
		t.Run(tc.section+"."+tc.field, func(t *testing.T) {
			var next map[string]interface{}
			if err := yaml.Unmarshal(base, &next); err != nil {
				t.Fatal(err)
			}
			next[tc.section].(map[string]interface{})[tc.field] = tc.value
			if tc.section == "MilterListen" && tc.field == "Network" {
				next["MilterListen"].(map[string]interface{})["AllowTCPWithSigning"] = true
			}
			raw, err := yaml.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			offset := f.logOffset(t)
			if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatal(err)
			}
			f.waitLog(t, offset, func(log string) bool { return strings.Contains(log, "restart required") })
			f.checkSelector(t, "default")
			buf, err := os.ReadFile(filepath.Join(f.dir, "arcmilter.log"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(buf[offset:]), "child process started") {
				t.Fatal("restart-only configuration spawned a replacement child")
			}
		})
	}
}

func TestExecChildRestartKeepsLastAcceptedConfig(t *testing.T) {
	f := newExecTest(t)
	f.build(t)
	f.start(t)
	path := filepath.Join(f.dir, "test.yaml")
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rejected map[string]interface{}
	if err := yaml.Unmarshal(base, &rejected); err != nil {
		t.Fatal(err)
	}
	listener := rejected["MilterListen"].(map[string]interface{})
	listener["Network"] = "tcp"
	listener["Address"] = "127.0.0.1:10029"
	listener["AllowTCPWithSigning"] = true
	raw, err := yaml.Marshal(rejected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	offset := f.logOffset(t)
	if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	f.waitLog(t, offset, func(log string) bool {
		return strings.Contains(log, "MilterListen.Network cannot change during reload")
	})

	oldPID := f.childPID
	offset = f.logOffset(t)
	if err := syscall.Kill(oldPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	f.childPID = f.waitLogPID(t, "child process ready", offset)
	if f.childPID == oldPID {
		t.Fatal("child was not replaced after rejected reload")
	}
	// The inherited listener is Unix. A child that adopts the rejected TCP
	// setting closes every Unix connection before it reaches the Milter server.
	f.checkSelector(t, "default")

	// An edit without SIGHUP must likewise wait until the parent accepts it.
	var unrequested map[string]interface{}
	if err := yaml.Unmarshal(base, &unrequested); err != nil {
		t.Fatal(err)
	}
	unrequested["Domains"].(map[string]interface{})["example.jp"].(map[string]interface{})["Selector"] = "unrequested"
	raw, err = yaml.Marshal(unrequested)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	oldPID = f.childPID
	offset = f.logOffset(t)
	if err := syscall.Kill(oldPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	f.childPID = f.waitLogPID(t, "child process ready", offset)
	if f.childPID == oldPID {
		t.Fatal("child was not replaced after unrequested edit")
	}
	f.checkSelector(t, "default")
}

func TestExecPendingChildStopsWithoutAcceptLock(t *testing.T) {
	for _, termination := range []struct {
		name   string
		signal syscall.Signal
	}{{"normal exit", syscall.SIGTERM}, {"abnormal exit", syscall.SIGKILL}} {
		t.Run(termination.name, func(t *testing.T) {
			f := newExecTest(t)
			f.build(t)
			f.start(t)
			oldPID := f.childPID
			// A stopped old child retains the accept lock even after the parent
			// asks it to exit. Its replacement must still honor cancellation.
			if err := syscall.Kill(oldPID, syscall.SIGSTOP); err != nil {
				t.Fatal(err)
			}
			paused := true
			defer func() {
				if paused {
					_ = syscall.Kill(oldPID, syscall.SIGCONT)
				}
			}()
			offset := f.logOffset(t)
			if err := f.cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatal(err)
			}
			pendingPID := f.waitLogPID(t, "child process started", offset)
			if pendingPID == oldPID {
				t.Fatal("reload did not start a replacement child")
			}
			f.waitLog(t, offset, func(log string) bool {
				return strings.Contains(log, fmt.Sprintf("child process ready pid=%d", pendingPID))
			})
			f.waitLog(t, offset, func(log string) bool {
				return strings.Contains(log, fmt.Sprintf("sent SIGTERM to old child process pid=%d", oldPID))
			})
			if err := syscall.Kill(pendingPID, termination.signal); err != nil {
				t.Fatal(err)
			}
			f.waitLog(t, offset, func(log string) bool {
				return strings.Contains(log, fmt.Sprintf("child process exit pid=%d", pendingPID))
			})
			offset = f.logOffset(t)
			if err := syscall.Kill(oldPID, syscall.SIGCONT); err != nil {
				t.Fatal(err)
			}
			paused = false
			f.childPID = f.waitLogPID(t, "child process ready", offset)
			if f.childPID == oldPID || f.childPID == pendingPID {
				t.Fatal("handoff did not replenish its lost children")
			}
			f.checkSelector(t, "default")
		})
	}
}

func TestMilterPeerListener(t *testing.T) {
	done := errors.New("accept complete")
	untrusted := &milterPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}}
	malformed := &milterPeerTestConn{remote: milterPeerTestAddr("not a TCP address")}
	trusted := &milterPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346}}
	listener := &milterPeerListener{
		Listener: &milterPeerTestListener{connections: []net.Conn{untrusted, malformed, trusted}, err: done},
		allowed:  net.IP.IsLoopback,
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if conn != trusted || !untrusted.closed || !malformed.closed || trusted.closed {
		t.Fatalf("peer filtering: conn=%p untrusted.closed=%t malformed.closed=%t trusted.closed=%t",
			conn, untrusted.closed, malformed.closed, trusted.closed)
	}
	_ = trusted.Close()

	last := &milterPeerTestConn{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 12347}}
	listener.Listener = &milterPeerTestListener{connections: []net.Conn{last}, err: done}
	if conn, err := listener.Accept(); !errors.Is(err, done) || conn != nil || !last.closed {
		t.Fatalf("rejected final peer: conn=%v err=%v closed=%t", conn, err, last.closed)
	}
}

func TestMilterConnectionListener(t *testing.T) {
	done := errors.New("accept complete")
	first := &milterPeerTestConn{remote: milterPeerTestAddr("first")}
	second := &milterPeerTestConn{remote: milterPeerTestAddr("second")}
	listener := &milterConnectionListener{
		Listener: &milterPeerTestListener{connections: []net.Conn{first, second}, err: done},
		slots:    make(chan struct{}, 1),
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	limited, ok := conn.(*milterLimitedConn)
	if !ok {
		t.Fatalf("first admission returned %T, want *milterLimitedConn", conn)
	}
	packet, ok := limited.Conn.(*milterPacketLimitedConn)
	if !ok || packet.Conn != first || first.closed || len(listener.slots) != 1 {
		t.Fatalf("first admission: conn=%T first.closed=%t slots=%d", conn, first.closed, len(listener.slots))
	}
	if conn, err := listener.Accept(); !errors.Is(err, done) || conn != nil || !second.closed || len(listener.slots) != 1 {
		t.Fatalf("full admission: conn=%v err=%v second.closed=%t slots=%d", conn, err, second.closed, len(listener.slots))
	}
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}
	if !first.closed || len(listener.slots) != 0 {
		t.Fatalf("release: first.closed=%t slots=%d", first.closed, len(listener.slots))
	}

	third := &milterPeerTestConn{remote: milterPeerTestAddr("third")}
	listener.Listener = &milterPeerTestListener{connections: []net.Conn{third}, err: done}
	conn, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !third.closed || len(listener.slots) != 0 {
		t.Fatalf("readmission: third.closed=%t slots=%d", third.closed, len(listener.slots))
	}
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
		permission: 0600,
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

func newExecTest(t *testing.T) *execTest {
	t.Helper()
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
	return f
}

func TestExec(t *testing.T) {
	f := newExecTest(t)
	if !t.Run("build", f.build) || !t.Run("version", f.version) || !t.Run("exec", f.start) {
		return
	}
	t.Run("milter", func(t *testing.T) { testMilter(t, filepath.Join(f.dir, "arcmilter.sock")) })
	// 最初の子を正常終了させ、Milterの全ケースのカウンターを回収してから強制終了を検証する。
	if !t.Run("reload", f.reload) || !t.Run("restart", f.restart) || !t.Run("reload-invalid", f.reloadInvalid) || !t.Run("restart-after-invalid-reload", f.restart) || !t.Run("reload-timeout", f.reloadTimeout) || !t.Run("restart-after-reload-timeout", f.restart) {
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
	keyData, err := os.ReadFile("t/key")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(f.dir, "key")
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		t.Fatal(err)
	}
	conf["Domains"].(map[string]interface{})["example.jp"].(map[string]interface{})["PrivateKeyFile"] = keyPath
	if f.configure != nil {
		f.configure(conf)
	}
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

// rawMilterHeader は Milter の LF 区切りの値をメール形式の CRLF に戻す。
func rawMilterHeader(name, value string) string {
	return name + ": " + strings.ReplaceAll(value, "\n", "\r\n") + "\r\n"
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
					"spf=fail smtp.mailfrom=example.com",
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
						d, err := dkim.ParseSignature(rawMilterHeader(mAct.HeaderName, mAct.HeaderValue))
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
						d, err := arc.ParseARCMessageSignature(rawMilterHeader(mAct.HeaderName, mAct.HeaderValue))
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
						d, err := arc.ParseARCAuthenticationResults(rawMilterHeader(mAct.HeaderName, mAct.HeaderValue))
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
						d, err := arc.ParseARCSeal(rawMilterHeader(mAct.HeaderName, mAct.HeaderValue))
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
	f.checkSelector(t, "reloaded")
	buf, err := os.ReadFile(filepath.Join(f.dir, "arcmilter.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(buf[offset:]), "child process started") {
		t.Fatal("invalid configuration spawned a replacement child")
	}
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
			sig, err := dkim.ParseSignature(rawMilterHeader(mod.HeaderName, mod.HeaderValue))
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

func TestAcquirePidFile(t *testing.T) {
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
			file, err := acquirePidFile(pidFile)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				defer file.Close()
				if second, err := acquirePidFile(pidFile); err == nil {
					second.Close()
					t.Error("concurrent parent acquired the same pid file")
				}
				buf, err := os.ReadFile(pidFile)
				if err != nil || string(buf) != strconv.Itoa(os.Getpid()) {
					t.Errorf("pid file content = %q, %v", buf, err)
				}
			}
		})
	}
}

func TestAcquirePidFileRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := acquirePidFile(link); err == nil {
		file.Close()
		t.Fatal("symlink pid file was accepted")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "preserve" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}

	unsafe := filepath.Join(dir, "unsafe.pid")
	if err := os.WriteFile(unsafe, []byte("preserve"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0666); err != nil {
		t.Fatal(err)
	}
	if file, err := acquirePidFile(unsafe); err == nil {
		file.Close()
		t.Fatal("group/world-writable pid file was accepted")
	}
	if got, err := os.ReadFile(unsafe); err != nil || string(got) != "preserve" {
		t.Fatalf("unsafe file changed: %q, %v", got, err)
	}

	hardlink := filepath.Join(dir, "hardlink.pid")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if file, err := acquirePidFile(hardlink); err == nil {
		file.Close()
		t.Fatal("multiply-linked pid file was accepted")
	}

	tooLarge := filepath.Join(dir, "large.pid")
	if err := os.WriteFile(tooLarge, []byte(strings.Repeat("1", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := acquirePidFile(tooLarge); err == nil {
		file.Close()
		t.Fatal("oversized pid file was accepted")
	}
}

func TestRemovePidFileDoesNotUnlinkReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")
	file, err := acquirePidFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(dir, "old.pid")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePidFile(path, file); err == nil {
		t.Fatal("replacement pid file was removed")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement file changed: %q, %v", got, err)
	}
}
