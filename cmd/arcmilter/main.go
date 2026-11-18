package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/masa23/arcmilter/arcmilter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/arcmilter/control"
)

var (
	version        = "dev"
	conf           *config.Config
	childlen       []child
	childMu        sync.Mutex
	msockfd        *os.File
	pidFile        *os.File
	acceptLockPath string
	parentLogMu    sync.Mutex
	parentLogFile  *os.File
	parentStopping bool
	activeConf     *config.Config // protected by parentLogMu
)

const (
	childReadyTimeout = 10 * time.Second
	childRestartDelay = time.Second
)

type child struct {
	Process *os.Process
	Ready   bool
}

// milterPeerListener validates the real TCP peer before go-milter reads any
// protocol-supplied CONNECT address or macros. Those protocol values describe
// the SMTP session and must never authenticate the process speaking Milter.
type milterPeerListener struct {
	net.Listener
	allowed func(net.IP) bool
}

func (l *milterPeerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, ok := conn.RemoteAddr().(*net.TCPAddr)
		if ok && peer.IP != nil && l.allowed(peer.IP) {
			return conn, nil
		}
		// Keep untrusted clients outside the Milter state machine. In
		// particular, they cannot inject a forged CONNECT address or auth macro.
		_ = conn.Close()
	}
}

// milterConnectionListener bounds all live Milter sessions, including Unix
// sockets. This is an aggregate guard for per-message parsers and DKIM2 raw
// captures; a per-message byte limit alone cannot prevent concurrent OOMs.
type milterConnectionListener struct {
	net.Listener
	slots chan struct{}
}

func (l *milterConnectionListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &milterLimitedConn{Conn: limitMilterPackets(conn), release: func() { <-l.slots }}, nil
		default:
			// Do not let connections waiting for a slot consume descriptors or
			// unbounded goroutines in go-milter. The MTA can retry later.
			_ = conn.Close()
		}
	}
}

type milterLimitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

// listenPrivateUnix prevents a local client from connecting in the short
// interval between bind and the configured Chmod. The parent is still
// single-threaded here, so temporarily tightening the process umask is safe.
func listenPrivateUnix(address string) (net.Listener, error) {
	if err := validatePrivateRuntimeDirectory(address); err != nil {
		return nil, err
	}
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	return net.Listen("unix", address)
}

// Socket permissions and PID/lock file identities depend on their pathname.
func validatePrivateRuntimeDirectory(address string) error {
	return config.ValidateTrustedParentDirectory(address)
}

func removeStaleUnixSocket(path string, expectedUID int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) && stat.Uid != uint32(expectedUID) {
		return fmt.Errorf("existing socket path %s is not an owned Unix socket", path)
	}
	return os.Remove(path)
}

func configureUnixSocket(path string, mode fs.FileMode, uid, gid int) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("bound socket path %s changed before permission setup", path)
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if after.Mode()&os.ModeSocket == 0 || !os.SameFile(before, after) {
		return fmt.Errorf("bound socket path %s changed during permission setup", path)
	}
	return nil
}

// prepareMilterAcceptLock creates or reuses the inode used to serialize Accept
// across old and new child processes. It intentionally survives a parent
// restart so a replacement cannot bypass a child that is still exiting. Each
// child opens the path separately so flock sees distinct descriptions.
func prepareMilterAcceptLock(path string) error {
	if err := validatePrivateRuntimeDirectory(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	if err := validateMilterAcceptLock(file); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func openMilterAcceptLock(path string) (*os.File, error) {
	if err := validatePrivateRuntimeDirectory(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := validateMilterAcceptLock(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateMilterAcceptLock(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("Milter accept lock must be an owned private regular file with one link")
	}
	return nil
}

func acquireMilterAcceptLock(ctx context.Context, file *os.File) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if err := ctx.Err(); err != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				return err
			}
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func notifyChildReady(ctx context.Context, delay time.Duration, notify func() error) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	if ctx.Err() != nil {
		return
	}
	if err := notify(); err != nil && ctx.Err() == nil {
		log.Printf("failed to notify child ready: %v", err)
	}
}

func dropChildPrivileges(uid, gid int) error {
	// Setgid does not clear supplementary groups inherited from the parent.
	// Clear them while still privileged, before changing the primary GID/UID.
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups(nil); err != nil {
			return fmt.Errorf("clear supplementary groups: %w", err)
		}
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("set gid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("set uid: %w", err)
	}
	return nil
}

func (c *milterLimitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// acquirePidFile holds an exclusive lock for the entire parent lifetime. The
// file is opened without following symlinks and is only rewritten through the
// validated descriptor, so a stale PID cannot redirect a privileged write.
func acquirePidFile(path string) (_ *os.File, err error) {
	if err := validatePrivateRuntimeDirectory(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open pid file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat pid file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("pid file must be an owned, non-writable regular file with one link")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("pid file %s is locked by another process", path)
		}
		return nil, fmt.Errorf("failed to lock pid file: %w", err)
	}
	buf, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return nil, fmt.Errorf("failed to read pid file: %w", err)
	}
	if len(buf) == 64 {
		return nil, errors.New("pid file is too large")
	}
	pidStr := strings.TrimSpace(string(buf))
	if pidStr != "" {
		oldPid, parseErr := strconv.Atoi(pidStr)
		if parseErr != nil || oldPid <= 0 {
			return nil, fmt.Errorf("failed to parse pid file: invalid pid %q", pidStr)
		}
		if killErr := syscall.Kill(oldPid, 0); killErr == nil {
			return nil, fmt.Errorf("pid file %s already exists", path)
		} else if !errors.Is(killErr, syscall.ESRCH) {
			return nil, fmt.Errorf("pid file %s already exists (process %d exists but cannot be signaled: %v)", path, oldPid, killErr)
		}
	}
	if err := file.Truncate(0); err != nil {
		return nil, fmt.Errorf("failed to truncate pid file: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek pid file: %w", err)
	}
	if _, err := file.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		return nil, fmt.Errorf("failed to write pid file: %w", err)
	}
	return file, nil
}

func removePidFile(path string, file *os.File) error {
	if file == nil {
		return nil
	}
	defer file.Close()
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	held, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(current, held) {
		return errors.New("pid file changed after startup")
	}
	return os.Remove(path)
}

func addChild(p *os.Process) {
	childMu.Lock()
	defer childMu.Unlock()
	childlen = append(childlen, child{
		Process: p,
		Ready:   false,
	})
}

func removeChild(p *os.Process) {
	childMu.Lock()
	defer childMu.Unlock()
	for i, c := range childlen {
		if c.Process == p {
			childlen = append(childlen[:i], childlen[i+1:]...)
			break
		}
	}
}

func childCount() int {
	childMu.Lock()
	defer childMu.Unlock()
	return len(childlen)
}

func markChildReady(pid int) {
	childMu.Lock()
	defer childMu.Unlock()
	for i, c := range childlen {
		if c.Process.Pid == pid {
			childlen[i].Ready = true
			break
		}
	}
}

func setChildrenReady(ready bool) {
	childMu.Lock()
	defer childMu.Unlock()
	for i := range childlen {
		childlen[i].Ready = ready
	}
}

func restoreChildrenReady(children []child) {
	childMu.Lock()
	defer childMu.Unlock()
	readyByPid := make(map[int]bool, len(children))
	for _, c := range children {
		readyByPid[c.Process.Pid] = c.Ready
	}
	for i, c := range childlen {
		if ready, ok := readyByPid[c.Process.Pid]; ok {
			childlen[i].Ready = ready
		}
	}
}

func hasReadyChild() bool {
	childMu.Lock()
	defer childMu.Unlock()
	for _, c := range childlen {
		if c.Ready {
			return true
		}
	}
	return false
}

func isChildReady(pid int) bool {
	childMu.Lock()
	defer childMu.Unlock()
	for _, c := range childlen {
		if c.Process.Pid == pid {
			return c.Ready
		}
	}
	return false
}

func childrenSnapshot() []child {
	childMu.Lock()
	defer childMu.Unlock()
	children := make([]child, len(childlen))
	copy(children, childlen)
	return children
}

func childrenOtherThan(pid int) []child {
	children := childrenSnapshot()
	others := children[:0]
	for _, c := range children {
		if c.Process.Pid != pid {
			others = append(others, c)
		}
	}
	return others
}

func openLogFile() error {
	parentLogMu.Lock()
	defer parentLogMu.Unlock()
	previous := conf.LogFd
	next := os.Stderr
	var openErr error
	if conf.LogFile.Path != "" {
		fd, err := openPrivateLogFile(conf.LogFile.Path, fs.FileMode(conf.LogFile.Mode))
		if err != nil {
			openErr = fmt.Errorf("failed to open log file: %v", err)
		} else {
			next = fd
		}
	}
	conf.LogFd = next
	parentLogFile = next
	log.SetOutput(next)
	if previous != nil && previous != next && previous != os.Stderr && previous != os.Stdout {
		if err := previous.Close(); err != nil {
			log.Printf("failed to close log file: %v", err)
		}
	}
	return openErr
}

func openPrivateLogFile(path string, mode fs.FileMode) (*os.File, error) {
	if err := validatePrivateRuntimeDirectory(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm()&^mode.Perm() != 0 {
		_ = file.Close()
		return nil, errors.New("log file must be an owned regular file with one link and no extra permissions")
	}
	return file, nil
}

func switchParentConfig(next *config.Config) (*config.Config, error) {
	previous := conf
	next.LogFd = previous.LogFd
	conf = next
	if err := openLogFile(); err != nil {
		if rollbackErr := rollbackParentConfig(previous); rollbackErr != nil {
			return previous, fmt.Errorf("reload log open failed: %w; restoring old log failed: %v", err, rollbackErr)
		}
		return previous, err
	}
	return previous, nil
}

func rollbackParentConfig(previous *config.Config) error {
	previous.LogFd = conf.LogFd
	conf = previous
	return openLogFile()
}

// The caller holds parentLogMu until the process has started and is registered
// in childlen. Log rotation and parent shutdown cannot invalidate this copy or
// miss a replacement child that is being created at the same time.
func duplicateParentLogFileLocked() (*os.File, error) {
	if parentLogFile == nil {
		return nil, errors.New("parent log file is unavailable")
	}
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := syscall.Dup(int(parentLogFile.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "child-log"), nil
}

func debugConfigSummary(c *config.Config) string {
	// PrivateKeySigner can contain the entire Ed25519 private key as a slice.
	// Logging the Config or Domains structs would disclose it with %+v.
	return fmt.Sprintf("config: path=%q network=%q address=%q max_connections=%d domains=%d dkim2_verify=%t forwarding=%q",
		c.Path, c.MilterListen.Network, c.MilterListen.Address, c.MilterListen.MaxConnections,
		len(c.Domains), c.EnableDKIM2, c.DKIM2Forwarding.Mode)
}

func validateReloadConfig(current, next *config.Config) error {
	for _, field := range []struct {
		name    string
		changed bool
	}{
		{"MilterListen.Network", current.MilterListen.Network != next.MilterListen.Network},
		{"MilterListen.Address", current.MilterListen.Address != next.MilterListen.Address},
		{"MilterListen.Mode", current.MilterListen.Network == "unix" && current.MilterListen.Mode != next.MilterListen.Mode},
		{"MilterListen.Owner", current.MilterListen.Network == "unix" && current.MilterListen.Uid != next.MilterListen.Uid},
		{"MilterListen.Group", current.MilterListen.Network == "unix" && current.MilterListen.Gid != next.MilterListen.Gid},
		{"ControlSocketFile.Path", current.ControlSocketFile.Path != next.ControlSocketFile.Path},
		{"ControlSocketFile.Mode", current.ControlSocketFile.Mode != next.ControlSocketFile.Mode},
		{"PIDFile.Path", current.PidFile.Path != next.PidFile.Path},
	} {
		if field.changed {
			return fmt.Errorf("%s cannot change during reload; restart required", field.name)
		}
	}
	return nil
}

func checkSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM)
	for {
		switch <-sig {
		case syscall.SIGHUP:
			// 設定ファイルを再読み込み
			newConf, err := config.Load(conf.Path)
			if err != nil {
				log.Printf("failed to load config: %v path=%s", err, conf.Path)
				continue
			}
			if err := validateReloadConfig(conf, newConf); err != nil {
				log.Printf("failed to reload config: %v path=%s", err, conf.Path)
				continue
			}
			previousConf, err := switchParentConfig(newConf)
			if err != nil {
				log.Printf("failed to open reload log file: %v", err)
				continue
			}
			// 新しい子自身の準備完了を待つ。
			newChild := execChildProcess(msockfd, acceptLockPath, newConf)
			// Ready trueの子プロセスを待つ
			ticker := time.NewTicker(1 * time.Second)
			timer := time.NewTimer(childReadyTimeout)
			ready := false
		waitReady:
			for {
				select {
				case <-ticker.C:
					if isChildReady(newChild.Pid) {
						ready = true
					}
				case <-timer.C:
					log.Printf("timed out waiting for child process readiness")
					break waitReady
				}
				if ready {
					break
				}
			}
			ticker.Stop()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if !ready {
				if err := newChild.Signal(syscall.SIGTERM); err != nil {
					log.Printf("failed to send signal to new child process: %v", err)
				}
				if err := rollbackParentConfig(previousConf); err != nil {
					log.Printf("failed to restore previous log file after reload timeout: %v", err)
				}
				continue
			}
			parentLogMu.Lock()
			activeConf = newConf
			parentLogMu.Unlock()
			// 起動中に自動補充された子も含め、準備完了を待った子以外を停止する。
			for _, c := range childrenOtherThan(newChild.Pid) {
				if err := c.Process.Signal(syscall.SIGTERM); err != nil {
					if !errors.Is(err, os.ErrProcessDone) {
						log.Printf("failed to send signal to child process: %v", err)
					}
				} else {
					log.Printf("sent SIGTERM to old child process pid=%d", c.Process.Pid)
				}
			}
		case syscall.SIGTERM:
			parentLogMu.Lock()
			parentStopping = true
			parentLogMu.Unlock()
			// 子プロセスを終了
			for _, c := range childrenSnapshot() {
				// 子プロセスにSIGTERMを送る
				if err := c.Process.Signal(syscall.SIGTERM); err != nil {
					log.Printf("failed to send signal to child process: %v", err)
				}
			}
			// PIDファイルを削除
			if err := removePidFile(conf.PidFile.Path, pidFile); err != nil {
				log.Printf("failed to remove pid file: %v", err)
			}
			// ログファイルを閉じる
			parentLogMu.Lock()
			parentLogFile = nil
			if conf.LogFd != nil && conf.LogFd != os.Stderr && conf.LogFd != os.Stdout {
				if err := conf.LogFd.Close(); err != nil {
					log.Printf("failed to close log file: %v", err)
				}
			}
			parentLogMu.Unlock()
			os.Exit(0)
		}
	}
}

func childProcess() {
	socketfd := os.NewFile(uintptr(4), "socket")
	socket, err := net.FileListener(socketfd)
	if err != nil {
		log.Fatalf("Failed to get socket: %v", err)
	}
	defer socket.Close()
	acceptLock := os.NewFile(uintptr(5), "milter-accept-lock")
	if acceptLock == nil {
		log.Fatal("Failed to get Milter accept lock")
	}
	if conf.MilterListen.Network == "tcp" {
		socket = &milterPeerListener{Listener: socket, allowed: conf.IsAllowedMilterPeer}
	}
	socket = &milterConnectionListener{
		Listener: socket,
		slots:    make(chan struct{}, conf.MilterListen.MaxConnections),
	}

	// control用のソケットに接続
	ctrl, err := rpc.Dial("unix", conf.ControlSocketFile.Path)
	if err != nil {
		log.Fatalf("Failed to connect control socket: %v", err)
	}
	defer ctrl.Close()

	// ArcMilterServerの作成
	server := arcmilter.New(ctrl)
	server.SetDebug(conf.Debug)

	// 子プロセスの権限を変更
	if err := dropChildPrivileges(conf.Uid, conf.Gid); err != nil {
		log.Fatalf("Failed to drop child privileges: %v", err)
	}

	if conf.Debug {
		log.Print(debugConfigSummary(conf))
	}

	childCtx, cancelChild := context.WithCancel(context.Background())
	defer cancelChild()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-childCtx.Done():
			return
		case <-sig:
			log.Printf("received SIGTERM child process closing socket pid=%d", os.Getpid())
			cancelChild()
			if err := socket.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("failed to close socket: %v", err)
			}
		}
	}()

	// 1秒待ってから親プロセスに準備完了を通知
	go notifyChildReady(childCtx, time.Second, func() error {
		return ctrl.Call("Control.ChildReady", control.ChildReadyArgs{Pid: os.Getpid()}, &struct{}{})
	})

	// A replacement child can finish initialization while the old child keeps
	// serving, but only one process may enter Accept. This preserves the global
	// MaxConnections memory bound across SIGHUP reloads.
	if err := acquireMilterAcceptLock(childCtx, acceptLock); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Fatalf("Failed to acquire Milter accept lock: %v", err)
	}
	if childCtx.Err() != nil {
		return
	}

	err = server.Serve(socket, conf)
	// Do not close this descriptor before the process exits: releasing flock
	// earlier could let the replacement accept while old session goroutines are
	// still being torn down. KeepAlive also prevents an os.File finalizer from
	// releasing it while Serve is running.
	runtime.KeepAlive(acceptLock)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("Failed to serve milter: %v", err)
	}
}

func startChildIfAllowed(onlyIfEmpty bool, start func() *os.Process) *os.Process {
	parentLogMu.Lock()
	defer parentLogMu.Unlock()
	if parentStopping || onlyIfEmpty && childCount() != 0 {
		return nil
	}
	p := start()
	if p != nil {
		addChild(p)
	}
	return p
}

func execChildProcess(msockfd *os.File, lockPath string, snapshot *config.Config) *os.Process {
	return execChildProcessIfNeeded(msockfd, lockPath, false, snapshot)
}

func execChildProcessIfNeeded(msockfd *os.File, lockPath string, onlyIfEmpty bool, snapshot *config.Config) *os.Process {
	var cmd *exec.Cmd
	p := startChildIfAllowed(onlyIfEmpty, func() *os.Process {
		if snapshot == nil {
			snapshot = activeConf
		}
		if snapshot == nil || len(snapshot.SourceYAML) == 0 {
			log.Fatal("No accepted configuration snapshot for child process")
		}
		childSocket, err := socketFileForChild(msockfd)
		if err != nil {
			log.Fatalf("Failed to duplicate socket for child process: %v", err)
		}
		defer childSocket.Close()
		acceptLock, err := openMilterAcceptLock(lockPath)
		if err != nil {
			log.Fatalf("Failed to open Milter accept lock: %v", err)
		}
		defer acceptLock.Close()
		logfd, err := duplicateParentLogFileLocked()
		if err != nil {
			log.Fatalf("Failed to duplicate log file for child process: %v", err)
		}
		defer logfd.Close()
		configReader, configWriter, err := os.Pipe()
		if err != nil {
			log.Fatalf("Failed to create child configuration pipe: %v", err)
		}
		defer configReader.Close()
		cmd = &exec.Cmd{
			Stdin:  os.Stdin,
			Stdout: logfd,
			Stderr: logfd,
			Path:   os.Args[0],
			Args:   append(os.Args, "-child"),
			ExtraFiles: []*os.File{
				logfd,
				childSocket,
				acceptLock,
				configReader,
			},
		}
		if err := cmd.Start(); err != nil {
			_ = configWriter.Close()
			log.Fatalf("Failed to start child process: %v", err)
		}
		go func(pid int, source []byte) {
			defer configWriter.Close()
			if _, err := io.Copy(configWriter, bytes.NewReader(source)); err != nil {
				log.Printf("failed to send accepted configuration to child pid=%d: %v", pid, err)
			}
		}(cmd.Process.Pid, snapshot.SourceYAML)
		return cmd.Process
	})
	if p == nil {
		return nil
	}
	log.Printf("child process started pid=%d", p.Pid)
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("child process wait error: %v", err)
		}
		removeChild(p)
		log.Printf("child process exit pid=%d", p.Pid)
		// A handoff can lose its replacement before the old process exits.
		// Replenish the last child on either normal or abnormal exit. Delay
		// retries so an invalid configuration cannot create a busy restart loop.
		timer := time.NewTimer(childRestartDelay)
		defer timer.Stop()
		<-timer.C
		// The shared lifecycle lock prevents duplicate replacements and any
		// spawning after parent shutdown has begun.
		execChildProcessIfNeeded(msockfd, lockPath, true, nil)
	}()
	return p
}

// net.Listener.Fileが返すFileは、Fdを呼ぶたびに共有ソケットをblockingにする。
// ExtraFiles用に通常のFileとして複製し、既存の子のAcceptをブロックさせない。
func socketFileForChild(socket *os.File) (*os.File, error) {
	raw, err := socket.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(source uintptr) {
		// DupとCloseOnExecの間に、別のgoroutineが子を起動しないようにする。
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
		fd, dupErr = syscall.Dup(int(source))
		if dupErr == nil {
			syscall.CloseOnExec(fd)
		}
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "milter-socket"), nil
}

func main() {
	var child bool
	var confPath string
	var err error
	var versionFlag bool

	flag.StringVar(&confPath, "conf", "arcmilter.yaml", "config file path")
	flag.BoolVar(&child, "child", false, "child process")
	flag.BoolVar(&versionFlag, "version", false, "show version")
	flag.Parse()

	// バージョン表示
	if versionFlag {
		fmt.Printf("arcmilter version %s\n", version)
		os.Exit(0)
	}

	// panicを補足してログに出力
	defer func() {
		if err := recover(); err != nil {
			log.Printf("Panic: %v", err)
		}
	}()

	if child {
		logfd := os.NewFile(uintptr(3), "log")
		log.SetOutput(logfd)
	}

	// Only the parent reads the on-disk configuration. Children receive the
	// snapshot approved by the parent through descriptor 6.
	if child {
		configReader := os.NewFile(uintptr(6), "accepted-config")
		if configReader == nil {
			log.Fatal("Missing accepted configuration descriptor")
		}
		buf, readErr := io.ReadAll(io.LimitReader(configReader, config.MaxConfigBytes+1))
		_ = configReader.Close()
		if readErr != nil {
			log.Fatalf("Failed to read accepted configuration: %v", readErr)
		}
		conf, err = config.LoadTrustedSnapshot(confPath, buf)
	} else {
		conf, err = config.Load(confPath)
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// childプロセスの場合
	if child {
		// child process
		conf.LogFd = os.NewFile(uintptr(3), "log")
		childProcess()
		return
	}
	activeConf = conf

	// PIDファイルを確認
	pidFile, err = acquirePidFile(conf.PidFile.Path)
	if err != nil {
		log.Fatalf("Failed to check pid file: %v", err)
	}
	acceptLockPath = conf.PidFile.Path + ".accept.lock"
	if err := prepareMilterAcceptLock(acceptLockPath); err != nil {
		log.Fatalf("Failed to prepare Milter accept lock: %v", err)
	}

	// ログファイルをセットする
	if err := openLogFile(); err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	if conf.MilterListen.Network == "unix" {
		// milter listen
		if err := validatePrivateRuntimeDirectory(conf.MilterListen.Address); err != nil {
			log.Fatalf("Unsafe Milter socket directory: %v", err)
		}
		if err := removeStaleUnixSocket(conf.MilterListen.Address, conf.MilterListen.Uid); err != nil {
			log.Fatalf("Failed to remove socket: %v", err)
		}
		msocket, err := listenPrivateUnix(conf.MilterListen.Address)
		if err != nil {
			log.Fatalf("Failed to listen socket: %v", err)
		}
		defer msocket.Close()
		if err := configureUnixSocket(conf.MilterListen.Address, fs.FileMode(conf.MilterListen.Mode),
			conf.MilterListen.Uid, conf.MilterListen.Gid); err != nil {
			log.Fatalf("Failed to configure Milter socket: %v", err)
		}
		msockfd, err = msocket.(*net.UnixListener).File()
		if err != nil {
			log.Fatalf("Failed to get socket fd: %v", err)
		}
	} else {
		// milter listen
		msocket, err := net.Listen(conf.MilterListen.Network, conf.MilterListen.Address)
		if err != nil {
			log.Fatalf("Failed to listen socket: %v", err)
		}
		defer msocket.Close()
		msockfd, err = msocket.(*net.TCPListener).File()
		if err != nil {
			log.Fatalf("Failed to get socket fd: %v", err)
		}
	}

	// controlのソケットを作成
	if err := validatePrivateRuntimeDirectory(conf.ControlSocketFile.Path); err != nil {
		log.Fatalf("Unsafe control socket directory: %v", err)
	}
	if err := removeStaleUnixSocket(conf.ControlSocketFile.Path, os.Geteuid()); err != nil {
		log.Fatalf("Failed to remove socket: %v", err)
	}
	csocket, err := listenPrivateUnix(conf.ControlSocketFile.Path)
	if err != nil {
		log.Fatalf("Failed to listen socket: %v", err)
	}
	defer csocket.Close()
	if err := configureUnixSocket(conf.ControlSocketFile.Path, fs.FileMode(conf.ControlSocketFile.Mode), -1, -1); err != nil {
		log.Fatalf("Failed to configure control socket: %v", err)
	}

	// control rpcサーバーを起動
	go func() {
		ctrl := control.New(func(pid int) {
			log.Printf("child process ready pid=%d", pid)
			markChildReady(pid)
		})
		if err := ctrl.Serve(csocket); err != nil {
			log.Fatalf("Failed to serve control socket: %v", err)
		}
	}()

	// 子プロセスの実行
	go execChildProcess(msockfd, acceptLockPath, nil)

	checkSignal()
}
