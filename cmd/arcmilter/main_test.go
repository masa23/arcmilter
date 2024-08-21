package main

import (
	"errors"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/d--j/go-milter"
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
	path      string
	permisson os.FileMode
	stopExist bool
}{
	{
		path:      "./t/tmp/arcmilter.log",
		permisson: 0600,
		stopExist: true,
	},
	{
		path:      "./t/tmp/arcmilter.pid",
		permisson: 0644,
		stopExist: false,
	},
	{
		path:      "./t/tmp/arcmilter.sock",
		permisson: 0600,
		stopExist: true,
	},
	{
		path:      "./t/tmp/arcmilterctl.sock",
		permisson: 0600,
		stopExist: true,
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
		if info.Mode().Perm() != f.permisson {
			t.Fatalf("unexpected permission %s: %v", f.path, info.Mode().Perm())
		}
	}
}

func testMilter(t *testing.T) {
	// milterに接続して、テストデータを流す
	client := milter.NewClient("unix", "./t/tmp/arcmilter.sock")
	globalMacros := milter.NewMacroBag()
	globalMacros.Set(milter.MacroMTAFQDN, "example.jp")
	globalMacros.Set(milter.MacroMTAPid, strconv.Itoa(os.Getpid()))

	macros := globalMacros.Copy()
	session, err := client.Session(macros)
	if err != nil {
		t.Fatalf("failed to create milter session: %v", err)
	}
	defer session.Close()

	// ToDo: テストデータの作成
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
