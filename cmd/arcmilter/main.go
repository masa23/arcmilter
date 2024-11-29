package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/masa23/arcmilter/arcmilter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/arcmilter/control"
)

var (
	version  = "dev"
	conf     *config.Config
	childlen []child
	msockfd  *os.File
)

type child struct {
	Process *os.Process
	Ready   bool
}

// PIDファイルを確認して、存在していたら終了する
func checkPidFile(path string) error {
	// pidを取得
	pid := os.Getpid()

	// PIDファイルを開く
	buf, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// ファイルが存在しなければ作成
		if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644); err != nil {
			return fmt.Errorf("failed to create pid file: %v", err)
		}
	} else {
		oldPid, err := strconv.Atoi(string(buf))
		if err != nil {
			return fmt.Errorf("failed to parse pid file: %v", err)
		}
		// 既に起動しているか確認
		if err := syscall.Kill(oldPid, 0); err == nil {
			return fmt.Errorf("pid file %s already exists", path)
		} else {
			// 起動していなければ上書き
			if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644); err != nil {
				log.Fatalf("failed to write pid file: %v", err)
			}
		}
	}
	return nil
}

func openLogFile() error {
	if conf.LogFile.Path != "" {
		fd, err := os.OpenFile(conf.LogFile.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, fs.FileMode(conf.LogFile.Mode))
		if err != nil {
			conf.LogFd = os.Stderr
			log.SetOutput(conf.LogFd)
			return fmt.Errorf("failed to open log file: %v", err)
		}
		log.SetOutput(fd)
		if conf.LogFd != nil {
			if err := conf.LogFd.Close(); err != nil {
				log.Printf("failed to close log file: %v", err)
			}
		}
		conf.LogFd = fd
		return nil
	}
	conf.LogFd = os.Stderr
	log.SetOutput(conf.LogFd)
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
			} else {
				// ログファイルを引き継ぐ
				if conf.LogFd != nil {
					newConf.LogFd = conf.LogFd
				}
				conf = newConf
			}
			// ログファイルの開きなおし
			if err := openLogFile(); err != nil {
				log.Printf("failed to open log file: %v", err)
			}
			// 子プロセスのReadyをfalseにする
			for i := range childlen {
				childlen[i].Ready = false
			}
			go execChildProcess(conf.LogFd, msockfd)
			// Ready trueの子プロセスを待つ
			f := false
			for {
				time.Sleep(1 * time.Second)
				for _, c := range childlen {
					if c.Ready {
						f = true
						break
					}
				}
				if f {
					break
				}
			}
			// Ready falseの子プロセスを終了
			for _, c := range childlen {
				if !c.Ready {
					// 子プロセスにSIGTERMを送る
					if err := c.Process.Signal(syscall.SIGTERM); err != nil {
						log.Printf("failed to send signal to child process: %v", err)
					}
				}
			}
		case syscall.SIGTERM:
			// 子プロセスを終了
			for _, c := range childlen {
				// 子プロセスにSIGTERMを送る
				if err := c.Process.Signal(syscall.SIGTERM); err != nil {
					log.Printf("failed to send signal to child process: %v", err)
				}
			}
			// PIDファイルを削除
			if err := os.Remove(conf.PidFile.Path); err != nil {
				log.Printf("failed to remove pid file: %v", err)
			}
			// ログファイルを閉じる
			if conf.LogFd != nil {
				if err := conf.LogFd.Close(); err != nil {
					log.Printf("failed to close log file: %v", err)
				}
			}
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
	if err := syscall.Setgid(conf.Gid); err != nil {
		log.Fatalf("Failed to set gid: %v", err)
	}
	if err := syscall.Setuid(conf.Uid); err != nil {
		log.Fatalf("Failed to set uid: %v", err)
	}

	if conf.Debug {
		log.Printf("config: %+v", conf)
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		for {
			switch <-sig {
			case syscall.SIGTERM:
				log.Printf("received SIGTERM child process closing socket pid=%d", os.Getpid())
				// fdを閉じる
				if err := socket.Close(); err != nil {
					log.Printf("failed to close socket: %v", err)
				}
			}
		}
	}()

	// 1秒待ってから親プロセスに準備完了を通知
	go func() {
		time.Sleep(1 * time.Second)
		// 親プロセスに準備完了を通知
		if err := ctrl.Call("Control.ChildReady", control.ChildReadyArgs{Pid: os.Getpid()}, &struct{}{}); err != nil {
			log.Printf("failed to notify child ready: %v", err)
		}
	}()

	if err := server.Serve(socket, conf); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("Failed to serve milter: %v", err)
	}
}

func execChildProcess(logfd, msockfd *os.File) {
	cmd := exec.Cmd{
		Stdin:  os.Stdin,
		Stdout: logfd,
		Stderr: logfd,
		Path:   os.Args[0],
		Args:   append(os.Args, "-child"),
		ExtraFiles: []*os.File{
			logfd,
			msockfd,
		},
	}
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start child process: %v", err)
	}
	// childlenに追加する
	childlen = append(childlen, child{
		Process: cmd.Process,
		Ready:   false,
	})
	log.Printf("child process started pid=%d", cmd.Process.Pid)
	err = cmd.Wait()
	if err != nil {
		log.Printf("child process wait error: %v", err)
		// 子プロセスが異常終了した場合は再起動
		// すでに子プロセスが2以上起動している場合は再起動しない
		if len(childlen) < 2 {
			go execChildProcess(logfd, msockfd)
		}
	}
	// childlenから消す
	for i, c := range childlen {
		if c.Process == cmd.Process {
			childlen = append(childlen[:i], childlen[i+1:]...)
			break
		}
	}
	log.Printf("child process exit pid=%d", cmd.Process.Pid)
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

	// 設定ファイルを読み込む
	conf, err = config.Load(confPath)
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

	// PIDファイルを確認
	if err := checkPidFile(conf.PidFile.Path); err != nil {
		log.Fatalf("Failed to check pid file: %v", err)
	}

	// ログファイルをセットする
	if err := openLogFile(); err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	if conf.MilterListen.Network == "unix" {
		// milter listen
		if err := os.Remove(conf.MilterListen.Address); err != nil && !os.IsNotExist(err) {
			log.Fatalf("Failed to remove socket: %v", err)
		}
		msocket, err := net.Listen("unix", conf.MilterListen.Address)
		if err != nil {
			log.Fatalf("Failed to listen socket: %v", err)
		}
		defer msocket.Close()
		// socketのパーミッションを変更
		if err := os.Chmod(conf.MilterListen.Address, fs.FileMode(conf.MilterListen.Mode)); err != nil {
			log.Fatalf("Failed to change socket permission: %v", err)
		}
		// socketのオーナーを変更
		if err := os.Chown(conf.MilterListen.Address, conf.MilterListen.Uid, conf.MilterListen.Gid); err != nil {
			log.Fatalf("Failed to change socket owner: %v", err)
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
	// scoketが存在していたら削除
	if err := os.Remove(conf.ControlSocketFile.Path); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove socket: %v", err)
	}
	csocket, err := net.Listen("unix", conf.ControlSocketFile.Path)
	if err != nil {
		log.Fatalf("Failed to listen socket: %v", err)
	}
	defer csocket.Close()
	// socketのパーミッションを変更
	if err := os.Chmod(conf.ControlSocketFile.Path, fs.FileMode(conf.ControlSocketFile.Mode)); err != nil {
		log.Fatalf("Failed to change socket permission: %v", err)
	}

	// control rpcサーバーを起動
	go func() {
		ctrl := control.New(func(pid int) {
			log.Printf("child process ready pid=%d", pid)
			for i, c := range childlen {
				if c.Process.Pid == pid {
					childlen[i].Ready = true
					break
				}
			}
		})
		if err := ctrl.Serve(csocket); err != nil {
			log.Fatalf("Failed to serve control socket: %v", err)
		}
	}()

	// 子プロセスの実行
	go execChildProcess(conf.LogFd, msockfd)

	checkSignal()
}
