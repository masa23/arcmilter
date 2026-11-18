package control

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"syscall"
)

// Control serves child readiness notifications on a private Unix socket.
type Control struct {
	childReady func(pid int)
}

const maxControlConnections = 16

func New(childReady func(pid int)) *Control {
	return &Control{
		childReady: childReady,
	}
}

func (c *Control) Serve(l net.Listener) error {
	slots := make(chan struct{}, maxControlConnections)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		peer, err := controlPeerCredentials(conn)
		if err != nil || peer == nil || peer.Uid != uint32(os.Geteuid()) || peer.Pid <= 0 {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		server := rpc.NewServer()
		if err := server.RegisterName("Control", &peerControl{childReady: c.childReady, pid: int(peer.Pid)}); err != nil {
			<-slots
			_ = conn.Close()
			return fmt.Errorf("register control RPC: %w", err)
		}
		go func() {
			defer func() { <-slots }()
			server.ServeConn(conn)
		}()
	}
}

func controlPeerCredentials(conn net.Conn) (*syscall.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("control connection is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		peer, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if socketErr != nil {
		return nil, socketErr
	}
	return peer, nil
}

// ChildReadyArgs は子プロセスが準備完了したことを通知するための引数を表します
type ChildReadyArgs struct {
	Pid int
}

type peerControl struct {
	childReady func(pid int)
	pid        int
}

// ChildReady accepts only the PID supplied by the Unix kernel for this RPC
// connection. A process with access to the socket cannot claim that a
// replacement child has finished starting.
func (c *peerControl) ChildReady(args ChildReadyArgs, reply *struct{}) error {
	if args.Pid != c.pid {
		return fmt.Errorf("control ready PID %d does not match peer PID", args.Pid)
	}
	c.childReady(c.pid)
	return nil
}
