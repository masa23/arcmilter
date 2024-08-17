package control

import (
	"log"
	"net"
	"net/rpc"
)

// Control はRPCのレシーバとして動作し、子プロセスが準備完了したことを通知するための機能を提供します
type Control struct {
	childReady func(pid int)
}

func New(childReady func(pid int)) *Control {
	return &Control{
		childReady: childReady,
	}
}

func (c *Control) Serve(l net.Listener) error {
	if err := rpc.Register(c); err != nil {
		log.Fatalf("failed to register control: %v", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("failed to accept control socket: %v", err)
		}
		go rpc.ServeConn(conn)
	}
}

// ChildReadyArgs は子プロセスが準備完了したことを通知するための引数を表します
type ChildReadyArgs struct {
	Pid int
}

// ChildReady は子プロセスが準備完了したことを通知するためのメソッドです
// 事前に指定したhook関数を実行します
func (c *Control) ChildReady(args ChildReadyArgs, reply *struct{}) error {
	c.childReady(args.Pid)
	return nil
}
