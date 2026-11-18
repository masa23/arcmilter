package control

import (
	"errors"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"
)

func TestControlServeBindsReadyToUnixPeerPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ready := make(chan int, 2)
	done := make(chan error, 1)
	go func() {
		done <- New(func(pid int) { ready <- pid }).Serve(listener)
	}()

	client, err := rpc.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var reply struct{}
	if err := client.Call("Control.ChildReady", ChildReadyArgs{Pid: os.Getpid() + 1}, &reply); err == nil {
		t.Fatal("ready notification accepted a forged PID")
	}
	select {
	case pid := <-ready:
		t.Fatalf("forged ready notification invoked callback for PID %d", pid)
	default:
	}
	if err := client.Call("Control.ChildReady", ChildReadyArgs{Pid: os.Getpid()}, &reply); err != nil {
		t.Fatal(err)
	}
	select {
	case pid := <-ready:
		if pid != os.Getpid() {
			t.Fatalf("callback PID = %d, want %d", pid, os.Getpid())
		}
	default:
		t.Fatal("valid ready notification did not invoke callback")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after listener close = %v, want net.ErrClosed", err)
	}
}

func TestControlServeBoundsLiveConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = New(func(int) {}).Serve(listener) }()

	var clients []*rpc.Client
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	for range maxControlConnections {
		client, err := rpc.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		if err := client.Call("Control.ChildReady", ChildReadyArgs{Pid: os.Getpid()}, &struct{}{}); err != nil {
			t.Fatalf("valid connection rejected: %v", err)
		}
	}
	client, err := rpc.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Call("Control.ChildReady", ChildReadyArgs{Pid: os.Getpid()}, &struct{}{}); err == nil {
		t.Fatal("accepted connection above control limit")
	}
}
