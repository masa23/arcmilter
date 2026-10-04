package main

import (
	"os"
	"sync"
	"testing"
)

func isolateChildren(t *testing.T) {
	t.Helper()
	childMu.Lock()
	old := childlen
	childlen = nil
	childMu.Unlock()
	t.Cleanup(func() { childMu.Lock(); childlen = old; childMu.Unlock() })
}

func TestChildReadinessAndRecovery(t *testing.T) {
	isolateChildren(t)
	a, b, replacement := &os.Process{Pid: 101}, &os.Process{Pid: 102}, &os.Process{Pid: 103}
	if childCount() != 0 || hasReadyChild() {
		t.Fatal("empty child list is ready")
	}
	addChild(a)
	addChild(b)
	markChildReady(999)
	if hasReadyChild() {
		t.Fatal("unknown PID marked a child ready")
	}
	markChildReady(a.Pid)
	if childCount() != 2 || !hasReadyChild() {
		t.Fatal("ready child was not found")
	}
	before := childrenSnapshot()
	before[0].Ready = false
	if !hasReadyChild() {
		t.Fatal("snapshot mutation changed live children")
	}
	before = childrenSnapshot()
	setChildrenReady(false)
	addChild(replacement)
	removeChild(b)
	if hasReadyChild() {
		t.Fatal("children remained ready after reset")
	}
	restoreChildrenReady(before)
	after := childrenSnapshot()
	if len(after) != 2 || !after[0].Ready || after[1].Ready {
		t.Fatalf("readiness recovery changed replacement child: %v", after)
	}
	removeChild(a)
	removeChild(a)
	if childCount() != 1 || hasReadyChild() {
		t.Fatal("child removal retained readiness")
	}
	markChildReady(replacement.Pid)
	if !hasReadyChild() {
		t.Fatal("replacement child did not become ready")
	}
}

func TestConcurrentChildUpdates(t *testing.T) {
	isolateChildren(t)
	var wg sync.WaitGroup
	for pid := 1; pid <= 32; pid++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			p := &os.Process{Pid: pid}
			addChild(p)
			markChildReady(pid)
			_ = childrenSnapshot()
			_ = childCount()
			_ = hasReadyChild()
			removeChild(p)
		}(pid)
	}
	wg.Wait()
	if childCount() != 0 {
		t.Fatal("concurrent removals retained children")
	}
}
