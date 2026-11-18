package main

import (
	"os"
	"sync"
	"sync/atomic"
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

func TestChildReadinessIsSpecificToReplacement(t *testing.T) {
	isolateChildren(t)
	old, replacement := &os.Process{Pid: 101}, &os.Process{Pid: 102}
	addChild(old)
	addChild(replacement)
	// The old child's delayed notification arrives while its replacement is
	// still initializing. It must not satisfy the replacement's readiness.
	markChildReady(old.Pid)
	if !hasReadyChild() || !isChildReady(old.Pid) || isChildReady(replacement.Pid) || isChildReady(999) {
		t.Fatal("old or unknown child satisfied replacement readiness")
	}
	markChildReady(replacement.Pid)
	if !isChildReady(replacement.Pid) {
		t.Fatal("replacement's own readiness was not observed")
	}
}

func TestReloadIncludesAutomaticallyReplenishedChild(t *testing.T) {
	isolateChildren(t)
	old, automatic, replacement := &os.Process{Pid: 101}, &os.Process{Pid: 102}, &os.Process{Pid: 103}
	addChild(old)
	// The old child exits and is automatically replenished before the explicit
	// reload child is registered. The automatic child is also a handoff target.
	removeChild(old)
	addChild(automatic)
	addChild(replacement)
	markChildReady(automatic.Pid)
	markChildReady(replacement.Pid)
	others := childrenOtherThan(replacement.Pid)
	if len(others) != 1 || others[0].Process != automatic {
		t.Fatalf("reload did not target the automatic replacement: %v", others)
	}
}

func isolateChildSupervisor(t *testing.T) {
	t.Helper()
	isolateChildren(t)
	parentLogMu.Lock()
	oldStopping := parentStopping
	parentStopping = false
	parentLogMu.Unlock()
	t.Cleanup(func() {
		parentLogMu.Lock()
		parentStopping = oldStopping
		parentLogMu.Unlock()
	})
}

func TestChildSupervisorReplenishesOnlyOnceAfterConcurrentExits(t *testing.T) {
	isolateChildSupervisor(t)
	a, b := &os.Process{Pid: 101}, &os.Process{Pid: 102}
	addChild(a)
	addChild(b)
	var starts atomic.Int64
	start := func() *os.Process {
		starts.Add(1)
		return &os.Process{Pid: 103}
	}
	var wait sync.WaitGroup
	for _, exited := range []*os.Process{a, b} {
		wait.Add(1)
		go func(p *os.Process) {
			defer wait.Done()
			removeChild(p)
			startChildIfAllowed(true, start)
		}(exited)
	}
	wait.Wait()
	if starts.Load() != 1 || childCount() != 1 {
		t.Fatalf("concurrent exits produced %d replacements and %d live children", starts.Load(), childCount())
	}
	if p := startChildIfAllowed(true, start); p != nil || starts.Load() != 1 {
		t.Fatal("supervisor spawned a second replacement")
	}
	if p := startChildIfAllowed(false, start); p == nil || starts.Load() != 2 {
		t.Fatal("explicit reload could not spawn alongside the running child")
	}
}

func TestChildSupervisorDoesNotSpawnDuringShutdown(t *testing.T) {
	isolateChildSupervisor(t)
	parentLogMu.Lock()
	parentStopping = true
	parentLogMu.Unlock()
	for _, onlyIfEmpty := range []bool{false, true} {
		if p := startChildIfAllowed(onlyIfEmpty, func() *os.Process {
			t.Fatal("shutdown started a replacement child")
			return &os.Process{Pid: 101}
		}); p != nil {
			t.Fatal("shutdown returned a replacement child")
		}
	}
}
