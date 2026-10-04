package control

import "testing"

func TestChildReadyNotifiesPID(t *testing.T) {
	var got []int
	c := New(func(pid int) { got = append(got, pid) })
	for _, pid := range []int{123, 456} {
		if err := c.ChildReady(ChildReadyArgs{Pid: pid}, &struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 2 || got[0] != 123 || got[1] != 456 {
		t.Fatalf("unexpected ready notifications: %v", got)
	}
}
