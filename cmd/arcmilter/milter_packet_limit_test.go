package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

func milterTestFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func TestMilterPacketLimitPreservesFrames(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	limited := limitMilterPackets(server)
	first := milterTestFrame([]byte("HFrom\x00sender@example.test\x00"))
	second := milterTestFrame([]byte("E"))
	go func() {
		_, _ = peer.Write(append(first, second...))
	}()
	for _, frame := range [][]byte{first, second} {
		got := make([]byte, len(frame))
		// Exercise a fragmented length header, then the remaining frame.
		if _, err := io.ReadFull(limited, got[:1]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(limited, got[1:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("frame changed: got %q, want %q", got, frame)
		}
	}
}

func TestMilterPacketLimitRejectsOversizedFrameBeforeBody(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	limited := limitMilterPackets(server)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], maxMilterPacketBytes+1)
	go func() { _, _ = peer.Write(length[:]) }()
	if _, err := limited.Read(make([]byte, 4)); !errors.Is(err, errMilterPacketTooLarge) {
		t.Fatalf("oversized packet error = %v", err)
	}
}

func TestMilterPacketLimitRejectsEmptyFrame(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	limited := limitMilterPackets(server)
	go func() { _, _ = peer.Write([]byte{0, 0, 0, 0}) }()
	if _, err := limited.Read(make([]byte, 4)); !errors.Is(err, errMilterPacketEmpty) {
		t.Fatalf("empty packet error = %v", err)
	}
}
