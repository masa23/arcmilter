package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// go-milter's wire reader permits 512 MiB packets and grows its buffer as a
// peer sends data. Postfix normally uses packets no larger than 1 MiB. Bound
// each frame before the library reads its length, including a little room for
// protocol fields, so a compromised Milter peer cannot exhaust memory with a
// single packet.
const maxMilterPacketBytes = 2 << 20

var errMilterPacketTooLarge = errors.New("Milter packet exceeds 2 MiB limit")
var errMilterPacketEmpty = errors.New("Milter packet length is zero")

type milterPacketLimitedConn struct {
	net.Conn
	header          [4]byte
	headerBytesSent int
	remaining       uint32
	readingHeader   bool
}

func limitMilterPackets(conn net.Conn) net.Conn {
	return &milterPacketLimitedConn{Conn: conn, readingHeader: true}
}

func (c *milterPacketLimitedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.readingHeader {
		if c.headerBytesSent == 0 {
			if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
				return 0, err
			}
			c.remaining = binary.BigEndian.Uint32(c.header[:])
			if c.remaining == 0 {
				_ = c.Conn.Close()
				return 0, errMilterPacketEmpty
			}
			if c.remaining > maxMilterPacketBytes {
				_ = c.Conn.Close()
				return 0, errMilterPacketTooLarge
			}
		}
		n := copy(p, c.header[c.headerBytesSent:])
		c.headerBytesSent += n
		if c.headerBytesSent == len(c.header) {
			c.headerBytesSent = 0
			c.readingHeader = false
		}
		return n, nil
	}
	length := min(len(p), int(c.remaining))
	n, err := c.Conn.Read(p[:length])
	c.remaining -= uint32(n)
	if c.remaining == 0 {
		c.readingHeader = true
	}
	return n, err
}
