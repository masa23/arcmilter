package canonical

import (
	"io"
	"strings"
)

const crlf = "\r\n"

// シンプルとリラックスの2つの正規化アルゴリズムを定義します。
type Canonicalization string

const (
	Simple  Canonicalization = "simple"
	Relaxed Canonicalization = "relaxed"
)

// ヘッダのシンプル正規化を行う関数です。
func SimpleHeader(s string) string {
	return s
}

// ヘッダのリラックス正規化を行う関数です。
func RelaxedHeader(s string) string {
	k, v, ok := strings.Cut(s, ":")
	if !ok {
		return strings.TrimSpace(strings.ToLower(s)) + ":" + crlf
	}

	k = strings.TrimSpace(strings.ToLower(k))
	v = strings.Join(strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}), " ")
	return k + ":" + v + crlf
}

type crlfFixer struct {
	cr bool
}

func (cf *crlfFixer) Fix(b []byte) []byte {
	res := make([]byte, 0, len(b))
	for _, ch := range b {
		prevCR := cf.cr
		cf.cr = false
		switch ch {
		case '\r':
			cf.cr = true
		case '\n':
			if !prevCR {
				res = append(res, '\r')
			}
		}
		res = append(res, ch)
	}
	return res
}

// ヘッダの正規化を行う関数です。
func Header(s string, canonical Canonicalization) string {
	switch canonical {
	case Simple:
		return SimpleHeader(s)
	case Relaxed:
		return RelaxedHeader(s)
	default:
		return SimpleHeader(s)
	}
}

type simpleBodyCanonicalizer struct {
	w         io.Writer
	crlfBuf   []byte
	crlfFixer crlfFixer
}

func (c *simpleBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)
	b = append(c.crlfBuf, b...)

	b = c.crlfFixer.Fix(b)

	end := len(b)
	// If it ends with \r, maybe the next write will begin with \n
	if end > 0 && b[end-1] == '\r' {
		end--
	}
	// Keep all \r\n sequences
	for end >= 2 {
		prev := b[end-2]
		cur := b[end-1]
		if prev != '\r' || cur != '\n' {
			break
		}
		end -= 2
	}

	c.crlfBuf = b[end:]

	var err error
	if end > 0 {
		_, err = c.w.Write(b[:end])
	}
	return written, err
}

func (c *simpleBodyCanonicalizer) Close() error {
	// Flush crlfBuf if it ends with a single \r (without a matching \n)
	if len(c.crlfBuf) > 0 && c.crlfBuf[len(c.crlfBuf)-1] == '\r' {
		if _, err := c.w.Write(c.crlfBuf); err != nil {
			return err
		}
	}
	c.crlfBuf = nil

	if _, err := c.w.Write([]byte(crlf)); err != nil {
		return err
	}
	return nil
}

// ボディをシンプル正規化する関数です。
func SimpleBody(w io.Writer) io.WriteCloser {
	return &simpleBodyCanonicalizer{w: w}
}

type relaxedBodyCanonicalizer struct {
	w         io.Writer
	crlfBuf   []byte
	wsp       bool
	written   bool
	crlfFixer crlfFixer
}

func (c *relaxedBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)

	b = c.crlfFixer.Fix(b)

	canonical := make([]byte, 0, len(b))
	for _, ch := range b {
		if ch == ' ' || ch == '\t' {
			c.wsp = true
		} else if ch == '\r' || ch == '\n' {
			c.wsp = false
			c.crlfBuf = append(c.crlfBuf, ch)
		} else {
			if len(c.crlfBuf) > 0 {
				canonical = append(canonical, c.crlfBuf...)
				c.crlfBuf = c.crlfBuf[:0]
			}
			if c.wsp {
				canonical = append(canonical, ' ')
				c.wsp = false
			}

			canonical = append(canonical, ch)
		}
	}

	if !c.written && len(canonical) > 0 {
		c.written = true
	}

	_, err := c.w.Write(canonical)
	return written, err
}

func (c *relaxedBodyCanonicalizer) Close() error {
	if c.written {
		if _, err := c.w.Write([]byte(crlf)); err != nil {
			return err
		}
	}
	return nil
}

// ボディをリラックス正規化する関数です。
func RelaxedBody(w io.Writer) io.WriteCloser {
	return &relaxedBodyCanonicalizer{w: w}
}

// ボディの正規化を行う関数です。
func Body(w io.Writer, canonical Canonicalization) io.WriteCloser {
	switch canonical {
	case Simple:
		return SimpleBody(w)
	case Relaxed:
		return RelaxedBody(w)
	default:
		return SimpleBody(w)
	}
}
