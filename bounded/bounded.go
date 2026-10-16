// Package bounded holds the writers that keep a session's output from filling the host's memory or
// disk (backlog B-021). A writer never fails and never blocks: it keeps what fits and drops the rest,
// so the tool writing to it goes on to its end, and the adapter then fails the session as too chatty.
package bounded

import (
	"bytes"
	"io"
)

// Buffer keeps the first Limit bytes written to it.
type Buffer struct {
	limit   int
	buf     bytes.Buffer
	dropped bool
}

// NewBuffer returns a Buffer that keeps at most limit bytes.
func NewBuffer(limit int) *Buffer { return &Buffer{limit: limit} }

func (b *Buffer) Write(p []byte) (int, error) {
	n := len(p)
	room := b.limit - b.buf.Len()
	if room < len(p) {
		b.dropped = true
		p = p[:max(room, 0)]
	}
	b.buf.Write(p)
	return n, nil
}

// Bytes returns what was kept.
func (b *Buffer) Bytes() []byte { return b.buf.Bytes() }

// Truncated reports whether bytes were dropped.
func (b *Buffer) Truncated() bool { return b.dropped }

// Writer passes the first limit bytes written to it on to w, and drops the rest.
type Writer struct {
	w       io.Writer
	left    int64
	dropped bool
	err     error
}

// NewWriter returns a Writer that passes on at most limit bytes to w. An error from w is kept
// (see Err), and later writes are dropped, so a full disk never stops the session itself.
func NewWriter(w io.Writer, limit int64) *Writer { return &Writer{w: w, left: limit} }

func (b *Writer) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > b.left {
		b.dropped = true
		p = p[:max(b.left, 0)]
	}
	if len(p) > 0 && b.err == nil {
		if _, err := b.w.Write(p); err != nil {
			b.err = err
		}
	}
	b.left -= int64(len(p))
	return n, nil
}

// Truncated reports whether bytes were dropped.
func (b *Writer) Truncated() bool { return b.dropped }

// Err returns the first error w gave.
func (b *Writer) Err() error { return b.err }
