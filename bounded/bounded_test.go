package bounded

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestABufferKeepsTheFirstBytesAndSaysItDroppedTheRest(t *testing.T) {
	b := NewBuffer(5)
	for _, s := range []string{"ab", "cdefg", "hi"} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v; a bounded writer never fails and never reports a short write", s, n, err)
		}
	}
	if string(b.Bytes()) != "abcde" || !b.Truncated() {
		t.Errorf("kept %q, truncated %v; want abcde, true", b.Bytes(), b.Truncated())
	}
	exact := NewBuffer(3)
	exact.Write([]byte("abc"))
	if string(exact.Bytes()) != "abc" || exact.Truncated() {
		t.Errorf("a write that exactly fits: kept %q, truncated %v", exact.Bytes(), exact.Truncated())
	}
}

func TestAWriterPassesOnTheFirstBytesOnly(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, 4)
	w.Write([]byte("ab"))
	w.Write([]byte("cdef"))
	w.Write([]byte("g"))
	if out.String() != "abcd" || !w.Truncated() || w.Err() != nil {
		t.Errorf("passed on %q, truncated %v, err %v", out.String(), w.Truncated(), w.Err())
	}
}

type failing struct{ calls int }

func (f *failing) Write([]byte) (int, error) { f.calls++; return 0, errors.New("disk full") }

func TestAWriterKeepsTheErrorOfItsDestinationAndGoesOn(t *testing.T) {
	f := &failing{}
	w := NewWriter(f, 100)
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Errorf("Write() = %d, %v; the session must not stop for a full disk", n, err)
	}
	w.Write([]byte("def"))
	if w.Err() == nil || f.calls != 1 {
		t.Errorf("err %v after %d calls; want the first error kept and no more writes", w.Err(), f.calls)
	}
}

func TestALineWriterHandsOverWholeLinesWhateverTheChunks(t *testing.T) {
	var got []string
	w := NewLineWriter(func(l []byte) { got = append(got, string(l)) }, 8)
	for _, s := range []string{"ab", "c\nde", "f\n\ng", "h\ntoolonglineindeed\nok\nhalf"} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v; a bounded writer never fails and never reports a short write", s, n, err)
		}
	}
	// A line over the limit is dropped, and the one after it still arrives; an unfinished last line never does.
	want := []string{"abc", "def", "", "gh", "ok"}
	if !slices.Equal(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}
