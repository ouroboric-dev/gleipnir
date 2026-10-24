// Package submit is what both agent adapters share of the typed output channel (change typed-boundaries, design
// section 3): the one MCP server a session may start, how a stream's tool results say a submit was accepted, and how
// the document of the last accepted submit is read. The server itself is ygg-submit, in the work image.
package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/ouroboric-dev/gleipnir/bounded"
	"github.com/ouroboric-dev/gungnir"
)

const (
	// Server is the name of the one MCP server a session may use, and Command is the program the managed settings
	// allow it to run, with no arguments: the contract goes in the environment.
	Server  = "ygg"
	Command = "/opt/ygg/bin/ygg-submit"
	// ContractVar is the variable that tells the server which contract to check.
	ContractVar = "YGG_OUTPUT_CONTRACT"
	// MaxFile is the most bytes of a draft file that ygg-submit accepts and the adapter reads.
	MaxFile = 4 << 20
)

// accepted is what ygg-submit answers for a valid output (sandbox/assets/ygg-submit.mjs, verdict).
func accepted(contract string) string { return "accepted: the document is a valid " + contract }

// Tracker follows the submit calls of one session's stream and keeps the input of the last accepted one. A call is
// accepted when its tool result is not an error and its text is exactly ygg-submit's acceptance of the session's
// contract; anything else, the errors to fix included, is a refusal.
type Tracker struct {
	want    string
	pending map[string]json.RawMessage
	last    json.RawMessage
}

// NewTracker returns a tracker for a session that returns contract.
func NewTracker(contract string) *Tracker {
	return &Tracker{want: accepted(contract), pending: map[string]json.RawMessage{}}
}

// Call notes a call of the submit tool and its input, as the stream printed it.
func (t *Tracker) Call(id string, input json.RawMessage) { t.pending[id] = input }

// Result notes the tool result of the call with this id. A result of no known call changes nothing.
func (t *Tracker) Result(id, text string, isError bool) {
	input, ok := t.pending[id]
	if !ok {
		return
	}
	delete(t.pending, id)
	if !isError && strings.TrimSpace(text) == t.want {
		t.last = input
	}
}

// Last is the input of the last accepted call, or nil when no call was accepted.
func (t *Tracker) Last() json.RawMessage { return t.last }

// Document is the output document of an accepted submit whose input was input: the value of its "output", byte for
// byte as the stream printed it, or the bytes of the draft file it named, read through r. A file is read under the
// rules ygg-submit applies (relative, under out/, no .. segment, no NUL) and at most MaxFile bytes of it.
func Document(ctx context.Context, r gungnir.Runner, input json.RawMessage) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("the accepted submit's input is not an object: %w", err)
	}
	out, hasOut := in["output"]
	file, hasFile := in["file"]
	switch {
	case hasOut == hasFile || len(in) != 1:
		return nil, errors.New("the accepted submit's input does not hold exactly one of output and file")
	case hasOut:
		if doc := bytes.TrimSpace(out); len(doc) == 0 || doc[0] != '{' {
			return nil, errors.New("the accepted submit's output is not an object")
		}
		return out, nil
	}
	var name string
	if err := json.Unmarshal(file, &name); err != nil {
		return nil, fmt.Errorf("the accepted submit's file is not a string: %w", err)
	}
	p, err := Path(name)
	if err != nil {
		return nil, err
	}
	return read(ctx, r, p)
}

// Path cleans the draft path of a submit the way ygg-submit does and refuses what it refuses.
func Path(file string) (string, error) {
	switch {
	case file == "":
		return "", errors.New("the draft path is empty")
	case strings.ContainsRune(file, 0) || strings.HasPrefix(file, "/"):
		return "", fmt.Errorf("the draft %q is not relative to the working directory", file)
	case strings.HasSuffix(file, "/"):
		return "", fmt.Errorf("the draft %q names no file", file)
	}
	var segs []string
	for _, s := range strings.Split(file, "/") {
		if s == ".." {
			return "", fmt.Errorf("the draft %q holds a .. segment", file)
		}
		if s != "" && s != "." {
			segs = append(segs, s)
		}
	}
	if len(segs) < 2 || segs[0] != "out" {
		return "", fmt.Errorf("the draft %q is not a file under out/", file)
	}
	return path.Join(segs...), nil
}

// guardedRead is the script of the read: the path (its $1) must resolve to a regular file under out/ of the working
// directory, so a symlink out of out/ is not followed and a FIFO or a device is not opened. The read itself is bounded
// at one byte more than the limit, to tell a file at the limit from one over it.
var guardedRead = `r=$(realpath -e -- "$1") && b=$(realpath .) && case "$r" in "$b"/out/*) ;; *) exit 3;; esac && ` +
	`test -f "$r" && exec head -c ` + strconv.Itoa(MaxFile+1) + ` -- "$r"`

// read runs the guarded, bounded read of the file in the session's sandbox.
func read(ctx context.Context, r gungnir.Runner, p string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("the submitted draft %s can't be read: the session has no sandbox", p)
	}
	buf := bounded.NewBuffer(MaxFile + 1)
	res, err := r.Run(ctx, gungnir.Cmd{Argv: []string{"sh", "-c", guardedRead, "sh", p}, Stdout: buf})
	switch {
	case err != nil:
		return nil, fmt.Errorf("the submitted draft %s can't be read: %w", p, err)
	case res.ExitCode != 0:
		return nil, fmt.Errorf("the submitted draft %s can't be read: head exited %d", p, res.ExitCode)
	case len(buf.Bytes()) > MaxFile:
		return nil, fmt.Errorf("the submitted draft %s is over the limit of %d bytes", p, MaxFile)
	case len(buf.Bytes()) == 0:
		return nil, fmt.Errorf("the submitted draft %s is empty", p)
	}
	return buf.Bytes(), nil
}
