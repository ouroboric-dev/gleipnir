package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The tests of the model gate (local-models spec §3.5, §6): the only path from a sandbox to llama-server. Each test
// builds the embedded source, as the server image does, and runs it against an httptest upstream that stands in for
// llama-server.

const gateLimit = 32 << 20 // spec §3.5: a body is at most 32 MiB

// buildGate writes the embedded source of the gate into a folder outside any module and builds it there, as the
// image's builder stage does, so the test runs the bytes the image carries.
func buildGate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(modelGateSource), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ygg-modelgate")
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build of the gate: %v\n%s", err, out)
	}
	return bin
}

// startGate starts the gate in front of upstream with the allow file allow, and returns its base URL. The gate
// listens on a port the system picks and says which on its standard error.
func startGate(t *testing.T, upstream, allow string) string {
	t.Helper()
	bin := buildGate(t)
	cmd := exec.Command(bin, "-listen", "127.0.0.1:0", "-upstream", upstream, "-allow", allow)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	addr, done := make(chan string, 1), make(chan struct{})
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done; _ = cmd.Wait() })
	go func() {
		defer close(done)
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			line := s.Text()
			t.Log("gate: " + line)
			if _, rest, ok := strings.Cut(line, "listening on "); ok {
				a, _, _ := strings.Cut(rest, ",")
				select {
				case addr <- a:
				default:
				}
			}
		}
	}()
	select {
	case a := <-addr:
		return "http://" + a
	case <-done:
		t.Fatal("the gate exited before it said where it listens")
	case <-time.After(10 * time.Second):
		t.Fatal("the gate did not say where it listens")
	}
	return ""
}

// writeAllow writes the allow file as Odin does: the model's name and a newline.
func writeAllow(t *testing.T, path, model string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(model+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// seen is what the upstream received.
type seen struct {
	method, uri, contentType string
	body                     []byte
}

// recordingUpstream answers every request with a fixed chat reply and records the last one.
func recordingUpstream(t *testing.T) (*httptest.Server, *atomic.Pointer[seen], *atomic.Int32) {
	t.Helper()
	var last atomic.Pointer[seen]
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		last.Store(&seen{method: r.Method, uri: r.RequestURI, contentType: r.Header.Get("Content-Type"), body: b})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "llama")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	t.Cleanup(up.Close)
	return up, &last, &hits
}

func chat(t *testing.T, base, model string) *http.Response {
	t.Helper()
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"`+model+`","messages":[{"role":"user","content":"Say OK."}]}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestModelGatePassesTheAllowedModel(t *testing.T) {
	up, last, _ := recordingUpstream(t)
	allow := filepath.Join(t.TempDir(), "allowed")
	writeAllow(t, allow, "qwen-a")
	base := startGate(t, up.URL, allow)

	body := `{"model":"qwen-a","messages":[{"role":"user","content":"Say OK."}],"stream":false}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != `{"choices":[{"message":{"content":"OK"}}]}` || resp.Header.Get("X-Upstream") != "llama" {
		t.Errorf("the gate answered %d %q (X-Upstream %q); want the upstream's 200 reply", resp.StatusCode, got, resp.Header.Get("X-Upstream"))
	}
	s := last.Load()
	if s == nil {
		t.Fatal("the upstream never saw the request")
	}
	if s.method != http.MethodPost || s.uri != "/v1/chat/completions" || s.contentType != "application/json" || string(s.body) != body {
		t.Errorf("the upstream saw %s %s (%s) %q; want the request as the client sent it", s.method, s.uri, s.contentType, s.body)
	}

	// A body of exactly 32 MiB is still at most 32 MiB.
	pad := gateLimit - len(`{"model":"qwen-a","pad":""}`)
	full := `{"model":"qwen-a","pad":"` + strings.Repeat("a", pad) + `"}`
	resp2, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(full))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || len(last.Load().body) != gateLimit {
		t.Errorf("a body of exactly 32 MiB: %d, the upstream got %d bytes; want 200 and all of it", resp2.StatusCode, len(last.Load().body))
	}
}

func TestModelGateStreams(t *testing.T) {
	released := make(chan struct{})
	var secondWritten atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-released:
		case <-time.After(5 * time.Second): // a gate that holds the first chunk back never lets the client release us
		}
		secondWritten.Store(true)
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	t.Cleanup(up.Close)
	allow := filepath.Join(t.TempDir(), "allowed")
	writeAllow(t, allow, "qwen-a")
	base := startGate(t, up.URL, allow)

	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"qwen-a","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	first, err := r.ReadString('\n')
	if err != nil || first != "data: one\n" {
		t.Fatalf("the first chunk: %q, %v", first, err)
	}
	if secondWritten.Load() {
		t.Error("the client read the first chunk only after the upstream wrote the second: the gate does not stream")
	}
	close(released)
	rest, _ := io.ReadAll(r)
	if string(rest) != "\ndata: two\n\n" {
		t.Errorf("the rest of the stream: %q", rest)
	}
}

func TestModelGateRefuses(t *testing.T) {
	const ok = `{"model":"qwen-a","messages":[]}`
	over := `{"model":"qwen-a","pad":"` + strings.Repeat("a", gateLimit) + `"}`
	for _, c := range []struct {
		name, method, url, body string
		allow                   *string // the allow file's content; nil: no file
		chunked                 bool    // send the body with no Content-Length
		header                  map[string]string
		raw                     bool // write the request line as given, over a bare connection: an absolute-form target
		want                    int
	}{
		{name: "another model", method: "POST", url: "/v1/chat/completions", body: `{"model":"qwen-b","messages":[]}`, want: 403},
		{name: "the model with a space", method: "POST", url: "/v1/chat/completions", body: `{"model":" qwen-a","messages":[]}`, want: 403},
		{name: "a load", method: "POST", url: "/models/load", body: `{"model":"qwen-a"}`, want: 403},
		{name: "an unload", method: "POST", url: "/models/unload", body: `{"model":"qwen-a"}`, want: 403},
		{name: "the slots", method: "GET", url: "/slots", want: 403},
		{name: "the metrics", method: "GET", url: "/metrics", want: 403},
		{name: "the props", method: "GET", url: "/props", want: 403},
		{name: "the model list", method: "GET", url: "/models", want: 403},
		{name: "a GET of the chat path", method: "GET", url: "/v1/chat/completions", want: 403},
		{name: "a PUT of the chat path", method: "PUT", url: "/v1/chat/completions", body: ok, want: 403},
		{name: "a query", method: "POST", url: "/v1/chat/completions?autoload=false", body: ok, want: 403},
		{name: "an empty query", method: "POST", url: "/v1/chat/completions?", body: ok, want: 403},
		{name: "a trailing slash", method: "POST", url: "/v1/chat/completions/", body: ok, want: 403},
		{name: "an escaped slash", method: "POST", url: "/v1/chat%2Fcompletions", body: ok, want: 403},
		{name: "a double slash", method: "POST", url: "/v1//chat/completions", body: ok, want: 403},
		{name: "a dot segment", method: "POST", url: "/v1/x/../chat/completions", body: ok, want: 403},
		{name: "above 32 MiB", method: "POST", url: "/v1/chat/completions", body: over, want: 413},
		{name: "above 32 MiB, chunked", method: "POST", url: "/v1/chat/completions", body: over, chunked: true, want: 413},
		{name: "not JSON", method: "POST", url: "/v1/chat/completions", body: `model=qwen-a`, want: 400},
		{name: "cut JSON", method: "POST", url: "/v1/chat/completions", body: `{"model":"qwen-a"`, want: 400},
		{name: "JSON and more", method: "POST", url: "/v1/chat/completions", body: ok + ` {}`, want: 400},
		{name: "an array", method: "POST", url: "/v1/chat/completions", body: `["qwen-a"]`, want: 400},
		{name: "no model", method: "POST", url: "/v1/chat/completions", body: `{"messages":[]}`, want: 400},
		{name: "a model that is not a string", method: "POST", url: "/v1/chat/completions", body: `{"model":["qwen-a"]}`, want: 400},
		{name: "two models", method: "POST", url: "/v1/chat/completions", body: `{"model":"qwen-a","model":"qwen-b"}`, want: 400},
		{name: "not UTF-8", method: "POST", url: "/v1/chat/completions", body: "{\"model\":\"qwen-a\",\"x\":\"\xff\"}", want: 400},
		{name: "an upgrade", method: "POST", url: "/v1/chat/completions", body: ok, header: map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, want: 403},
		{name: "an Upgrade header alone", method: "POST", url: "/v1/chat/completions", body: ok, header: map[string]string{"Upgrade": "h2c"}, want: 403},
		{name: "a Connection naming upgrade", method: "POST", url: "/v1/chat/completions", body: ok, header: map[string]string{"Connection": "keep-alive, upgrade"}, want: 403},
		{name: "a gzip body", method: "POST", url: "/v1/chat/completions", body: ok, header: map[string]string{"Content-Encoding": "gzip"}, want: 403},
		{name: "identity then gzip", method: "POST", url: "/v1/chat/completions", body: ok, header: map[string]string{"Content-Encoding": "identity, gzip"}, want: 403},
		{name: "an absolute-form target", method: "POST", url: "http://x/v1/chat/completions", body: ok, raw: true, want: 403},
		{name: "a lowercase post", method: "post", url: "/v1/chat/completions", body: ok, raw: true, want: 403},
		{name: "an escaped second model", method: "POST", url: "/v1/chat/completions", body: `{"model":"qwen-a","mod\u0065l":"qwen-b"}`, want: 400},
		{name: "a second model, the plain form", method: "POST", url: "/v1/chat/completions", body: `{"model":"m","model":"other"}`, want: 400},
		{name: "no allow file", method: "POST", url: "/v1/chat/completions", body: ok, allow: nil, want: 503},
		{name: "an empty allow file", method: "POST", url: "/v1/chat/completions", body: `{"model":""}`, allow: ptr(" \n"), want: 503},
	} {
		t.Run(c.name, func(t *testing.T) {
			up, _, hits := recordingUpstream(t)
			allow := filepath.Join(t.TempDir(), "allowed")
			switch {
			case c.allow != nil:
				if err := os.WriteFile(allow, []byte(*c.allow), 0o644); err != nil {
					t.Fatal(err)
				}
			case c.want != 503:
				writeAllow(t, allow, "qwen-a")
			}
			base := startGate(t, up.URL, allow)
			if c.raw {
				if got := rawRequest(t, base, c.method, c.url, c.body); got != c.want {
					t.Errorf("%s %s: %d; want %d", c.method, c.url, got, c.want)
				}
				if n := hits.Load(); n != 0 {
					t.Errorf("the upstream saw %d requests; a refused request must never reach it", n)
				}
				return
			}
			u, err := url.Parse(base + c.url)
			if err != nil {
				t.Fatal(err)
			}
			var body io.Reader = http.NoBody
			if c.body != "" {
				body = strings.NewReader(c.body)
				if c.chunked {
					body = io.MultiReader(strings.NewReader(c.body)) // hides the length, so the client sends it chunked
				}
			}
			req, err := http.NewRequestWithContext(context.Background(), c.method, u.String(), body)
			if err != nil {
				t.Fatal(err)
			}
			req.URL = u // keep the path as written: an escaped slash, a double slash, a dot segment
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Expect", "100-continue") // the gate may refuse before the client sends a body it will not read
			for k, v := range c.header {
				req.Header.Set(k, v)
			}
			client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 5 * time.Second}}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("%s %s: %d; want %d", c.method, c.url, resp.StatusCode, c.want)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("the upstream saw %d requests; a refused request must never reach it", n)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// rawRequest writes one request over a bare connection to the gate at base, with the method and the request target
// exactly as given (no client rewrites them), and returns the status of the answer.
func rawRequest(t *testing.T, base, method, target, body string) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		method, target, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// A body that says it is not encoded passes: Content-Encoding identity, or the header empty.
func TestModelGatePassesAnIdentityBody(t *testing.T) {
	up, _, hits := recordingUpstream(t)
	allow := filepath.Join(t.TempDir(), "allowed")
	writeAllow(t, allow, "qwen-a")
	base := startGate(t, up.URL, allow)
	for _, enc := range []string{"identity", ""} {
		req, err := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"qwen-a","messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Encoding", enc)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("Content-Encoding %q: %d; want 200", enc, resp.StatusCode)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("the upstream saw %d requests; want 2", n)
	}
}

func TestModelGateRereadsTheAllowFile(t *testing.T) {
	up, _, _ := recordingUpstream(t)
	allow := filepath.Join(t.TempDir(), "allowed")
	writeAllow(t, allow, "qwen-a")
	base := startGate(t, up.URL, allow)
	for _, step := range []struct {
		allow, model string // allow "": remove the file
		want         int
	}{
		{"qwen-a", "qwen-a", 200},
		{"qwen-a", "qwen-b", 403},
		{"qwen-b", "qwen-b", 200}, // a new run's model, with no restart
		{"qwen-b", "qwen-a", 403},
		{"", "qwen-b", 503},
		{"qwen-a", "qwen-a", 200},
	} {
		if step.allow == "" {
			if err := os.Remove(allow); err != nil {
				t.Fatal(err)
			}
		} else {
			writeAllow(t, allow, step.allow)
		}
		if got := chat(t, base, step.model).StatusCode; got != step.want {
			t.Errorf("allowed %q, asked for %q: %d; want %d", step.allow, step.model, got, step.want)
		}
	}
}

func TestModelGateNeedsItsFlags(t *testing.T) {
	bin := buildGate(t)
	allow := filepath.Join(t.TempDir(), "allowed")
	for name, args := range map[string][]string{
		"no upstream":             {"-listen", "127.0.0.1:0", "-allow", allow},
		"no allow file":           {"-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:8080"},
		"no address":              {"-upstream", "http://127.0.0.1:8080", "-allow", allow},
		"an upstream with a path": {"-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:8080/v1", "-allow", allow},
		"an upstream over https":  {"-listen", "127.0.0.1:0", "-upstream", "https://127.0.0.1:8080", "-allow", allow},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var errOut bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stderr = &errOut
		err := cmd.Run()
		cancel()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 || errOut.Len() == 0 {
			t.Errorf("%s: %v, %q; want exit 2 with a reason", name, err, errOut.String())
		}
	}
}
