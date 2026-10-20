//go:build sandbox

package sandbox

// The prompt of an OpenCode session goes on stdin, through the driver's exec (see opencode.Args). A real
// reviewer session answered "Ready to help. What would you like to do?", which is what OpenCode says to an
// empty message (the real-agent smoke, v0-H17). This test finds out whether the prompt reaches OpenCode
// through the sandbox. It costs nothing: a stand-in provider runs inside the same command, on the loopback
// interface, and records the requests. Set the same variables as for TestSandboxDriverOnARealEngine, then run:
//
//	go test -tags sandbox -run TestAnOpenCodePromptOnStdinReachesTheProvider -v -timeout 40m ./sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gleipnir/opencode"
	"github.com/ouroboric-dev/gungnir"
)

// A provider that records every request body in the file named by its first argument and answers 500.
const recordingProvider = `import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode("utf8", "replace")
        open(sys.argv[1], "a").write(body + "\n")
        self.send_response(500); self.end_headers(); self.wfile.write(b'{"error":{"message":"stand-in"}}')
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[2])), H).serve_forever()
`

func TestAnOpenCodePromptOnStdinReachesTheProvider(t *testing.T) {
	socket, tree, engineTree := itEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	cfg := Config{Mounts: []PathMap{{Host: tree, Engine: engineTree}}, Images: ImagesFor(itStack), UID: os.Getuid(), GID: os.Getgid()}
	work, err := os.MkdirTemp(tree, "work-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	d, err := New(socket, cfg, work)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.run(ctx, d.Podman, "image", "exists", cfg.Images.Work); err != nil {
		t.Logf("building the images (a few minutes)")
		if _, err := d.Build(ctx, itStack); err != nil {
			t.Fatalf("Build() = %v", err)
		}
	}
	env, err := d.Up(ctx, itTree(t, tree))
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })

	// The command line and the configuration are the adapter's, as a reviewer gets them (read only, strict
	// privacy); the one change is the address of the provider, which is the stand-in.
	const model = "openrouter/deepseek/deepseek-v4-flash"
	agent, err := opencode.New(model, opencode.Config{Privacy: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	task := gungnir.Task{ReadOnly: true, MaxTurns: 10}
	raw, err := agent.ConfigJSON(task)
	if err != nil {
		t.Fatal(err)
	}
	var conf map[string]any
	if err := json.Unmarshal([]byte(raw), &conf); err != nil {
		t.Fatal(err)
	}
	opts := conf["provider"].(map[string]any)["openrouter"].(map[string]any)["options"].(map[string]any)
	opts["baseURL"], opts["apiKey"] = "http://127.0.0.1:18080/v1", "stand-in-key"
	confJSON, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}

	const marker = "STDIN-MARKER-7f3a9c"
	prompt := "Review the work in this repository against the brief.\n\n" + marker + "\n"
	script := `d=$(mktemp -d); printf '%s' "$PROVIDER" > "$d/provider.py"; ` +
		`python3 "$d/provider.py" "$d/requests" 18080 & sleep 1; ` +
		`timeout 90 "$@" >/dev/null 2>&1; ` +
		`grep -c ` + marker + ` "$d/requests"`
	argv := append([]string{"sh", "-c", script, "sh"}, opencode.Args(task, strings.TrimPrefix(model, "openrouter/"))...)
	var out bytes.Buffer
	res, err := d.Exec(ctx, env, gungnir.Cmd{Argv: argv, Stdin: strings.NewReader(prompt), Stdout: &out, Stderr: &out,
		Env: map[string]string{"PROVIDER": recordingProvider, "OPENCODE_CONFIG_CONTENT": string(confJSON), "OPENCODE_DISABLE_PROJECT_CONFIG": "1"}})
	if err != nil {
		t.Fatalf("Exec() = %v", err)
	}
	got := strings.TrimSpace(out.String())
	if res.ExitCode != 0 || got == "" || got == "0" {
		t.Errorf("the provider saw the prompt %q times (exit %d): the prompt on stdin did not reach OpenCode through the sandbox", got, res.ExitCode)
	}
}
