package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubs puts fake iptables, ip6tables and getent first on PATH: iptables and ip6tables log their
// arguments, and getent answers from a fixed table.
func stubs(t *testing.T) (bin, log string) {
	t.Helper()
	bin, log = t.TempDir(), filepath.Join(t.TempDir(), "calls.log")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("iptables", `echo "iptables $*" >> "$STUB_LOG"`+"\n")
	write("ip6tables", `echo "ip6tables $*" >> "$STUB_LOG"`+"\n")
	write("getent", `case "$2" in
  api.anthropic.com) echo "160.79.104.10 STREAM api.anthropic.com" ;;
  proxy.golang.org) echo "142.250.1.1 STREAM"; echo "142.250.1.2 STREAM" ;;
esac
`)
	return bin, log
}

func runEgress(t *testing.T, hosts string, extra ...string) (calls string, state string, err error) {
	t.Helper()
	bin, log := stubs(t)
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte(hosts), 0o644)
	resolv := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolv, []byte("nameserver 10.89.0.1\n"), 0o644)
	script := filepath.Join(dir, "egress.sh")
	os.WriteFile(script, []byte(strings.ReplaceAll(EgressScript, "/etc/resolv.conf", resolv)), 0o755)
	state = filepath.Join(dir, "state")
	cmd := exec.Command("sh", script, hostsFile)
	cmd.Env = append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "STUB_LOG=" + log, "YGG_FW_STATE=" + state, "YGG_ONCE=1"}, extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = &scriptError{err, string(out)}
	}
	b, _ := os.ReadFile(log)
	return string(b), state, err
}

type scriptError struct {
	error
	out string
}

func (e *scriptError) Error() string { return e.error.Error() + ": " + e.out }

func TestEgressDeniesEverythingButTheListedHosts(t *testing.T) {
	calls, state, err := runEgress(t, "api.anthropic.com\nproxy.golang.org\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -P OUTPUT DROP", "iptables -P INPUT DROP", "iptables -P FORWARD DROP", "ip6tables -P OUTPUT DROP",
		"iptables -A OUTPUT -p udp -d 10.89.0.1 --dport 53 -j ACCEPT",
		"iptables -A YGG_HOSTS_A -p tcp -d 160.79.104.10 --dport 443 -j ACCEPT",
		"iptables -A YGG_HOSTS_A -p tcp -d 142.250.1.2 --dport 443 -j ACCEPT",
		"iptables -A OUTPUT -j YGG_HOSTS_A",
	} {
		if !strings.Contains(calls, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "-P OUTPUT ACCEPT") || strings.Contains(calls, "--dport 80") {
		t.Errorf("the rules open more than 443 to the listed hosts:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err != nil {
		t.Error("the firewall never said it was ready")
	}
}

func TestEgressRefusesToOpenHalfClosed(t *testing.T) {
	calls, state, err := runEgress(t, "api.anthropic.com\nno-such-host.example.com\n")
	if err == nil {
		t.Fatal("egress.sh succeeded with a host that doesn't resolve")
	}
	if strings.Contains(calls, "-P OUTPUT DROP") {
		t.Errorf("the script changed rules before it knew every host:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
		t.Error("a failed firewall said it was ready")
	}
}
