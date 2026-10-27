package sandbox

import (
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
  postgres) echo "10.89.0.5 STREAM postgres" ;;
  seaweedfs) echo "10.89.0.6 STREAM seaweedfs" ;;
  lmit-server) echo "10.89.7.2 STREAM lmit-server" ;;
  late) n="$(cat "$STUB_LATE" 2>/dev/null || echo 0)"; echo $((n+1)) > "$STUB_LATE"; [ "$n" -ge 2 ] && echo "10.89.0.7 STREAM late" ;;
  rotating.example.com) n="$(cat "$STUB_ROTATE" 2>/dev/null || echo 0)"; echo $((n+1)) > "$STUB_ROTATE"; echo "10.0.0.$((n+1)) STREAM rotating.example.com" ;;
esac
`)
	// dnsmasq logs how it was called and the configuration it was given, writes its pid file as the real one
	// does once it listens, and stays up a moment, or fails to start when STUB_DNSMASQ_FAIL is set.
	write("dnsmasq", `echo "dnsmasq $*" >> "$STUB_LOG"
[ -z "$STUB_DNSMASQ_FAIL" ] || exit 1
conf=""; for a in "$@"; do case "$a" in --conf-file=*) conf="${a#--conf-file=}" ;; esac; done
sed 's/^/conf: /' "$conf" >> "$STUB_LOG"
echo "$$" > "$(sed -n 's/^pid-file=//p' "$conf")"
exec /bin/sleep 2
`)
	write("sleep", "exit 0\n")
	return bin, log
}

func runEgress(t *testing.T, hosts string, extra ...string) (calls string, state string, err error) {
	t.Helper()
	return runEgressWithServices(t, hosts, "", extra...)
}

// runEgressWithServices is runEgress with a services file: one "name port" line for each port a service
// opens. An empty services means the script gets no second argument.
func runEgressWithServices(t *testing.T, hosts, services string, extra ...string) (calls string, state string, err error) {
	t.Helper()
	return runEgressIn(t, "sh", hosts, services, extra...)
}

// runEgressIn is runEgressWithServices with the shell that runs the script.
func runEgressIn(t *testing.T, shell, hosts, services string, extra ...string) (calls string, state string, err error) {
	t.Helper()
	bin, log := stubs(t)
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte(hosts), 0o644)
	resolv := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolv, []byte("nameserver 10.89.0.1\n"), 0o644)
	route := filepath.Join(dir, "route")
	os.WriteFile(route, []byte(routeTable(t, "eth0 default 10.89.0.1", "eth0 10.89.0.0/24")), 0o644)
	script := filepath.Join(dir, "egress.sh")
	os.WriteFile(script, []byte(EgressScript), 0o755)
	state = filepath.Join(dir, "state")
	args := []string{script, hostsFile}
	if services != "" {
		servicesFile := filepath.Join(dir, "services")
		os.WriteFile(servicesFile, []byte(services), 0o644)
		args = append(args, servicesFile)
	}
	cmd := exec.Command(shell, args...)
	cmd.Env = append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "STUB_LOG=" + log, "STUB_LATE=" + filepath.Join(dir, "late"), "STUB_ROTATE=" + filepath.Join(dir, "rotate"),
		"YGG_FW_STATE=" + state, "YGG_FW_RESOLV=" + resolv, "YGG_FW_ROUTE=" + route, "YGG_ONCE=1"}, extra...)
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

func TestEgressOpensAServicesPortsAndNoOthers(t *testing.T) {
	calls, state, err := runEgressWithServices(t, "api.anthropic.com\n", "postgres 5432\nseaweedfs 8333\nseaweedfs 9333\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -A YGG_HOSTS_A -p tcp -d 160.79.104.10 --dport 443 -j ACCEPT",
		"iptables -A YGG_HOSTS_A -p tcp -d 10.89.0.5 --dport 5432 -j ACCEPT",
		"iptables -A YGG_HOSTS_A -p tcp -d 10.89.0.6 --dport 8333 -j ACCEPT",
		"iptables -A YGG_HOSTS_A -p tcp -d 10.89.0.6 --dport 9333 -j ACCEPT",
	} {
		if !strings.Contains(calls, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, calls)
		}
	}
	for _, not := range []string{"-d 10.89.0.5 --dport 443", "-d 10.89.0.5 --dport 5433", "-P OUTPUT ACCEPT"} {
		if strings.Contains(calls, not) {
			t.Errorf("the rules hold %q, which opens more than the service's ports:\n%s", not, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err != nil {
		t.Error("the firewall never said it was ready")
	}
}

func TestEgressWaitsForAServiceThatIsStillStarting(t *testing.T) {
	calls, _, err := runEgressWithServices(t, "api.anthropic.com\n", "late 5432\n", "YGG_SERVICE_WAIT=5")
	if err != nil || !strings.Contains(calls, "-d 10.89.0.7 --dport 5432 -j ACCEPT\n") {
		t.Errorf("a service that resolves on the third try: %v\n%s", err, calls)
	}
}

func TestEgressRefusesToOpenWithoutAService(t *testing.T) {
	calls, state, err := runEgressWithServices(t, "api.anthropic.com\n", "postgres 5432\nghost 5432\n", "YGG_SERVICE_WAIT=2")
	if err == nil {
		t.Fatal("egress.sh succeeded with a service that never resolves")
	}
	if strings.Contains(calls, "-P OUTPUT DROP") {
		t.Errorf("the script changed rules before it knew every address:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
		t.Error("a failed firewall said it was ready")
	}
}

func TestEgressAnswersDNSItselfForTheListedHostsAndTheServicesAndNothingElse(t *testing.T) {
	calls, state, err := runEgressWithServices(t, "api.anthropic.com\nproxy.golang.org\n", "postgres 5432\n")
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := os.ReadFile(filepath.Join(state, "hosts"))
	for _, want := range []string{"160.79.104.10 api.anthropic.com\n", "142.250.1.1 proxy.golang.org\n", "142.250.1.2 proxy.golang.org\n"} {
		if !strings.Contains(string(hosts), want) {
			t.Errorf("the answers lack %q:\n%s", want, hosts)
		}
	}
	for _, want := range []string{"conf: port=5353\n", "conf: listen-address=127.0.0.1\n", "conf: no-resolv\n", "conf: no-hosts\n", "conf: cache-size=0\n",
		"conf: addn-hosts=" + filepath.Join(state, "hosts") + "\n", "conf: server=/postgres/10.89.0.1\n", "conf: user=nobody\n"} {
		if !strings.Contains(calls, want) {
			t.Errorf("dnsmasq's configuration lacks %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "conf: server=/api.anthropic.com") || strings.Contains(calls, "server=10.89.0.1") {
		t.Errorf("dnsmasq forwards more than the services' names:\n%s", calls)
	}
	// What the work container asks is answered here: every DNS query of a process that is neither root (the
	// script's own lookups) nor nobody (dnsmasq's) goes to dnsmasq's port.
	for _, want := range []string{
		"iptables -t nat -A OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j RETURN",
		"iptables -t nat -A OUTPUT -p udp --dport 53 -m owner --uid-owner 65534 -j RETURN",
		"iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5353 -j ACCEPT",
		"iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5353 -j ACCEPT",
		"iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353",
		"iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353",
	} {
		if !strings.Contains(calls, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err != nil {
		t.Error("the firewall never said it was ready")
	}
}

func TestEgressRefusesToOpenWhenItCannotAnswerDNS(t *testing.T) {
	_, state, err := runEgress(t, "api.anthropic.com\n", "STUB_DNSMASQ_FAIL=1")
	if err == nil {
		t.Fatal("egress.sh succeeded without a resolver for the work container")
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
		t.Error("a firewall with no resolver said it was ready")
	}
}

func TestEgressAnswersWhatItAllowsAfterARefreshToo(t *testing.T) {
	calls, state, err := runEgress(t, "rotating.example.com\n", "YGG_ONCE=0", "YGG_MAX_REFRESH=1")
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := os.ReadFile(filepath.Join(state, "hosts"))
	if string(hosts) != "10.0.0.2 rotating.example.com\n" {
		t.Errorf("after a refresh the answers are %q, want the new address alone", hosts)
	}
	for _, want := range []string{"iptables -A YGG_HOSTS_A -p tcp -d 10.0.0.1 --dport 443 -j ACCEPT\n", "iptables -A YGG_HOSTS_B -p tcp -d 10.0.0.2 --dport 443 -j ACCEPT\n"} {
		if !strings.Contains(calls, want) {
			t.Errorf("the rules lack %q:\n%s", want, calls)
		}
	}
}

// routeTable writes /proc/net/route's text for routes given as "IFACE default GATEWAY [metric N]" or
// "IFACE ADDRESS/PREFIX [via GATEWAY] [metric N]": the kernel prints each address as the hex of its 32 bits in
// memory, little-endian on the engine's machines, and a connected route's gateway as 00000000.
func routeTable(t *testing.T, routes ...string) string {
	t.Helper()
	le := func(ip net.IP) string {
		v := ip.To4()
		return fmt.Sprintf("%02X%02X%02X%02X", v[3], v[2], v[1], v[0])
	}
	var b strings.Builder
	b.WriteString("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\t\t\n")
	for _, r := range routes {
		f := strings.Fields(r)
		dst, mask, gw, flags, metric := "00000000", "00000000", "00000000", "0001", "0"
		rest := f[2:]
		if f[1] == "default" {
			gw, flags, rest = le(net.ParseIP(f[2])), "0003", f[3:]
		} else {
			_, subnet, err := net.ParseCIDR(f[1])
			if err != nil {
				t.Fatal(err)
			}
			dst, mask = le(subnet.IP), le(net.IP(subnet.Mask))
		}
		for i := 0; i+1 < len(rest); i += 2 {
			switch rest[i] {
			case "via":
				gw, flags = le(net.ParseIP(rest[i+1])), "0003"
			case "metric":
				metric = rest[i+1]
			default:
				t.Fatalf("route %q: unknown word %q", r, rest[i])
			}
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t0\t0\t%s\t%s\t0\t0\t0   \n", f[0], dst, gw, flags, metric, mask)
	}
	return b.String()
}

// egressFunction returns the definition of the shell function name in egress.sh, so a test can run it alone.
func egressFunction(t *testing.T, name string) string {
	t.Helper()
	start := strings.Index(EgressScript, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("egress.sh has no function %s", name)
	}
	end := strings.Index(EgressScript[start:], "\n}\n")
	return EgressScript[start+1 : start+end+3]
}

// awks returns a folder for each awk the firewall image might hold that this machine has: the one on PATH, and
// mawk (Debian's default) and busybox's, each linked as awk. The selection is POSIX awk, so all must agree.
func awks(t *testing.T) map[string]string {
	t.Helper()
	dirs := map[string]string{"awk": ""}
	for _, a := range [][]string{{"mawk"}, {"busybox", "awk"}} {
		path, err := exec.LookPath(a[0])
		if err != nil {
			continue
		}
		dir := t.TempDir()
		body := "#!/bin/sh\nexec " + strings.Join(append([]string{path}, a[1:]...), " ") + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(dir, "awk"), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		dirs[strings.Join(a, " ")] = dir
	}
	t.Logf("the awks this run tests: %v", slices.Sorted(maps.Keys(dirs)))
	return dirs
}

func TestEgressPicksTheResolverOfTheDefaultRoutesNetwork(t *testing.T) {
	lmis := routeTable(t, "eth1 default 10.89.12.1", "eth0 10.89.7.0/24", "eth1 10.89.12.0/24", "eth2 10.89.11.0/24")
	for _, c := range []struct {
		name, route, resolv, want, refusal string
	}{
		{"an internal network's resolver first", lmis,
			"search dns.podman dns.podman dns.podman\nnameserver 10.89.7.1\nnameserver 10.89.11.1\nnameserver 10.89.12.1\n", "10.89.12.1", ""},
		{"the default network's resolver first", lmis, "nameserver 10.89.12.1\nnameserver 10.89.7.1\n", "10.89.12.1", ""},
		{"one network", routeTable(t, "eth0 default 10.89.0.1", "eth0 10.89.0.0/24"), "nameserver 10.89.0.1\n", "10.89.0.1", ""},
		{"a wider subnet and an IPv6 resolver", routeTable(t, "eth0 10.89.7.0/24", "eth1 default 10.88.0.1", "eth1 10.88.0.0/16"),
			"nameserver fd00::1\nnameserver 10.89.7.1\nnameserver 10.88.3.1\n", "10.88.3.1", ""},
		{"no resolver in the default network", lmis, "nameserver 10.89.7.1\nnameserver 10.89.11.1\n", "", "no nameserver"},
		{"no default route", routeTable(t, "eth0 10.89.7.0/24"), "nameserver 10.89.7.1\n", "", "no default route"},
		// A split route (0.0.0.0/1) has destination 00000000 too: only mask 00000000 makes a default route.
		{"a split route on an internal interface listed first",
			routeTable(t, "eth1 0.0.0.0/1 via 10.89.7.1", "eth1 10.89.7.0/24", "eth0 default 10.89.12.1", "eth0 10.89.12.0/24"),
			"nameserver 10.89.7.1\nnameserver 10.89.12.1\n", "10.89.12.1", ""},
		// A route through a gateway is not the interface's subnet: only connected routes count.
		{"a wide route through a gateway on the default interface",
			routeTable(t, "eth0 default 10.89.12.1", "eth0 10.89.0.0/16 via 10.89.12.1", "eth0 10.89.12.0/24", "eth1 10.89.7.0/24"),
			"nameserver 10.89.7.1\nnameserver 10.89.12.1\n", "10.89.12.1", ""},
		{"two default routes: the lower metric wins, wherever it is listed",
			routeTable(t, "eth1 default 10.89.7.1 metric 200", "eth1 10.89.7.0/24", "eth0 default 10.89.12.1 metric 100", "eth0 10.89.12.0/24"),
			"nameserver 10.89.7.1\nnameserver 10.89.12.1\n", "10.89.12.1", ""},
		{"two default routes of one metric: the first listed",
			routeTable(t, "eth0 default 10.89.12.1 metric 100", "eth0 10.89.12.0/24", "eth1 default 10.89.7.1 metric 100", "eth1 10.89.7.0/24"),
			"nameserver 10.89.7.1\nnameserver 10.89.12.1\n", "10.89.12.1", ""},
	} {
		for awk, dir := range awks(t) {
			t.Run(c.name+" ("+awk+")", func(t *testing.T) {
				files := t.TempDir()
				route, resolv := filepath.Join(files, "route"), filepath.Join(files, "resolv.conf")
				os.WriteFile(route, []byte(c.route), 0o644)
				os.WriteFile(resolv, []byte(c.resolv), 0o644)
				cmd := exec.Command("sh", "-c", egressFunction(t, "default_resolver")+`default_resolver "$1" "$2"`, "sh", route, resolv)
				if dir != "" {
					cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
				}
				var stderr strings.Builder
				cmd.Stderr = &stderr
				out, err := cmd.Output()
				got := strings.TrimSpace(string(out))
				if c.refusal == "" && (err != nil || got != c.want) {
					t.Errorf("default_resolver = %q, %v (%s); want %s", got, err, stderr.String(), c.want)
				}
				if c.refusal != "" && (err == nil || got != "" || !strings.Contains(stderr.String(), c.refusal)) {
					t.Errorf("default_resolver = %q, %v (%s); want a failure that says %q", got, err, stderr.String(), c.refusal)
				}
			})
		}
	}
}

func TestEgressAsksTheDefaultNetworksResolverAloneForEveryName(t *testing.T) {
	dir := t.TempDir()
	resolv, route := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "route")
	os.WriteFile(resolv, []byte("search dns.podman dns.podman\nnameserver 10.89.5.1\nnameserver 10.89.0.1\noptions edns0\n"), 0o644)
	os.WriteFile(route, []byte(routeTable(t, "eth0 default 10.89.0.1", "eth0 10.89.0.0/24", "eth1 10.89.5.0/24")), 0o644)
	calls, state, err := runEgressWithServices(t, "api.anthropic.com\n", "postgres 5432\nlmit-server 8090\n", "YGG_FW_RESOLV="+resolv, "YGG_FW_ROUTE="+route)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -A OUTPUT -p udp -d 10.89.0.1 --dport 53 -j ACCEPT\n", "iptables -A OUTPUT -p tcp -d 10.89.0.1 --dport 53 -j ACCEPT\n",
		"conf: server=/postgres/10.89.0.1\n", "conf: server=/lmit-server/10.89.0.1\n",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("the rules or dnsmasq's configuration lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "10.89.5.1") {
		t.Errorf("the rules or dnsmasq's configuration name the internal network's resolver:\n%s", calls)
	}
	// The script's own lookups (getent) read resolv.conf: it names the chosen resolver alone, and keeps the rest.
	if b, _ := os.ReadFile(resolv); string(b) != "search dns.podman dns.podman\noptions edns0\nnameserver 10.89.0.1\n" {
		t.Errorf("the firewall's resolv.conf after the start:\n%s\nwant its search and options lines and the default network's resolver alone", b)
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err != nil {
		t.Error("the firewall never said it was ready")
	}
}

func TestEgressRefusesToOpenWithoutTheDefaultNetworksResolver(t *testing.T) {
	dir := t.TempDir()
	resolv, route := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "route")
	os.WriteFile(resolv, []byte("nameserver 10.89.5.1\n"), 0o644)
	os.WriteFile(route, []byte(routeTable(t, "eth0 default 10.89.0.1", "eth0 10.89.0.0/24", "eth1 10.89.5.0/24")), 0o644)
	calls, state, err := runEgress(t, "api.anthropic.com\n", "YGG_FW_RESOLV="+resolv, "YGG_FW_ROUTE="+route)
	if err == nil || !strings.Contains(err.Error(), "no nameserver") {
		t.Fatalf("egress.sh with no resolver in the default route's network: %v; want a refusal that says so", err)
	}
	if strings.Contains(calls, "iptables") {
		t.Errorf("the script changed rules before it knew its resolver:\n%s", calls)
	}
	if b, _ := os.ReadFile(resolv); string(b) != "nameserver 10.89.5.1\n" {
		t.Errorf("a refused start rewrote resolv.conf:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
		t.Error("a refused firewall said it was ready")
	}
}

// TestEgressRefusesToOpenWhenItCannotRewriteResolvConf: a redirection that fails on a compound command does not
// stop dash under set -e, so the script must check it itself, or it would apply the rules with its lookups still
// asking every resolver of the old file.
func TestEgressRefusesToOpenWhenItCannotRewriteResolvConf(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	var shells []string
	for _, sh := range []string{"sh", "dash", "bash"} {
		if _, err := exec.LookPath(sh); err == nil {
			shells = append(shells, sh)
		}
	}
	t.Logf("the shells this run tests: %v", shells)
	for _, sh := range shells {
		t.Run(sh, func(t *testing.T) {
			resolv := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(resolv, []byte("nameserver 10.89.0.1\n"), 0o444); err != nil {
				t.Fatal(err)
			}
			calls, state, err := runEgressIn(t, sh, "api.anthropic.com\n", "", "YGG_FW_RESOLV="+resolv)
			if err == nil || !strings.Contains(err.Error(), "egress: cannot rewrite "+resolv) {
				t.Errorf("egress.sh with a read-only resolv.conf: %v; want exit 1 and \"cannot rewrite\"", err)
			}
			if strings.Contains(calls, "iptables") {
				t.Errorf("the script changed rules though it could not rewrite resolv.conf:\n%s", calls)
			}
			if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
				t.Error("the firewall said it was ready")
			}
		})
	}
}
