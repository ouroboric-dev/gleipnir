#!/bin/sh
# egress.sh HOSTS [SERVICES]: the egress firewall of a leaf's sandbox (spec §6.2). It runs as root in the
# firewall sidecar, which owns the network namespace the work container joins; the agent's container
# has no capabilities, so it can't change a rule. Output, input and forwarding are dropped, except
# loopback, replies, DNS to the resolver, 443/tcp to the addresses of the hosts in HOSTS (one
# name per line), and the listed ports of the services in SERVICES (one "name port" per line; the
# containers beside the work container, such as a database). A service may still be starting, so a
# name that does not resolve is tried again each second, up to YGG_SERVICE_WAIT times (default 30).
# Names are resolved to addresses, so the script resolves them again every
# YGG_REFRESH seconds (default 300) and swaps the rules in without a gap. Without a resolvable
# host at the start it exits 1, so the sandbox never opens half closed.
#
# The work container asks the same resolver the firewall asked, and a name served from a large pool (the Go
# proxy and the vulnerability databases are Google's) answers with another address from time to time, which
# the rules would not allow. So the work container is not left to ask: every DNS query of a process that is
# neither root (this script's own lookups) nor nobody (dnsmasq's) is redirected to a dnsmasq in this
# namespace, which answers from the addresses the rules allow, forwards the names of the services to the
# resolver that knows them, and answers nothing else. The rules are swapped before the answers change.
set -eu
HOSTS="${1:?usage: egress.sh HOSTS [SERVICES]}"
SERVICES="${2:-}"
WAIT="${YGG_SERVICE_WAIT:-30}"
DNSPORT=5353
STATE="${YGG_FW_STATE:-/run/ygg-fw}"
REFRESH="${YGG_REFRESH:-300}"
mkdir -p "$STATE"

ns="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)"
[ -n "$ns" ] || { echo "egress: no nameserver in /etc/resolv.conf" >&2; exit 1; }

# resolve prints "address host" for every IPv4 address of every host, one per line, or fails on a host with none.
resolve() {
  while read -r host; do
    [ -n "$host" ] || continue
    found="$(getent ahostsv4 "$host" | awk '{ print $1 }' | sort -u)"
    [ -n "$found" ] || { echo "egress: $host does not resolve" >&2; return 1; }
    for ip in $found; do echo "$ip $host"; done
  done < "$HOSTS"
}

# resolve_services prints "address port" for every port of every service, or fails on a service that
# has no address after WAIT tries.
resolve_services() {
  [ -n "$SERVICES" ] && [ -s "$SERVICES" ] || return 0
  while read -r name port; do
    [ -n "$name" ] || continue
    tries=0
    while :; do
      found="$(getent ahostsv4 "$name" | awk '{ print $1 }' | sort -u)"
      [ -n "$found" ] && break
      tries=$((tries + 1))
      if [ "$tries" -ge "$WAIT" ]; then echo "egress: service $name does not resolve" >&2; return 1; fi
      sleep 1
    done
    for ip in $found; do echo "$ip $port"; done
  done < "$SERVICES"
}

base() {
  for t in iptables ip6tables; do
    command -v "$t" >/dev/null 2>&1 || continue
    "$t" -P INPUT DROP
    "$t" -P FORWARD DROP
    "$t" -P OUTPUT DROP
    "$t" -A INPUT -i lo -j ACCEPT
    "$t" -A OUTPUT -o lo -j ACCEPT
    "$t" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    "$t" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  done
  iptables -A OUTPUT -p udp -d "$ns" --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp -d "$ns" --dport 53 -j ACCEPT
  # A process that is not root and not nobody asks dnsmasq, not the resolvers. The kernel keeps the output
  # interface of the route the packet had before its destination changed, so the filter does not see the
  # redirected query as loopback traffic, and the query to dnsmasq is allowed by its address and port.
  iptables -t nat -F OUTPUT
  for proto in udp tcp; do
    iptables -A OUTPUT -p "$proto" -d 127.0.0.1 --dport "$DNSPORT" -j ACCEPT
    iptables -t nat -A OUTPUT -p "$proto" --dport 53 -m owner --uid-owner 0 -j RETURN
    iptables -t nat -A OUTPUT -p "$proto" --dport 53 -m owner --uid-owner 65534 -j RETURN
    iptables -t nat -A OUTPUT -p "$proto" --dport 53 -j REDIRECT --to-ports "$DNSPORT"
  done
}

# answers writes the addresses dnsmasq gives for the allowed hosts ("address host" lines), whole, in one move.
answers() {
  printf '%s\n' "$1" > "$STATE/hosts.new"
  mv "$STATE/hosts.new" "$STATE/hosts"
}

# dns_conf writes dnsmasq's configuration: it answers from the file of addresses and from nothing else but the
# services' names, which it asks the resolver that knows them.
dns_conf() {
  {
    echo "port=$DNSPORT"
    echo "listen-address=127.0.0.1"
    echo "bind-interfaces"
    echo "no-resolv"
    echo "no-hosts"
    echo "cache-size=0"
    echo "local-ttl=5"
    echo "user=nobody"
    echo "pid-file=$STATE/dnsmasq.pid"
    echo "addn-hosts=$STATE/hosts"
    if [ -n "$SERVICES" ] && [ -s "$SERVICES" ]; then
      awk '{ print $1 }' "$SERVICES" | sort -u | while read -r name; do
        [ -n "$name" ] && echo "server=/$name/$ns"
      done
    fi
  } > "$STATE/dnsmasq.conf"
}

# start_dns starts dnsmasq and waits until it says it is listening (its pid file), or gives up.
start_dns() {
  rm -f "$STATE/dnsmasq.pid"
  dnsmasq --keep-in-foreground --conf-file="$STATE/dnsmasq.conf" >&2 &
  tries=0
  while [ ! -s "$STATE/dnsmasq.pid" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 10 ] || ! kill -0 "$!" 2>/dev/null; then echo "egress: dnsmasq did not start" >&2; return 1; fi
    sleep 1
  done
}

# apply swaps in a fresh chain of host rules: the new chain is reachable before the old one goes.
apply() {
  addrs="$(printf '%s\n' "$1" | awk '{ print $1 }' | sort -u)"
  svc="$2"
  old="$(cat "$STATE/chain" 2>/dev/null || true)"
  if [ "$old" = YGG_HOSTS_A ]; then new=YGG_HOSTS_B; else new=YGG_HOSTS_A; fi
  iptables -N "$new" 2>/dev/null || iptables -F "$new"
  for ip in $addrs; do
    iptables -A "$new" -p tcp -d "$ip" --dport 443 -j ACCEPT
  done
  while read -r ip port; do
    [ -n "$ip" ] || continue
    iptables -A "$new" -p tcp -d "$ip" --dport "$port" -j ACCEPT
  done <<EOF
$svc
EOF
  iptables -A OUTPUT -j "$new"
  if [ -n "$old" ]; then
    iptables -D OUTPUT -j "$old"
    iptables -F "$old"
  fi
  echo "$new" > "$STATE/chain"
}

hosts="$(resolve)"
svcs="$(resolve_services)"
base
apply "$hosts" "$svcs"
answers "$hosts"
dns_conf
start_dns
touch "$STATE/ready"
[ "${YGG_ONCE:-}" = 1 ] && exit 0
n=0
while sleep "$REFRESH"; do
  # The rules are swapped first, then the answers: whatever dnsmasq gives out is already allowed.
  if hosts="$(resolve)" && svcs="$(resolve_services)"; then
    apply "$hosts" "$svcs"
    answers "$hosts"
    kill -HUP "$(cat "$STATE/dnsmasq.pid")"
  else
    echo "egress: keeping the earlier addresses" >&2
  fi
  n=$((n + 1))
  [ "$n" -ne "${YGG_MAX_REFRESH:--1}" ] || exit 0
done
