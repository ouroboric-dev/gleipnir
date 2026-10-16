#!/bin/sh
# egress.sh HOSTS: the egress firewall of a leaf's sandbox (spec §6.2). It runs as root in the
# firewall sidecar, which owns the network namespace the work container joins; the agent's container
# has no capabilities, so it can't change a rule. Output, input and forwarding are dropped, except
# loopback, replies, DNS to the resolver, and 443/tcp to the addresses of the hosts in HOSTS (one
# name per line). Names are resolved to addresses, so the script resolves them again every
# YGG_REFRESH seconds (default 300) and swaps the rules in without a gap. Without a resolvable
# host at the start it exits 1, so the sandbox never opens half closed.
set -eu
HOSTS="${1:?usage: egress.sh HOSTS}"
STATE="${YGG_FW_STATE:-/run/ygg-fw}"
REFRESH="${YGG_REFRESH:-300}"
mkdir -p "$STATE"

ns="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)"
[ -n "$ns" ] || { echo "egress: no nameserver in /etc/resolv.conf" >&2; exit 1; }

# resolve prints the IPv4 addresses of every host, one per line, or fails on a host with none.
resolve() {
  while read -r host; do
    [ -n "$host" ] || continue
    found="$(getent ahostsv4 "$host" | awk '{ print $1 }' | sort -u)"
    [ -n "$found" ] || { echo "egress: $host does not resolve" >&2; return 1; }
    echo "$found"
  done < "$HOSTS"
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
}

# apply swaps in a fresh chain of host rules: the new chain is reachable before the old one goes.
apply() {
  addrs="$1"
  old="$(cat "$STATE/chain" 2>/dev/null || true)"
  if [ "$old" = YGG_HOSTS_A ]; then new=YGG_HOSTS_B; else new=YGG_HOSTS_A; fi
  iptables -N "$new" 2>/dev/null || iptables -F "$new"
  for ip in $addrs; do
    iptables -A "$new" -p tcp -d "$ip" --dport 443 -j ACCEPT
  done
  iptables -A OUTPUT -j "$new"
  if [ -n "$old" ]; then
    iptables -D OUTPUT -j "$old"
    iptables -F "$old"
  fi
  echo "$new" > "$STATE/chain"
}

addrs="$(resolve)"
base
apply "$addrs"
touch "$STATE/ready"
[ "${YGG_ONCE:-}" = 1 ] && exit 0
while sleep "$REFRESH"; do
  if addrs="$(resolve)"; then apply "$addrs"; else echo "egress: keeping the earlier addresses" >&2; fi
done
