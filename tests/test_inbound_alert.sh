#!/bin/sh

set -u

SCRIPT=${SCRIPT:-root/usr/bin/pushbot/pushbot}
PASS=0
FAIL=0

load_function() {
	name="$1"
	body=$(awk -v name="$name" '
		$0 ~ "^function " name "\\(\\)" { found=1 }
		found { print }
		found && /^}/ { exit }
	' "$SCRIPT")
	[ -n "$body" ] || return 1
	eval "$body"
}

assert_eq() {
	name="$1" expected="$2" actual="$3"
	if [ "$expected" = "$actual" ]; then
		PASS=$((PASS + 1))
		printf 'ok - %s\n' "$name"
	else
		FAIL=$((FAIL + 1))
		printf 'not ok - %s\n  expected: %s\n  actual:   %s\n' "$name" "$expected" "$actual"
	fi
}

assert_rejected() {
	name="$1" line="$2"
	if parse_inbound_conntrack_event "$line" >/dev/null 2>&1; then
		FAIL=$((FAIL + 1))
		printf 'not ok - %s\n  expected event to be rejected\n' "$name"
	else
		PASS=$((PASS + 1))
		printf 'ok - %s\n' "$name"
	fi
}

load_function parse_inbound_conntrack_event || {
	printf 'not ok - parse_inbound_conntrack_event is missing\n'
	exit 1
}
load_function inbound_route_is_wan_to_lan || {
	printf 'not ok - inbound_route_is_wan_to_lan is missing\n'
	exit 1
}
load_function resolve_inbound_target_name || {
	printf 'not ok - resolve_inbound_target_name is missing\n'
	exit 1
}

ipv4='[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=54321 dport=443 [UNREPLIED] src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=54321'
assert_eq 'IPv4 DNAT uses the translated LAN target' \
	'ipv4 tcp 198.51.100.7 54321 192.168.1.20 8443' \
	"$(parse_inbound_conntrack_event "$ipv4")"

ipv6='[NEW] udp 17 30 src=2001:db8:ffff::7 dst=2001:db8:1::20 sport=53000 dport=53 [UNREPLIED] src=2001:db8:1::20 dst=2001:db8:ffff::7 sport=53 dport=53000'
assert_eq 'IPv6 keeps complete colon-delimited addresses' \
	'ipv6 udp 2001:db8:ffff::7 53000 2001:db8:1::20 53' \
	"$(parse_inbound_conntrack_event "$ipv6")"

assert_rejected 'ICMP is ignored' '[NEW] icmp 1 30 src=198.51.100.7 dst=192.168.1.20 type=8 code=0 id=1 src=192.168.1.20 dst=198.51.100.7 type=0 code=0 id=1'
assert_rejected 'missing reply tuple is ignored' '[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=54321 dport=443'

inbound_zone_role_for_ip() {
	case "$1" in
		198.51.100.7) printf '%s\n' wan ;;
		192.168.1.20|2001:db8:1::20) printf '%s\n' lan ;;
		*) printf '%s\n' unknown ;;
	esac
}
inbound_is_local_address() { [ "$1" = '192.168.1.1' ]; }
inbound_route_is_wan_to_lan '198.51.100.7' '192.168.1.20'
assert_eq 'custom firewall roles accept WAN to LAN' '0' "$?"
if inbound_route_is_wan_to_lan '192.168.1.20' '198.51.100.7'; then rc=0; else rc=$?; fi
assert_eq 'LAN outbound direction is rejected' '1' "$rc"
if inbound_route_is_wan_to_lan '198.51.100.7' '192.168.1.1'; then rc=0; else rc=$?; fi
assert_eq 'router INPUT target is rejected' '1' "$rc"

device_aliases='AA:BB:CC:DD:EE:01 camera'
INBOUND_DHCP_LEASES=$(mktemp)
trap 'rm -f "$INBOUND_DHCP_LEASES"' EXIT
printf '%s\n' '0 aa:bb:cc:dd:ee:01 192.168.1.20 dhcp-camera *' > "$INBOUND_DHCP_LEASES"
assert_eq 'PushBot alias wins over DHCP hostname' 'camera' "$(resolve_inbound_target_name '192.168.1.20')"
device_aliases=''
assert_eq 'DHCP hostname is the fallback' 'dhcp-camera' "$(resolve_inbound_target_name '192.168.1.20')"
assert_eq 'unknown device has an explicit name' '未知设备' "$(resolve_inbound_target_name '192.168.1.99')"

printf '%s tests, %s failures\n' "$((PASS + FAIL))" "$FAIL"
[ "$FAIL" -eq 0 ]
