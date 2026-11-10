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
load_function inbound_disturb_allows_send || {
	printf 'not ok - inbound_disturb_allows_send is missing\n'
	exit 1
}
load_function prepare_inbound_send_context || {
	printf 'not ok - prepare_inbound_send_context is missing\n'
	exit 1
}
load_function start_inbound_listener || {
	printf 'not ok - start_inbound_listener is missing\n'
	exit 1
}
load_function stop_inbound_listener || {
	printf 'not ok - stop_inbound_listener is missing\n'
	exit 1
}
load_function inbound_alert_send || {
	printf 'not ok - inbound_alert_send is missing\n'
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
assert_rejected 'nonnumeric source port is ignored' '[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=bad dport=443 src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=bad'
assert_rejected 'out of range port is ignored' '[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=70000 dport=443 src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=70000'
assert_rejected 'third tuple is ignored' '[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=54321 dport=443 src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=54321 src=10.0.0.1 dst=10.0.0.2 sport=1 dport=2'

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

# Exercise the real classifier with device-bound zones and custom names.
load_function inbound_zone_role_for_ip
ip() {
	case "$*" in
		'route get 198.51.100.7') echo '198.51.100.7 dev ppp0 src 203.0.113.9' ;;
		'route get 192.168.1.20') echo '192.168.1.20 dev br-home src 192.168.1.1' ;;
		'route show default') echo 'default dev ppp0' ;;
		'-6 route show default') : ;;
		*) return 1 ;;
	esac
}
uci() {
	case "$*" in
		'-q get firewall.@zone[0]') echo zone ;;
		'-q get firewall.@zone[0].network') : ;;
		'-q get firewall.@zone[0].device') echo ppp0 ;;
		'-q get firewall.@zone[0].masq') echo 1 ;;
		'-q get firewall.@zone[1]') echo zone ;;
		'-q get firewall.@zone[1].network') : ;;
		'-q get firewall.@zone[1].device') echo br-home ;;
		'-q get firewall.@zone[1].masq') echo 0 ;;
		*) return 1 ;;
	esac
}
ubus() { return 1; }
jsonfilter() { return 1; }
assert_eq 'device-bound custom WAN zone is classified' 'wan' "$(inbound_zone_role_for_ip '198.51.100.7')"
assert_eq 'device-bound custom LAN zone is classified' 'lan' "$(inbound_zone_role_for_ip '192.168.1.20')"

device_aliases='AA:BB:CC:DD:EE:01 camera'
INBOUND_DHCP_LEASES=$(mktemp)
printf '%s\n' '0 aa:bb:cc:dd:ee:01 192.168.1.20 dhcp-camera *' > "$INBOUND_DHCP_LEASES"
assert_eq 'PushBot alias wins over DHCP hostname' 'camera' "$(resolve_inbound_target_name '192.168.1.20')"
device_aliases=''
assert_eq 'DHCP hostname is the fallback' 'dhcp-camera' "$(resolve_inbound_target_name '192.168.1.20')"
assert_eq 'unknown device has an explicit name' '未知设备' "$(resolve_inbound_target_name '192.168.1.99')"
device_aliases='AA:BB:CC:DD:EE:FF camera-v6'
ip() {
	case "$*" in
		'neigh show to 2001:db8:1::20') echo '2001:db8:1::20 dev br-home lladdr aa:bb:cc:dd:ee:ff REACHABLE' ;;
		*) return 1 ;;
	esac
}
assert_eq 'IPv6 neighbor MAC resolves the configured alias' 'camera-v6' "$(resolve_inbound_target_name '2001:db8:1::20')"
device_aliases='AA:BB:CC:DD:EE:10 static-nas'
ip() { return 1; }
uci() {
	case "$*" in
		'show dhcp') printf "%s\n" "dhcp.@host[0].ip='192.168.1.30'" "dhcp.@host[0].mac='AA:BB:CC:DD:EE:10'" "dhcp.@host[0].name='nas-host'" ;;
		'-q get dhcp.@host[0].mac') echo 'AA:BB:CC:DD:EE:10' ;;
		'-q get dhcp.@host[0].name') echo 'nas-host' ;;
		*) return 1 ;;
	esac
}
assert_eq 'static DHCP host IP resolves the configured alias' 'static-nas' "$(resolve_inbound_target_name '192.168.1.30')"

pushbot_sheep=1; starttime=9; endtime=17; INBOUND_TEST_HOUR=10
if inbound_disturb_allows_send; then rc=0; else rc=$?; fi
assert_eq 'DND mode 1 skips immediately during quiet hours' '1' "$rc"
pushbot_sheep=0
assert_eq 'normal mode allows inbound alerts' '0' "$(inbound_disturb_allows_send; echo $?)"

tmpdir=$(mktemp -d)
trap 'rm -f "$INBOUND_DHCP_LEASES"; rm -rf "$tmpdir"' EXIT
dir="$tmpdir/"
tempjsonpath='/tmp/pushbot/temp.json'
prepare_inbound_send_context
case "$tempjsonpath" in "$tmpdir"/temp.inbound.*.json) got=1;; *) got=0;; esac
assert_eq 'inbound sends use a process-private payload file' '1' "$got"

dir="$tmpdir/"
inbound_alert=0
INBOUND_CONNTRACK_CMD="$tmpdir/conntrack"
PUSHBOT_SELF="$tmpdir/pushbot"
cat > "$INBOUND_CONNTRACK_CMD" <<'EOF'
#!/bin/sh
printf '%s\n' '[NEW] tcp 6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.9 sport=54321 dport=443 [UNREPLIED] src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=54321'
printf '%s\n' '[UPDATE] tcp 6 119 ESTABLISHED src=198.51.100.7 dst=203.0.113.9 sport=54321 dport=443 src=192.168.1.20 dst=198.51.100.7 sport=8443 dport=54321'
EOF
cat > "$PUSHBOT_SELF" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> '$tmpdir/events'
EOF
chmod +x "$INBOUND_CONNTRACK_CMD" "$PUSHBOT_SELF"
start_inbound_listener
assert_eq 'disabled setting does not start the listener' 'absent' "$([ -f "${dir}inbound_listener.pid" ] && echo present || echo absent)"

inbound_alert=1
start_inbound_listener
sleep 1
assert_eq 'listener forwards each NEW event once' '1' "$(wc -l < "$tmpdir/events" | tr -d ' ')"
assert_eq 'listener invokes the inbound event command' 'inbound_event' "$(awk '{print $1}' "$tmpdir/events")"
stop_inbound_listener
assert_eq 'listener PID is cleaned on stop' 'absent' "$([ -f "${dir}inbound_listener.pid" ] && echo present || echo absent)"

cat > "$INBOUND_CONNTRACK_CMD" <<EOF
#!/bin/sh
echo \$\$ >> '$tmpdir/conntrack.pids'
exec tail -f /dev/null
EOF
chmod +x "$INBOUND_CONNTRACK_CMD"
logfile="$tmpdir/log"
start_inbound_listener & first_start=$!
start_inbound_listener & second_start=$!
wait "$first_start" "$second_start"
assert_eq 'concurrent starts create only one conntrack listener' '1' "$(wc -l < "$tmpdir/conntrack.pids" | tr -d ' ')"
listener_pids=$(cat "$tmpdir/conntrack.pids")
stop_inbound_listener
sleep 1
live=0
for listener_pid in $listener_pids; do kill -0 "$listener_pid" 2>/dev/null && live=$((live + 1)); done
assert_eq 'stop leaves no conntrack listener alive' '0' "$live"

parse_inbound_conntrack_event() { printf '%s\n' 'ipv4 tcp 198.51.100.7 54321 192.168.1.20 8443'; }
inbound_route_is_wan_to_lan() { return 0; }
resolve_inbound_target_name() { printf '%s\n' 'NAS'; }
check_dnd_limit() { [ "$1" = 'inbound' ] && [ "$2" = '198.51.100.7:54321-192.168.1.20:8443' ]; }
pushbot_disturb() { return 0; }
diy_send() { printf '%s\n%s\n' "$1" "$2" > "$tmpdir/message"; }
inbound_alert=1
pushbot_enable=1
device_name='主路由'
jsonpath='/tmp/channel.json'
lite_enable=''
str_splitline=''
str_title_start=''
str_title_end=''
str_linefeed='|'
str_tab=''
str_space=' '
font_fail=''
font_end=''
table_enable=''
logfile="$tmpdir/log"
dnd_low_range=1800
inbound_alert_send 'fixture event'
message=$(cat "$tmpdir/message")
case "$message" in *'【主路由】外网入站连接警告'*) ok=1;; *) ok=0;; esac
assert_eq 'message title includes the router name' '1' "$ok"
case "$message" in *'TCP'*'198.51.100.7'*'54321'*'NAS'*'192.168.1.20'*'8443'*) ok=1;; *) ok=0;; esac
assert_eq 'message includes protocol, source, target name and translated endpoint' '1' "$ok"

controller='ucode/controller/pushbot.uc'
template='ucode/template/pushbot/pushbot_status.ut'
pot='po/templates/pushbot.pot'
po='po/zh_Hans/pushbot.po'
config='root/etc/config/pushbot'
grep -q '"inbound_alert"' "$controller" && got=1 || got=0
assert_eq 'configuration API returns the inbound alert scalar' '1' "$got"
content_network=$(awk '/function initContentCard\(\)/ {in_content=1} in_content {print} /c1.appendChild\(b1\); container.appendChild\(c1\);/ {exit}' "$template")
printf '%s\n' "$content_network" | grep -q "mkH('inbound_alert'" && got=1 || got=0
assert_eq 'push content network card persists the inbound alert toggle' '1' "$got"
printf '%s\n' "$content_network" | grep -q "_('Inbound alert notification')" && got=1 || got=0
assert_eq 'push content network card renders the inbound alert label' '1' "$got"
grep -q '^msgid "Inbound alert notification"$' "$pot" && got=1 || got=0
assert_eq 'translation template exposes the inbound alert label' '1' "$got"
grep -A1 '^msgid "Inbound alert notification"$' "$po" | grep -q '^msgstr "入站警告提醒"$' && got=1 || got=0
assert_eq 'Simplified Chinese label is 入站警告提醒' '1' "$got"
grep -q "option inbound_alert '0'" "$config" && got=1 || got=0
assert_eq 'factory configuration keeps inbound alerts disabled' '1' "$got"

printf '%s tests, %s failures\n' "$((PASS + FAIL))" "$FAIL"
[ "$FAIL" -eq 0 ]
