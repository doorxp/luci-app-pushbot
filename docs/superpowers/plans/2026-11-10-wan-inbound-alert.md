# 外网入站连接告警 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 增加可配置的实时 WAN→LAN TCP/UDP 新连接推送，包含来源端点、协议、内网目标设备名和目标端点。

**Architecture:** 主脚本启动一个受控的 `conntrack -E -e NEW` 监听子进程，将事件写入 `/tmp/pushbot/` 队列；主循环逐批解析事件、从 firewall zone 与路由结果确认 WAN→LAN，再复用现有推送聚合与免打扰逻辑。解析和判定函数保持纯文本输入/输出，以便在非 OpenWrt 开发机上用夹具测试。

**Tech Stack:** POSIX/BusyBox shell、conntrack-tools、OpenWrt UCI/ubus、LuCI ucode/HTML JavaScript、gettext PO

**Spec:** `docs/superpowers/specs/2026-11-10-wan-inbound-alert-design.md`

## Global Constraints

- 同时支持 IPv4 DNAT 和 IPv6 直连。
- 仅推送已允许进入 LAN 的 TCP/UDP NEW 连接；不包含 INPUT、被拒绝流量和其他协议。
- 设备名顺序固定为 PushBot 别名、DHCP 主机名、“未知设备”，且始终保留目标 IP/端口。
- 开关位于“配置 → 推送内容”，名称为“入站警告提醒”，默认关闭。
- 保持 BusyBox/OpenWrt shell 兼容，不引入 conntrack 之外的新运行依赖。

## Review Focus

- IPv4 DNAT 元组的目标必须取 NAT 后内网地址/端口，而不是公网映射地址。
- IPv6 地址包含多个冒号，解析时不能按冒号拆分 IP 和端口。
- conntrack 输出字段缺失、顺序变化或协议非 TCP/UDP 时必须安全忽略。
- 重启、关闭开关和服务停止不能留下监听子进程，重复启动不能产生双重通知。
- 多 WAN、自定义 zone 名和自定义 LAN 名不能依赖 `wan`/`lan` 字面名称。

---

### Task 1: Conntrack 事件解析与方向判定

**Files:**
- Create: `tests/test_inbound_alert.sh`
- Modify: `root/usr/bin/pushbot/pushbot`

**Interfaces:**
- Produces: `parse_inbound_conntrack_event LINE`，成功时输出 `family protocol source_ip source_port target_ip target_port`；`inbound_route_is_wan_to_lan SOURCE_IP TARGET_IP` 以 firewall zone/路由设备判定方向；`resolve_inbound_target_name TARGET_IP` 输出设备名。

- [ ] 写夹具测试：IPv4 DNAT、IPv6 直连、UDP、非 TCP/UDP、字段缺失、LAN 出站、自定义 zone、多冒号 IPv6、别名/DHCP/未知设备。
- [ ] 运行 `sh tests/test_inbound_alert.sh`，确认因函数尚不存在而失败。
- [ ] 在主脚本实现最小解析、zone/路由判定和设备名解析函数。
- [ ] 再运行 `sh tests/test_inbound_alert.sh`，确认全部通过。
- [ ] 提交 `test: cover inbound conntrack event parsing` 和对应实现。

### Task 2: 监听生命周期与推送集成

**Files:**
- Modify: `tests/test_inbound_alert.sh`
- Modify: `root/usr/bin/pushbot/pushbot`
- Modify: `root/etc/init.d/pushbot`
- Modify: `Makefile`

**Interfaces:**
- Consumes: Task 1 的事件解析、方向判定和设备名解析函数。
- Produces: `start_inbound_listener`、`stop_inbound_listener`、`inbound_alert_send`；UCI 标量 `inbound_alert`。

- [ ] 扩展测试，覆盖默认关闭、监听命令只订阅 NEW、PID 单实例/清理、队列消费一次、免打扰键和完整消息字段。
- [ ] 运行测试并确认新增断言失败。
- [ ] 读取 `inbound_alert` 配置，管理 conntrack 子进程和事件队列，在主循环生成标题/内容并调用现有通知路径；init stop 同步清理监听器。
- [ ] 在 `LUCI_DEPENDS` 增加 `+conntrack`，并提升包 release。
- [ ] 运行定向测试和 shell 语法检查，确认通过。
- [ ] 提交 `feat: add WAN inbound connection alerts`。

### Task 3: LuCI 开关、保存链路与翻译

**Files:**
- Modify: `tests/test_inbound_alert.sh`
- Modify: `ucode/controller/pushbot.uc`
- Modify: `ucode/template/pushbot/pushbot_status.ut`
- Modify: `po/templates/pushbot.pot`
- Modify: `po/zh_Hans/pushbot.po`

**Interfaces:**
- Consumes: Task 2 的 UCI 标量 `inbound_alert`。
- Produces: “配置 → 推送内容”中的“入站警告提醒”开关及配置预览标签。

- [ ] 扩展测试，断言控制器读取该标量、表单收集该开关、开关位于 push content 卡片且中英文翻译条目存在。
- [ ] 运行测试并确认新增断言失败。
- [ ] 将 `inbound_alert` 加入控制器标量白名单、隐藏字段与配置预览，在推送内容卡片创建开关并补齐 gettext 条目。
- [ ] 运行定向测试、`sh -n root/usr/bin/pushbot/pushbot root/etc/init.d/pushbot` 和仓库可用的构建/静态检查。
- [ ] 运行 `git diff --check` 并审查完整 diff，确认默认值、重置配置和旧配置兼容。
- [ ] 提交 `feat: expose inbound alert setting in LuCI`。

