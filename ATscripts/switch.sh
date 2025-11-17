#!/bin/bash
CONF_PATH="/etc/mihomo/config.yaml"
CORE_BIN="/usr/local/bin/mihomo"
SERVICE_NAME="mihomo"

# -----------------------
# 检查配置文件是否存在
# -----------------------
if [ ! -f "$CONF_PATH" ]; then
    echo "❌ 配置文件不存在: $CONF_PATH"
    exit 1
fi

# -----------------------
# 检测防火墙后端类型
# -----------------------
detect_firewall_backend() {
    if iptables --version 2>/dev/null | grep -q "nf_tables"; then
        echo "✅ 检测到 iptables-nft (兼容层)"
        FIREWALL_BACKEND="iptables-nft"
    elif iptables --version 2>/dev/null | grep -q "legacy"; then
        echo "✅ 检测到 iptables-legacy"
        FIREWALL_BACKEND="iptables-legacy"
    elif command -v nft >/dev/null 2>&1; then
        echo "✅ 检测到原生 nftables"
        FIREWALL_BACKEND="nft"
    else
        echo "⚠️ 未检测到可用防火墙 (iptables/nftables)"
        FIREWALL_BACKEND="none"
    fi
}


# 调用检测函数
detect_firewall_backend

# -----------------------
# 从 YAML 读取端口配置
# -----------------------
TPROXY_PORT_TCP=$(grep '^redir-port:' "$CONF_PATH" | awk '{print $2}')
TPROXY_PORT_UDP=$(grep '^tproxy-port:' "$CONF_PATH" | awk '{print $2}')

# 如果未检测到端口，则使用默认值
TPROXY_PORT_TCP=${TPROXY_PORT_TCP:-7892}
TPROXY_PORT_UDP=${TPROXY_PORT_UDP:-7893}

echo "📦 检测到 redir-port: $TPROXY_PORT_TCP"
echo "📦 检测到 tproxy-port: $TPROXY_PORT_UDP"

# -----------------------
# 检测当前模式
# -----------------------
if grep -qE '^tun:\s*\n\s*enable:\s*true' "$CONF_PATH"; then
    CURRENT_MODE="tun"
else
    CURRENT_MODE="tproxy"
fi

echo "🔍 当前模式: $CURRENT_MODE"

# -----------------------
# 切换逻辑
# -----------------------
if [ "$CURRENT_MODE" = "tun" ]; then
    echo "🌀 切换到 TProxy 模式..."
    
    # 修改 YAML: 关闭 tun，启用 redir/tproxy 端口
    sed -i 's/^tun:\s*\n\s*enable:\s*true/tun:\n  enable: false/' "$CONF_PATH"

    # 确保 redir/tproxy-port 存在
    grep -q '^redir-port:' "$CONF_PATH" || echo "redir-port: $TPROXY_PORT_TCP" >> "$CONF_PATH"
    grep -q '^tproxy-port:' "$CONF_PATH" || echo "tproxy-port: $TPROXY_PORT_UDP" >> "$CONF_PATH"

    # 添加 iptables 规则
    echo "🔧 应用防火墙规则..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    LOCAL_NET=$(ip route | awk '/proto kernel/ {print $1; exit}')
    IFACE=$(ip route | grep default | awk '{print $5}')
    echo "检测到接口: $IFACE"
    echo "排除本地网段: $LOCAL_NET"

    case "$FIREWALL_BACKEND" in
        nft|iptables-nft)
            echo "使用 nftables 配置 TProxy 规则..."
            nft flush table inet tproxy 2>/dev/null || true
            nft delete table inet tproxy 2>/dev/null || true
            nft add table inet tproxy
            nft 'add chain inet tproxy prerouting { type filter hook prerouting priority mangle; policy accept; }'
            nft add rule inet tproxy prerouting ip saddr "$LOCAL_NET" return
            nft add rule inet tproxy prerouting meta l4proto tcp tproxy to :"$TPROXY_PORT_TCP" mark set 1
            nft add rule inet tproxy prerouting meta l4proto udp tproxy to :"$TPROXY_PORT_UDP" mark set 1
            ;;
        iptables-legacy)
            echo "使用传统 iptables 配置 TProxy 规则..."
            iptables -t mangle -F
            iptables -t mangle -A PREROUTING -s "$LOCAL_NET" -j RETURN
            iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port "$TPROXY_PORT_TCP" --tproxy-mark 0x1/0x1
            iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port "$TPROXY_PORT_UDP" --tproxy-mark 0x1/0x1
            ;;
        *)
            echo "❌ 无法应用防火墙规则，请检查防火墙环境。"
            exit 1
            ;;
    esac

    ip rule add fwmark 1 lookup 100 2>/dev/null
    ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null

    echo "✅ 已切换到 TProxy 模式"

else
    echo "🌀 切换到 TUN 模式..."
    
    # 修改 YAML: 启用 tun 并关闭 redir/tproxy
    if grep -q '^tun:' "$CONF_PATH"; then
        sed -i '/^tun:/,/^$/ s/enable:.*/enable: true/' "$CONF_PATH"
    else
        cat <<EOF >> "$CONF_PATH"

tun:
  enable: true
  stack: system
  device: mihomo-tun0
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
EOF
    fi

    # 注释掉 redir/tproxy-port
    sed -i 's/^redir-port:/# redir-port:/' "$CONF_PATH"
    sed -i 's/^tproxy-port:/# tproxy-port:/' "$CONF_PATH"

    # 清理 iptables
    echo "🧹 清理 iptables..."
    iptables -t mangle -F
    if command -v nft >/dev/null 2>&1; then
        nft flush table inet tproxy || true
    fi

    echo "✅ 已切换到 TUN 模式"
fi

# -----------------------
# 重启 Mihomo 服务
# -----------------------
echo "🔁 重启 Mihomo..."
if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
    systemctl restart "$SERVICE_NAME"
else
    pkill -f "$CORE_BIN"
    nohup "$CORE_BIN" -d /etc/mihomo/ -f "$CONF_PATH" >/var/log/mihomo.log 2>&1 &
fi

sleep 2
if pgrep -f "$CORE_BIN" >/dev/null; then
    echo "✅ Mihomo 已启动"
else
    echo "❌ 启动失败，请检查日志 /var/log/mihomo.log"
fi

echo "🎯 模式切换完成。"
