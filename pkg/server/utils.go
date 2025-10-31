package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ClientIP 从 HTTP 请求中提取客户端的真实 IP 地址
// 优先使用 X-Forwarded-For 头，以支持反向代理部署
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SplitCSV 将逗号分隔的字符串切分为一个字符串数组，并去除空白
func SplitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// AllocateNameplate 生成一个新的、未被占用的密码牌
// 它会尝试最多1000次来避免随机数碰撞
func AllocateNameplate(db *ControlDB, digits int, ttl time.Duration, now time.Time, ip string) (string, time.Time, error) {
	max := big.NewInt(1)
	for i := 0; i < digits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	db.Lock()
	defer db.Unlock()

	for tries := 0; tries < 1000; tries++ {
		nBig, _ := rand.Int(rand.Reader, max)
		code := fmt.Sprintf("%0*d", digits, nBig.Int64())
		// 检查生成的 code 是否已被占用且未过期
		row, err := db.Load(code)
		if err == nil && !row.Expired(now) && row.Consumed == 0 {
			continue // 如果占用，则重试
		}
		// 尝试插入新记录，如果因为主键冲突失败，也会重试
		if err := db.InsertNew(code, ttl, now, ip); err != nil {
			continue
		}
		return code, now.UTC().Add(ttl), nil
	}
	return "", time.Time{}, fmt.Errorf("exhausted allocating nameplate")
}

// HostAddrsWithP2P 获取 libp2p host 的所有监听地址，并附加其 PeerID
func HostAddrsWithP2P(h host.Host) []string {
	pid := peer.ID(h.ID()).String()
	var out []string
	for _, a := range h.Addrs() {
		out = append(out, fmt.Sprintf("%s/p2p/%s", a, pid))
	}
	return out
}

// AddP2PIfMissing 确保一个 multiaddr 字符串包含 /p2p/<PeerID> 后缀
func AddP2PIfMissing(addr, pid string) string {
	if strings.Contains(addr, "/p2p/") {
		return addr
	}
	return fmt.Sprintf("%s/p2p/%s", addr, pid)
}

// AdvertisedAddrsWithP2P 决定服务器对外宣告的地址
// 如果用户通过 -public-addrs 标志指定了地址，则优先使用这些地址；否则，使用 host 自动检测到的监听地址
func AdvertisedAddrsWithP2P(h host.Host, publicAddrsCSV string) []string {
	pid := peer.ID(h.ID()).String()
	if strings.TrimSpace(publicAddrsCSV) == "" {
		return HostAddrsWithP2P(h)
	}
	raw := SplitCSV(publicAddrsCSV)
	var out []string
	for _, a := range raw {
		a = AddP2PIfMissing(a, pid)
		out = append(out, a)
	}
	return out
}

// RelayAddrsWithCircuit 将一组标准的 Peer 地址转换为 Relay 使用的 "circuit" 地址
// 例如: /ip4/1.2.3.4/tcp/4001/p2p/PeerID -> /ip4/1.2.3.4/tcp/4001/p2p/PeerID/p2p-circuit
func RelayAddrsWithCircuit(base []string) []string {
	out := make([]string, 0, len(base))
	for _, a := range base {
		if strings.Contains(a, "/p2p-circuit") {
			out = append(out, a)
		} else {
			out = append(out, a+"/p2p-circuit")
		}
	}
	return out
}
