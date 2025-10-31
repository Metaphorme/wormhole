package client

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"net"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

// EFFWords 从嵌入的文本文件中解析 EFF 短词列表
func EFFWords(wordlistContent []byte) []string {
	lines := strings.Split(string(wordlistContent), "\n")
	words := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		tab := strings.Split(ln, "\t")
		if len(tab) >= 2 {
			words = append(words, tab[1])
		}
	}
	return words
}

// RandWord 从给定的单词列表中随机选择一个单词
func RandWord(ws []string) string {
	if len(ws) == 0 {
		return "word"
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ws))))
	return ws[nBig.Int64()]
}

// IsUnspecified 检查一个 multiaddr 是否是未指定地址 (如 0.0.0.0 或 ::)
func IsUnspecified(a ma.Multiaddr) bool {
	if v4, _ := a.ValueForProtocol(ma.P_IP4); v4 != "" {
		return v4 == "0.0.0.0"
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		return v6 == "::"
	}
	return false
}

// IsLoopbackOrPrivate 检查一个 multiaddr 是否是环回或私有地址
func IsLoopbackOrPrivate(a ma.Multiaddr) bool {
	if v4, _ := a.ValueForProtocol(ma.P_IP4); v4 != "" {
		ip := net.ParseIP(v4)
		if ip == nil {
			return false
		}
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		ip := net.ParseIP(v6)
		if ip == nil {
			return false
		}
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return false
}

// TransportHint 从 multiaddr 中提取传输层提示（如 "quic-v1", "ws", "tcp", "udp"）
func TransportHint(a ma.Multiaddr) string {
	protos := a.Protocols()
	for i := len(protos) - 1; i >= 0; i-- {
		switch protos[i].Name {
		case "quic-v1", "ws", "wss", "webtransport":
			return protos[i].Name
		case "tcp":
			return "tcp"
		case "udp":
			return "udp"
		}
	}
	return "unknown"
}
