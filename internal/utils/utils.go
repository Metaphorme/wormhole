package utils

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

// Min64 返回两个 int64 中的较小值
func Min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

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
		ip := parseIP(v4)
		if ip == nil {
			return false
		}
		return isLoopback(ip) || isPrivate(ip)
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		ip := parseIP(v6)
		if ip == nil {
			return false
		}
		return isLoopback(ip) || isPrivate(ip)
	}
	return false
}

// 简单的 IP 解析和检查函数（避免依赖 net 包的具体实现）
func parseIP(s string) []byte {
	// 这是一个简化版本，实际使用时应该用 net.ParseIP
	// 这里只是为了演示结构
	return []byte(s)
}

func isLoopback(ip []byte) bool {
	// 简化实现
	s := string(ip)
	return strings.HasPrefix(s, "127.") || s == "::1"
}

func isPrivate(ip []byte) bool {
	// 简化实现
	s := string(ip)
	return strings.HasPrefix(s, "10.") ||
		strings.HasPrefix(s, "192.168.") ||
		strings.HasPrefix(s, "172.16.") ||
		strings.HasPrefix(s, "fc") || strings.HasPrefix(s, "fd")
}
