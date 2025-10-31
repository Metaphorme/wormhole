package p2p

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// PathInfo 存储关于连接路径的分类信息
type PathInfo struct {
	Kind       string // "DIRECT" 或 "RELAY"
	RelayID    string
	RelayVia   string
	Transport  string
	LocalAddr  string
	RemoteAddr string
}

// reRelayBeforeCircuit 用于从 multiaddr 中识别中继地址
var reRelayBeforeCircuit = regexp.MustCompile(`/p2p/([^/]+)/p2p-circuit`)

// TransportHint 从 multiaddr 中猜测传输协议类型
func TransportHint(a ma.Multiaddr) string {
	s := a.String()
	switch {
	case strings.Contains(s, "/webtransport/"):
		return "webtransport"
	case strings.Contains(s, "/webrtc-direct/"):
		return "webrtc-direct"
	case strings.Contains(s, "/quic-v1"):
		return "quic-v1"
	case strings.Contains(s, "/ws"):
		return "ws"
	case strings.Contains(s, "/tcp/"):
		return "tcp"
	case strings.Contains(s, "/udp/"):
		return "udp"
	default:
		return "unknown"
	}
}

// ClassifyPath 分析一个 libp2p 连接，判断它是直连还是通过中继
func ClassifyPath(c network.Conn) PathInfo {
	pi := PathInfo{
		LocalAddr:  c.LocalMultiaddr().String(),
		RemoteAddr: c.RemoteMultiaddr().String(),
	}
	rm := c.RemoteMultiaddr()
	lm := c.LocalMultiaddr()
	rs := rm.String()
	ls := lm.String()

	if m := reRelayBeforeCircuit.FindStringSubmatch(rs); len(m) == 2 {
		pi.Kind = "RELAY"
		pi.RelayID = m[1]
		pi.Transport = TransportHint(rm)
		pi.RelayVia = rs[:strings.Index(rs, "/p2p-circuit")]
		return pi
	}
	if m := reRelayBeforeCircuit.FindStringSubmatch(ls); len(m) == 2 {
		pi.Kind = "RELAY"
		pi.RelayID = m[1]
		pi.Transport = TransportHint(lm)
		pi.RelayVia = ls[:strings.Index(ls, "/p2p-circuit")]
		return pi
	}
	pi.Kind = "DIRECT"
	if strings.Contains(rs, "/p2p/") && !strings.Contains(rs, "/p2p-circuit") {
		pi.Transport = TransportHint(rm)
	} else {
		pi.Transport = TransportHint(lm)
	}
	return pi
}

// ParseAddrInfos 解析地址字符串列表为 peer.AddrInfo
func ParseAddrInfos(addrs []string) ([]peer.AddrInfo, error) {
	var out []peer.AddrInfo
	for _, s := range addrs {
		if strings.HasPrefix(s, "dnsaddr://") {
			// 跳过 dnsaddr，这里简化处理
			continue
		}
		maddr, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			continue
		}
		out = append(out, *ai)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid addresses")
	}
	return out, nil
}
