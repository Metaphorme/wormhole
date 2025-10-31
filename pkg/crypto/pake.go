package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"golang.org/x/crypto/hkdf"
	spake2 "salsa.debian.org/vasudev/gospake2"
	_ "salsa.debian.org/vasudev/gospake2/ed25519group"
)

// BuildTranscript 构建一个唯一的会话摘要，用于密钥派生和确认
// 它将双方的 PeerID 按字典序排序，以确保双方生成相同的摘要
func BuildTranscript(nameplate string, proto protocol.ID, a, b peer.ID) []byte {
	ids := []string{a.String(), b.String()}
	if ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	s := strings.Join([]string{"wormhole-pake-v1", nameplate, string(proto), ids[0], ids[1]}, "|")
	return []byte(s)
}

// HkdfBytes 使用 HKDF 从输入密钥材料(ikm)派生出指定长度的密钥
func HkdfBytes(ikm []byte, label string, transcript []byte, n int) []byte {
	info := append([]byte(label+"|"), transcript...)
	r := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	_, _ = io.ReadFull(r, out)
	return out
}

// EmojiList 返回用于 SAS 的 emoji 列表
func EmojiList() []string {
	return []string{
		"😀", "😂", "😅", "😊", "😍", "😎", "🤔", "😴",
		"😇", "🙃", "🤓", "😼", "🤖", "👻", "💩", "👾",
		"🦄", "🐶", "🐱", "🐼", "🐧", "🐸", "🦊", "🦁",
		"🌞", "🌙", "⭐", "⚡", "🔥", "🌈", "❄️", "💧",
		"🍕", "🍔", "🍟", "🎂", "☕", "🍺", "🎈", "🎲",
		"🎵", "🎧", "🎮", "📷", "💡", "🔌", "🔋", "🔧",
		"⚙️", "🧲", "🌋", "⛰️", "🌳", "🌻", "🍄", "🍎",
		"🍇", "🍋", "🍪", "🍫", "🍦", "🍩", "🍭", "🥐",
	}
}

// SASFromKey 从共享密钥生成一个短认证字符串(SAS)，由5个 emoji 组成，用于人工验证
func SASFromKey(K []byte, transcript []byte) string {
	em := EmojiList()
	b := HkdfBytes(K, "sas", transcript, 4) // 派生32位数据
	acc := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	parts := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		idx := (acc >> (i * 6)) & 0x3F // 每6位映射一个 emoji
		parts = append(parts, em[idx%uint32(len(em))])
	}
	return strings.Join(parts, " ")
}

// PAKEState 封装了 SPAKE2 状态和配置信息
type PAKEState struct {
	state      spake2.SPAKE2
	transcript []byte
	roleA      bool
}

// NewPAKEState 创建一个新的 PAKE 状态
// roleA=true 表示是发起方(Dialer)
func NewPAKEState(roleA bool, passphrase, nameplate string, proto protocol.ID, local, remote peer.ID) *PAKEState {
	transcript := BuildTranscript(nameplate, proto, local, remote)
	pw := spake2.NewPassword(passphrase)
	var state spake2.SPAKE2
	if roleA {
		state = spake2.SPAKE2A(pw, spake2.NewIdentityA(local.String()), spake2.NewIdentityB(remote.String()))
	} else {
		state = spake2.SPAKE2B(pw, spake2.NewIdentityA(remote.String()), spake2.NewIdentityB(local.String()))
	}
	return &PAKEState{
		state:      state,
		transcript: transcript,
		roleA:      roleA,
	}
}

// Start 启动 PAKE 协商并返回要发送给对方的消息
func (p *PAKEState) Start() []byte {
	return p.state.Start()
}

// Finish 使用对方的消息完成 PAKE 协商，返回共享密钥
func (p *PAKEState) Finish(peerMsg []byte) ([]byte, error) {
	K, err := p.state.Finish(peerMsg)
	if err != nil {
		return nil, fmt.Errorf("pake finish: %w", err)
	}
	return K, nil
}

// ComputeConfirmTag 计算密钥确认 MAC 标签
func (p *PAKEState) ComputeConfirmTag(K []byte, side string) []byte {
	Kc := HkdfBytes(K, "confirm", p.transcript, 32)
	mac := hmac.New(sha256.New, Kc)
	mac.Write([]byte(side + "|"))
	mac.Write(p.transcript)
	return mac.Sum(nil)
}

// VerifyConfirmTag 验证对方的密钥确认 MAC 标签
func (p *PAKEState) VerifyConfirmTag(K []byte, side string, tag []byte) bool {
	expected := p.ComputeConfirmTag(K, side)
	return hmac.Equal(expected, tag)
}

// GetTranscript 返回会话摘要
func (p *PAKEState) GetTranscript() []byte {
	return p.transcript
}

// IsRoleA 返回是否为发起方角色
func (p *PAKEState) IsRoleA() bool {
	return p.roleA
}
