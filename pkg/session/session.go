package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Metaphorme/wormhole/pkg/crypto"
	"github.com/Metaphorme/wormhole/pkg/models"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// 帧类型定义
const (
	FramePakeMsg     = byte(0x10)
	FramePakeConfirm = byte(0x11)
	FramePakeAbort   = byte(0x1F)
)

// WriteFrame 写入一个简单的帧（类型 + 内容）
func WriteFrame(s network.Stream, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	// 这里使用 binary.BigEndian.PutUint32 会更好，但为了简化先这样
	l := uint32(len(payload))
	hdr[1] = byte(l >> 24)
	hdr[2] = byte(l >> 16)
	hdr[3] = byte(l >> 8)
	hdr[4] = byte(l)
	if _, err := s.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame 读取一个帧
func ReadFrame(s network.Stream) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	length := uint32(hdr[1])<<24 | uint32(hdr[2])<<16 | uint32(hdr[3])<<8 | uint32(hdr[4])
	if length == 0 {
		return typ, nil, nil
	}
	if length > 64*1024*1024 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(s, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// RunPAKEAndConfirm 执行 SPAKE2 密钥协商和密钥确认流程
func RunPAKEAndConfirm(ctx context.Context, s network.Stream, roleA bool, passphrase, nameplate string, proto protocol.ID, local, remote peer.ID) ([]byte, error) {
	pakeState := crypto.NewPAKEState(roleA, passphrase, nameplate, proto, local, remote)
	my := pakeState.Start()

	if roleA {
		// 发起方流程
		if err := WriteFrame(s, FramePakeMsg, my); err != nil {
			return nil, err
		}
		typ, peerMsg, err := ReadFrame(s)
		if err != nil || typ != FramePakeMsg {
			return nil, fmt.Errorf("pake: bad peer msg")
		}
		K, err := pakeState.Finish(peerMsg)
		if err != nil {
			return nil, err
		}
		tagA := pakeState.ComputeConfirmTag(K, "A")
		if err := WriteFrame(s, FramePakeConfirm, tagA); err != nil {
			return nil, err
		}
		typ, tagB, err := ReadFrame(s)
		if err != nil || typ != FramePakeConfirm {
			return nil, fmt.Errorf("pake: no cB")
		}
		if !pakeState.VerifyConfirmTag(K, "B", tagB) {
			_ = WriteFrame(s, FramePakeAbort, nil)
			return nil, fmt.Errorf("pake: key-confirm failed (cB)")
		}
		return K, nil
	} else {
		// 响应方流程
		typ, peerMsg, err := ReadFrame(s)
		if err != nil || typ != FramePakeMsg {
			return nil, fmt.Errorf("pake: bad peer msg")
		}
		K, err := pakeState.Finish(peerMsg)
		if err != nil {
			return nil, err
		}
		if err := WriteFrame(s, FramePakeMsg, my); err != nil {
			return nil, err
		}
		typ, tagA, err := ReadFrame(s)
		if err != nil || typ != FramePakeConfirm {
			return nil, fmt.Errorf("pake: no cA")
		}
		if !pakeState.VerifyConfirmTag(K, "A", tagA) {
			_ = WriteFrame(s, FramePakeAbort, nil)
			return nil, fmt.Errorf("pake: key-confirm failed (cA)")
		}
		tagB := pakeState.ComputeConfirmTag(K, "B")
		if err := WriteFrame(s, FramePakeConfirm, tagB); err != nil {
			return nil, err
		}
		return K, nil
	}
}

// ReadLineWithDeadline 从流中读取一行，带有超时
func ReadLineWithDeadline(rw *bufio.ReadWriter, s network.Stream, d time.Duration) (string, error) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	defer s.SetReadDeadline(time.Time{})
	line, err := rw.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// HelpText 返回帮助文本
func HelpText() string {
	return `Commands:
/peer                  show peer id & current path
/send -f <file>        send a file
/send -d <dir>         send a directory recursively
/bye                   close the chat`
}

// PostConsumeAsync 异步向控制服务器报告会话成功
func PostConsumeAsync(controlURL, nameplate string) {
	go func() {
		// 这里应该调用 api.Client
		// 简化实现，实际应该使用 pkg/api
		_ = controlURL
		_ = nameplate
	}()
}

// PostFailAsync 异步向控制服务器报告会话失败
func PostFailAsync(controlURL, nameplate string) {
	go func() {
		_ = controlURL
		_ = nameplate
	}()
}

// IsValidChatCommand 检查是否是聊天命令
func IsValidChatCommand(line string) bool {
	return line == models.ChatHello || line == models.ChatAccept ||
		line == models.ChatReject || line == models.ChatBye
}
