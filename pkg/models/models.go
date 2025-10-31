package models

import "time"

// AddrBundle 包含命名空间和一组地址，用于向客户端提供连接信息
type AddrBundle struct {
	Namespace string   `json:"namespace"`
	Addrs     []string `json:"addrs"`
}

// ConnectionInfo 封装了客户端建立 P2P 连接所需的所有信息
type ConnectionInfo struct {
	Rendezvous AddrBundle `json:"rendezvous"`          // Rendezvous 服务器信息
	Relay      AddrBundle `json:"relay"`               // Relay (中继) 服务器信息
	Bootstrap  []string   `json:"bootstrap,omitempty"` // 引导节点地址列表 (可选)
	Topic      string     `json:"topic"`               // 用于双方通信的 PubSub 主题
}

// AllocateResponse 是 /v1/allocate 接口的成功响应体
type AllocateResponse struct {
	Nameplate string    `json:"nameplate"`  // 新分配的密码牌
	ExpiresAt time.Time `json:"expires_at"` // 密码牌的过期时间
	ConnectionInfo
}

// ClaimRequest 是 /v1/claim 接口的请求体
type ClaimRequest struct {
	Nameplate string `json:"nameplate"` // 要认领的密码牌
	Side      string `json:"side"`      // 认领方 ("host" 或 "connect")
}

// ClaimResponse 是 /v1/claim 接口的响应体
type ClaimResponse struct {
	Status    string    `json:"status"`     // 认领后的状态 (waiting/paired/failed)
	ExpiresAt time.Time `json:"expires_at"` // 密码牌的过期时间
	ConnectionInfo
}

// ConsumeRequest 是 /v1/consume 接口的请求体
type ConsumeRequest struct {
	Nameplate string `json:"nameplate"`
}

// FailRequest 是 /v1/fail 接口的请求体
type FailRequest struct {
	Nameplate string `json:"nameplate"`
}

// PlateStatus 定义了密码牌（nameplate）的几种状态
type PlateStatus string

const (
	// StatusWaiting 表示密码牌已被一方认领，正在等待另一方
	StatusWaiting PlateStatus = "waiting"
	// StatusPaired 表示密码牌已被双方认领，配对成功
	StatusPaired PlateStatus = "paired"
	// StatusFailed 表示密码牌无效，原因可能是过期、已被消耗、认领失败等
	StatusFailed PlateStatus = "failed"
)

// Protocol IDs for libp2p
const (
	ProtoChat = "/wormhole/1.0.0/chat"
	ProtoXfer = "/wormhole/1.0.0/xfer"
)

// 聊天协议控制令牌
const (
	ChatHello  = "##HELLO"
	ChatAccept = "##ACCEPT"
	ChatReject = "##REJECT"
	ChatBye    = "##BYE"
)
