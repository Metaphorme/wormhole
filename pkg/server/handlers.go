package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Metaphorme/wormhole/pkg/models"
)

// HTTPHandlers 封装了 HTTP 处理器所需的依赖
type HTTPHandlers struct {
	DB             *ControlDB
	Limiter        *IPLimiter
	RzvNamespace   string
	AdvertisedAddr []string
	RelayAddrs     []string
	Bootstrap      []string
	TTL            time.Duration
	Digits         int
}

// NewHTTPHandlers 创建 HTTP 处理器实例
func NewHTTPHandlers(db *ControlDB, limiter *IPLimiter, rzvNamespace string, advertisedAddr, relayAddrs, bootstrap []string, ttl time.Duration, digits int) *HTTPHandlers {
	return &HTTPHandlers{
		DB:             db,
		Limiter:        limiter,
		RzvNamespace:   rzvNamespace,
		AdvertisedAddr: advertisedAddr,
		RelayAddrs:     relayAddrs,
		Bootstrap:      bootstrap,
		TTL:            ttl,
		Digits:         digits,
	}
}

// WithRateLimit 是一个中间件，用于在处理请求前进行频率检查
func (h *HTTPHandlers) WithRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		ok, wait := h.Limiter.Allow(ip, time.Now())
		if !ok {
			// 如果请求被限制，返回 429 Too Many Requests，并附带 Retry-After 头
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// HandleAllocate 处理 /v1/allocate 接口 - 分配一个新的密码牌
func (h *HTTPHandlers) HandleAllocate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := ClientIP(r)
	np, exp, err := AllocateNameplate(h.DB, h.Digits, h.TTL, time.Now(), ip)
	if err != nil {
		http.Error(w, "allocate failed", http.StatusInternalServerError)
		return
	}
	resp := models.AllocateResponse{
		Nameplate: np,
		ExpiresAt: exp,
		ConnectionInfo: models.ConnectionInfo{
			Rendezvous: models.AddrBundle{Namespace: h.RzvNamespace, Addrs: h.AdvertisedAddr},
			Relay:      models.AddrBundle{Namespace: "circuit-relay-v2", Addrs: h.RelayAddrs},
			Bootstrap:  h.Bootstrap,
			Topic:      fmt.Sprintf("/wormhole/%s", np),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleClaim 处理 /v1/claim 接口 - 认领一个密码牌的其中一侧
func (h *HTTPHandlers) HandleClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req models.ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 对于无效的请求，记录一次失败操作
		h.Limiter.RecordFail(ClientIP(r), time.Now())
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Nameplate == "" || req.Side == "" {
		h.Limiter.RecordFail(ClientIP(r), time.Now())
		http.Error(w, "nameplate & side required", http.StatusBadRequest)
		return
	}

	ip := ClientIP(r)
	st, row, err := h.DB.Claim(req.Nameplate, req.Side, time.Now(), ip)
	if err != nil {
		http.Error(w, "claim failed", http.StatusInternalServerError)
		return
	}

	// 统一构造过期时间：如果 row 为 nil (密码牌不存在)，则使用当前时间，避免泄露信息
	var exp time.Time
	if row != nil {
		exp = time.Unix(row.CreatedAt, 0).UTC().Add(time.Duration(row.TTLSeconds) * time.Second)
	} else {
		exp = time.Now().UTC()
	}

	// 如果认领结果是 failed，将此 IP 计入失败窗口
	if st == StatusFailed {
		h.Limiter.RecordFail(ip, time.Now())
	}

	resp := models.ClaimResponse{
		Status:    string(st),
		ExpiresAt: exp,
		ConnectionInfo: models.ConnectionInfo{
			Rendezvous: models.AddrBundle{Namespace: h.RzvNamespace, Addrs: h.AdvertisedAddr},
			Relay:      models.AddrBundle{Namespace: "circuit-relay-v2", Addrs: h.RelayAddrs},
			Bootstrap:  h.Bootstrap,
			Topic:      fmt.Sprintf("/wormhole/%s", req.Nameplate),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleConsume 处理 /v1/consume 接口 - 客户端报告连接成功，将密码牌标记为已消耗
func (h *HTTPHandlers) HandleConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req models.ConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Nameplate == "" {
		http.Error(w, "nameplate required", http.StatusBadRequest)
		return
	}
	if err := h.DB.Consume(req.Nameplate); err != nil {
		http.Error(w, "consume failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// HandleFail 处理 /v1/fail 接口 - 客户端报告连接失败，将密码牌标记为作废
func (h *HTTPHandlers) HandleFail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req models.FailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Nameplate == "" {
		http.Error(w, "nameplate required", http.StatusBadRequest)
		return
	}
	if err := h.DB.FailAndConsume(req.Nameplate); err != nil {
		http.Error(w, "fail-and-consume failed", http.StatusInternalServerError)
		return
	}
	// 即使密码牌之前已经作废，也返回成功，使客户端逻辑更简单
	WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// WriteJSON 是一个辅助函数，用于将数据结构序列化为 JSON 并写入 HTTP 响应
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSON 是 WriteJSON 的别名（为了向后兼容）
func writeJSON(w http.ResponseWriter, code int, v any) {
	WriteJSON(w, code, v)
}
