package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	rzv "github.com/waku-org/go-libp2p-rendezvous"
	rzvsqlite "github.com/waku-org/go-libp2p-rendezvous/db/sqlite"

	_ "modernc.org/sqlite" // 引入 CGO-free 的 SQLite 驱动
)

// -------------------- 控制面数据库结构与操作 --------------------

// plateStatus 定义了密码牌（nameplate）的几种状态。
type plateStatus string

const (
	// statusWaiting 表示密码牌已被一方认领，正在等待另一方。
	statusWaiting plateStatus = "waiting"
	// statusPaired 表示密码牌已被双方认领，配对成功。
	statusPaired plateStatus = "paired"
	// statusFailed 表示密码牌无效，原因可能是过期、已被消耗、认领失败等。
	// 注意：对客户端隐藏了 "expired" 状态，统一返回 "failed"，以简化客户端逻辑。
	statusFailed plateStatus = "failed"
)

// nameplateRow 对应数据库中 nameplates 表的一行记录。
type nameplateRow struct {
	Nameplate   string         // 密码牌，即客户端使用的短码。
	CreatedAt   int64          // 创建时间的 Unix 时间戳 (UTC)。
	TTLSeconds  int64          // 有效期，单位秒。
	ClaimedMask int64          // 认领状态掩码：bit0 代表 host(A)，bit1 代表 connect(B)。当值为3时表示双方都已认领。
	Consumed    int64          // 是否已被消耗（成功建立连接后由客户端报告）。0 表示未消耗，1 表示已消耗。
	FailCount   int64          // 失败计数器，用于记录无效认领等失败操作的次数。
	LastIP      sql.NullString // 最后一次操作该记录的客户端 IP。
}

// controlDB 是控制面数据库的封装，包含一个互斥锁以支持并发操作。
type controlDB struct {
	mu sync.Mutex
	db *sql.DB
}

// openControlDB 打开或创建一个 SQLite 数据库文件，并进行初始化配置。
func openControlDB(path string) (*controlDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 启用 WAL (Write-Ahead Logging) 模式，可以显著提高并发写入性能。
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	// 设置忙碌超时时间，当数据库被锁定时，连接会等待最多5秒而不是立即返回错误。
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	// 定义并执行数据库表结构（如果表不存在）。
	schema := `
CREATE TABLE IF NOT EXISTS nameplates(
  nameplate TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  claimed_mask INTEGER NOT NULL DEFAULT 0,
  consumed INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_nameplates_created ON nameplates(created_at);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &controlDB{db: db}, nil
}

// close 关闭数据库连接。
func (c *controlDB) close() error { return c.db.Close() }

// insertNew 向数据库中插入一条新的密码牌记录。
func (c *controlDB) insertNew(nameplate string, ttl time.Duration, now time.Time, ip string) error {
	_, err := c.db.Exec(`INSERT INTO nameplates(nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip)
VALUES(?, ?, ?, 0, 0, 0, ?)`, nameplate, now.UTC().Unix(), int64(ttl/time.Second), ip)
	return err
}

// load 从数据库加载指定密码牌的信息。
func (c *controlDB) load(nameplate string) (*nameplateRow, error) {
	row := c.db.QueryRow(`SELECT nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip FROM nameplates WHERE nameplate=?`, nameplate)
	var r nameplateRow
	if err := row.Scan(&r.Nameplate, &r.CreatedAt, &r.TTLSeconds, &r.ClaimedMask, &r.Consumed, &r.FailCount, &r.LastIP); err != nil {
		return nil, err
	}
	return &r, nil
}

// expired 判断密码牌在给定的时间点是否已过期。
func (r *nameplateRow) expired(at time.Time) bool {
	expires := time.Unix(r.CreatedAt, 0).UTC().Add(time.Duration(r.TTLSeconds) * time.Second)
	return at.UTC().After(expires)
}

// incrFail 增加指定密码牌的失败计数。
func (c *controlDB) incrFail(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET fail_count = fail_count + 1 WHERE nameplate=?`, nameplate)
	return err
}

// delete 从数据库中删除指定的密码牌。
func (c *controlDB) delete(nameplate string) error {
	_, err := c.db.Exec(`DELETE FROM nameplates WHERE nameplate=?`, nameplate)
	return err
}

// failAndConsume 将密码牌标记为已消耗，并原子地增加失败计数（仅当之前未被消耗时）。
// 这个操作是幂等的，用于客户端报告连接失败的场景。
func (c *controlDB) failAndConsume(nameplate string) error {
	_, err := c.db.Exec(`
        UPDATE nameplates
           SET fail_count = fail_count + CASE WHEN consumed=0 THEN 1 ELSE 0 END,
               consumed   = 1
         WHERE nameplate = ?`, nameplate)
	return err
}

// claim 处理客户端的认领请求，是核心业务逻辑之一。
// 它会检查密码牌的有效性，处理重复认领和无效 side 的情况，并更新认领状态。
// 如果密码牌已过期，会直接从数据库删除。
func (c *controlDB) claim(nameplate, side string, now time.Time, ip string) (plateStatus, *nameplateRow, error) {
	r, err := c.load(nameplate)
	if err != nil {
		// 如果密码牌不存在，直接返回 failed 状态。
		if errors.Is(err, sql.ErrNoRows) {
			return statusFailed, nil, nil
		}
		return "", nil, err
	}
	// 如果密码牌已过期，删除它并返回 failed。
	if r.expired(now) {
		_ = c.delete(nameplate)
		return statusFailed, nil, nil
	}
	// 如果密码牌已被消耗，返回 failed。
	if r.Consumed != 0 {
		return statusFailed, r, nil
	}

	var bit int64
	switch strings.ToLower(side) {
	case "host", "a":
		bit = 1 // bit0 for host side
	case "connect", "b":
		bit = 2 // bit1 for connect side
	default:
		// 无效的 side 参数，增加失败计数并返回 failed。
		_ = c.incrFail(nameplate)
		return statusFailed, r, nil
	}

	newMask := r.ClaimedMask | bit
	if newMask == r.ClaimedMask {
		// 重复认领同一侧，视为失败操作，增加失败计数。
		_ = c.incrFail(nameplate)
		return statusFailed, r, nil
	}

	// 更新数据库中的认领掩码和最后操作IP。
	if _, err := c.db.Exec(`UPDATE nameplates SET claimed_mask=?, last_ip=? WHERE nameplate=?`, newMask, ip, nameplate); err != nil {
		return "", nil, err
	}
	r.ClaimedMask = newMask
	r.LastIP = sql.NullString{String: ip, Valid: true}

	if newMask == 3 { // bit0 和 bit1 都被设置，表示双方都已认领。
		return statusPaired, r, nil
	}
	return statusWaiting, r, nil
}

// consume 将密码牌标记为已消耗，通常在客户端成功建立连接后调用。
func (c *controlDB) consume(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET consumed=1 WHERE nameplate=?`, nameplate)
	return err
}

// cleanupExpired 定期清理数据库中已过期或已消耗的密码牌记录。
func (c *controlDB) cleanupExpired(now time.Time) (int64, error) {
	res, err := c.db.Exec(`DELETE FROM nameplates WHERE (created_at + ttl_seconds) < ? OR consumed=1`, now.UTC().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// -------------------- HTTP 控制面接口定义 --------------------

// addrBundle 包含命名空间和一组地址，用于向客户端提供连接信息。
type addrBundle struct {
	Namespace string   `json:"namespace"`
	Addrs     []string `json:"addrs"`
}

// ConnectionInfo 封装了客户端建立 P2P 连接所需的所有信息。
type ConnectionInfo struct {
	Rendezvous addrBundle `json:"rendezvous"`          // Rendezvous 服务器信息
	Relay      addrBundle `json:"relay"`               // Relay (中继) 服务器信息
	Bootstrap  []string   `json:"bootstrap,omitempty"` // 引导节点地址列表 (可选)
	Topic      string     `json:"topic"`               // 用于双方通信的 PubSub 主题
}

// allocateResponse 是 /v1/allocate 接口的成功响应体。
type allocateResponse struct {
	Nameplate string    `json:"nameplate"`  // 新分配的密码牌
	ExpiresAt time.Time `json:"expires_at"` // 密码牌的过期时间
	ConnectionInfo
}

// claimRequest 是 /v1/claim 接口的请求体。
type claimRequest struct {
	Nameplate string `json:"nameplate"` // 要认领的密码牌
	Side      string `json:"side"`      // 认领方 ("host" 或 "connect")
}

// claimResponse 是 /v1/claim 接口的响应体。
type claimResponse struct {
	Status    plateStatus `json:"status"`     // 认领后的状态 (waiting/paired/failed)
	ExpiresAt time.Time   `json:"expires_at"` // 密码牌的过期时间
	ConnectionInfo
}

// consumeRequest 是 /v1/consume 接口的请求体。
type consumeRequest struct {
	Nameplate string `json:"nameplate"`
}

// failRequest 是 /v1/fail 接口的请求体。
type failRequest struct {
	Nameplate string `json:"nameplate"`
}

// writeJSON 是一个辅助函数，用于将数据结构序列化为 JSON 并写入 HTTP 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 从 HTTP 请求中提取客户端的真实 IP 地址。
// 优先使用 X-Forwarded-For 头，以支持反向代理部署。
func clientIP(r *http.Request) string {
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

// -------------------- 简单的 IP 维度频率控制器 --------------------

// ipLimiter 实现了一个基于 IP 的频率限制器。
// 它同时跟踪两个滑动窗口：一个是总请求频率，另一个是失败操作频率。
type ipLimiter struct {
	mu         sync.Mutex
	reqs       map[string][]time.Time // 记录每个 IP 的请求时间戳
	fails      map[string][]time.Time // 记录每个 IP 的失败操作时间戳
	reqWindow  time.Duration          // 请求频率的统计窗口
	maxReqs    int                    // 窗口内最大请求数
	failWindow time.Duration          // 失败频率的统计窗口
	maxFails   int                    // 窗口内最大失败数
}

// newIPLimiter 创建一个新的 IP 频率限制器实例。
func newIPLimiter(reqWindow time.Duration, maxReqs int, failWindow time.Duration, maxFails int) *ipLimiter {
	return &ipLimiter{
		reqs:       make(map[string][]time.Time),
		fails:      make(map[string][]time.Time),
		reqWindow:  reqWindow,
		maxReqs:    maxReqs,
		failWindow: failWindow,
		maxFails:   maxFails,
	}
}

// pruneLocked 清理两个map中已经移出滑动窗口的旧时间戳。
// 这个方法不是线程安全的，需要在锁的保护下调用。
func (l *ipLimiter) pruneLocked(now time.Time) {
	// 清理请求记录
	for ip, arr := range l.reqs {
		j := 0
		for _, t := range arr {
			if now.Sub(t) <= l.reqWindow {
				arr[j] = t
				j++
			}
		}
		if j == 0 {
			delete(l.reqs, ip)
		} else {
			l.reqs[ip] = arr[:j]
		}
	}
	// 清理失败记录
	for ip, arr := range l.fails {
		j := 0
		for _, t := range arr {
			if now.Sub(t) <= l.failWindow {
				arr[j] = t
				j++
			}
		}
		if j == 0 {
			delete(l.fails, ip)
		} else {
			l.fails[ip] = arr[:j]
		}
	}
}

// allow 判断来自特定 IP 的请求是否应该被允许。
// 如果不允许，它会返回 false 和一个建议的等待时间。
func (l *ipLimiter) allow(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	// 检查总请求频率
	arr := append(l.reqs[ip], now)
	l.reqs[ip] = arr
	if len(arr) > l.maxReqs {
		// 计算建议等待时间：等待直到最早的请求移出窗口
		wait := l.reqWindow - now.Sub(arr[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}

	// 检查失败操作频率
	if fails := l.fails[ip]; len(fails) > l.maxFails {
		wait := l.failWindow - now.Sub(fails[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}

	return true, 0
}

// recordFail 记录一次来自特定 IP 的失败操作。
func (l *ipLimiter) recordFail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	l.fails[ip] = append(l.fails[ip], now)
}

// -------------------- 服务器主程序 --------------------

func main() {
	// --- 命令行参数定义 ---
	var listenAddrs string
	var dbPath string
	var ctrlListen string
	var rzvNamespace string
	var ttlStr string
	var digits int
	var bootstrapCSV string
	var publicAddrsCSV string
	var identityPath string
	// 频率控制相关参数
	var rateReqWindowStr string
	var rateMaxReqs int
	var rateFailWindowStr string
	var rateMaxFails int

	flag.StringVar(&listenAddrs, "listen", "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4002/ws", "comma-separated multiaddrs for libp2p")
	flag.StringVar(&dbPath, "db", "./wormhole.db", "sqlite path used by BOTH rendezvous and control-plane")
	flag.StringVar(&ctrlListen, "control-listen", ":8080", "http control-plane listen addr")
	flag.StringVar(&rzvNamespace, "rendezvous-namespace", "wormhole", "rendezvous namespace")
	flag.StringVar(&ttlStr, "nameplate-ttl", "30m", "nameplate TTL, e.g. 10m/30m")
	flag.IntVar(&digits, "nameplate-digits", 3, "nameplate digits (3-4 recommended)")
	flag.StringVar(&bootstrapCSV, "bootstrap", "", "comma-separated bootstrap dnsaddr/multiaddrs (optional)")
	flag.StringVar(&publicAddrsCSV, "public-addrs", "", "comma-separated public announce addrs (multiaddr/dnsaddr). If set, overrides automatic hostAddrs")
	flag.StringVar(&identityPath, "identity", "./server.key", "path to persist libp2p private key")
	flag.StringVar(&rateReqWindowStr, "rate-req-window", "1m", "per-IP request rate window")
	flag.IntVar(&rateMaxReqs, "rate-max-reqs", 120, "max requests per IP within req-window")
	flag.StringVar(&rateFailWindowStr, "rate-fail-window", "10m", "per-IP failures window")
	flag.IntVar(&rateMaxFails, "rate-max-fails", 30, "max failures per IP within fail-window")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- 参数解析与校验 ---
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil || ttl <= 0 {
		log.Fatalf("invalid -nameplate-ttl: %v", err)
	}
	if digits < 3 || digits > 4 {
		log.Fatalf("invalid -nameplate-digits, want 3..4")
	}
	reqWin, err := time.ParseDuration(rateReqWindowStr)
	if err != nil || reqWin <= 0 {
		log.Fatalf("invalid -rate-req-window")
	}
	failWin, err := time.ParseDuration(rateFailWindowStr)
	if err != nil || failWin <= 0 {
		log.Fatalf("invalid -rate-fail-window")
	}
	ipRate := newIPLimiter(reqWin, rateMaxReqs, failWin, rateMaxFails)

	// --- Libp2p Host 初始化 ---
	// 加载或创建持久化的私钥，以确保服务器有固定的 PeerID。
	priv, err := loadOrCreateIdentity(identityPath)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}

	var addrs []ma.Multiaddr
	for _, s := range strings.Split(listenAddrs, ",") {
		a, err := ma.NewMultiaddr(strings.TrimSpace(s))
		if err != nil {
			log.Fatalf("bad multiaddr %q: %v", s, err)
		}
		addrs = append(addrs, a)
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(ws.New),
		libp2p.Transport(quic.NewTransport),
		libp2p.ListenAddrs(addrs...),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		// 启用 Relay v2 的 "hop" 服务，使该节点可以作为公共中继节点。
		libp2p.EnableRelayService(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	// --- 服务启动 ---
	// 启动 Rendezvous 服务，并使用与控制面相同的 SQLite 数据库文件。
	rzvDB, err := rzvsqlite.OpenDB(ctx, dbPath)
	if err != nil {
		log.Fatalf("open rendezvous db: %v", err)
	}
	defer rzvDB.Close()
	_ = rzv.NewRendezvousService(h, rzvDB) // 将服务注册到 libp2p host，处理 /rendezvous/1.0.0 协议

	// 初始化控制面数据库。
	ctrlDB, err := openControlDB(dbPath)
	if err != nil {
		log.Fatalf("open control db: %v", err)
	}
	defer ctrlDB.close()

	// 启动一个后台 goroutine，每分钟清理一次过期的密码牌。
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for range t.C {
			if n, err := ctrlDB.cleanupExpired(time.Now()); err == nil && n > 0 {
				log.Printf("[gc] cleaned %d nameplates", n)
			}
		}
	}()

	// --- 打印服务器信息 ---
	fmt.Println("wormhole-server up.")
	fmt.Printf("PeerID: %s\n", h.ID().String())
	fmt.Println("Listen addresses:")
	for _, a := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", a, peer.ID(h.ID()))
	}

	// 确定并组合对外宣告的地址。
	advertised := advertisedAddrsWithP2P(h, publicAddrsCSV)

	// --- HTTP 控制面服务器配置 ---
	mux := http.NewServeMux()

	// withRateLimit 是一个中间件，用于在处理请求前进行频率检查。
	withRateLimit := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			ok, wait := ipRate.allow(ip, time.Now())
			if !ok {
				// 如果请求被限制，返回 429 Too Many Requests，并附带 Retry-After 头。
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		}
	}

	// 接口1: /v1/allocate - 分配一个新的密码牌。
	mux.HandleFunc("/v1/allocate", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip := clientIP(r)
		np, exp, err := allocateNameplate(ctrlDB, digits, ttl, time.Now(), ip)
		if err != nil {
			http.Error(w, "allocate failed", http.StatusInternalServerError)
			return
		}
		resp := allocateResponse{
			Nameplate: np,
			ExpiresAt: exp,
			ConnectionInfo: ConnectionInfo{
				Rendezvous: addrBundle{Namespace: rzvNamespace, Addrs: advertised},
				Relay:      addrBundle{Namespace: "circuit-relay-v2", Addrs: relayAddrsWithCircuit(advertised)},
				Bootstrap:  splitCSV(bootstrapCSV),
				Topic:      fmt.Sprintf("/wormhole/%s", np),
			},
		}
		writeJSON(w, http.StatusOK, resp)
	}))

	// 接口2: /v1/claim - 认领一个密码牌的其中一侧。
	mux.HandleFunc("/v1/claim", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req claimRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// 对于无效的请求，记录一次失败操作。
			ipRate.recordFail(clientIP(r), time.Now())
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Nameplate == "" || req.Side == "" {
			ipRate.recordFail(clientIP(r), time.Now())
			http.Error(w, "nameplate & side required", http.StatusBadRequest)
			return
		}

		ip := clientIP(r)
		st, row, err := ctrlDB.claim(req.Nameplate, req.Side, time.Now(), ip)
		if err != nil {
			http.Error(w, "claim failed", http.StatusInternalServerError)
			return
		}

		// 统一构造过期时间：如果 row 为 nil (密码牌不存在)，则使用当前时间，避免泄露信息。
		var exp time.Time
		if row != nil {
			exp = time.Unix(row.CreatedAt, 0).UTC().Add(time.Duration(row.TTLSeconds) * time.Second)
		} else {
			exp = time.Now().UTC()
		}

		// 如果认领结果是 failed，将此 IP 计入失败窗口。
		if st == statusFailed {
			ipRate.recordFail(ip, time.Now())
		}

		resp := claimResponse{
			Status:    st,
			ExpiresAt: exp,
			ConnectionInfo: ConnectionInfo{
				Rendezvous: addrBundle{Namespace: rzvNamespace, Addrs: advertised},
				Relay:      addrBundle{Namespace: "circuit-relay-v2", Addrs: relayAddrsWithCircuit(advertised)},
				Bootstrap:  splitCSV(bootstrapCSV),
				Topic:      fmt.Sprintf("/wormhole/%s", req.Nameplate),
			},
		}
		writeJSON(w, http.StatusOK, resp)
	}))

	// 接口3: /v1/consume - 客户端报告连接成功，将密码牌标记为已消耗。
	mux.HandleFunc("/v1/consume", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req consumeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Nameplate == "" {
			http.Error(w, "nameplate required", http.StatusBadRequest)
			return
		}
		if err := ctrlDB.consume(req.Nameplate); err != nil {
			http.Error(w, "consume failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}))

	// 接口4: /v1/fail - 客户端报告连接失败，将密码牌标记为作废。
	mux.HandleFunc("/v1/fail", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req failRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Nameplate == "" {
			http.Error(w, "nameplate required", http.StatusBadRequest)
			return
		}
		if err := ctrlDB.failAndConsume(req.Nameplate); err != nil {
			http.Error(w, "fail-and-consume failed", http.StatusInternalServerError)
			return
		}
		// 即使密码牌之前已经作废，也返回成功，使客户端逻辑更简单。
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}))

	srv := &http.Server{
		Addr:              ctrlListen,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("control-plane listening at %s", ctrlListen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()

	// --- 优雅退出处理 ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	// 等待信号，然后给服务器 5 秒钟来关闭。
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(ctxShutdown)
	fmt.Println("bye")
}

// -------------------- 工具函数 --------------------

// splitCSV 将逗号分隔的字符串切分为一个字符串数组，并去除空白。
func splitCSV(s string) []string {
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

// allocateNameplate 生成一个新的、未被占用的密码牌。
// 它会尝试最多1000次来避免随机数碰撞。
func allocateNameplate(db *controlDB, digits int, ttl time.Duration, now time.Time, ip string) (string, time.Time, error) {
	max := big.NewInt(1)
	for i := 0; i < digits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	db.mu.Lock()
	defer db.mu.Unlock()

	for tries := 0; tries < 1000; tries++ {
		nBig, _ := rand.Int(rand.Reader, max)
		code := fmt.Sprintf("%0*d", digits, nBig.Int64())
		// 检查生成的 code 是否已被占用且未过期。
		row, err := db.load(code)
		if err == nil && !row.expired(now) && row.Consumed == 0 {
			continue // 如果占用，则重试。
		}
		// 尝试插入新记录，如果因为主键冲突失败，也会重试。
		if err := db.insertNew(code, ttl, now, ip); err != nil {
			continue
		}
		return code, now.UTC().Add(ttl), nil
	}
	return "", time.Time{}, fmt.Errorf("exhausted allocating nameplate")
}

// hostAddrsWithP2P 获取 libp2p host 的所有监听地址，并附加其 PeerID。
func hostAddrsWithP2P(h host.Host) []string {
	pid := peer.ID(h.ID()).String()
	var out []string
	for _, a := range h.Addrs() {
		out = append(out, fmt.Sprintf("%s/p2p/%s", a, pid))
	}
	return out
}

// addP2PIfMissing 确保一个 multiaddr 字符串包含 /p2p/<PeerID> 后缀。
func addP2PIfMissing(addr, pid string) string {
	if strings.Contains(addr, "/p2p/") {
		return addr
	}
	return fmt.Sprintf("%s/p2p/%s", addr, pid)
}

// advertisedAddrsWithP2P 决定服务器对外宣告的地址。
// 如果用户通过 -public-addrs 标志指定了地址，则优先使用这些地址；否则，使用 host 自动检测到的监听地址。
func advertisedAddrsWithP2P(h host.Host, publicAddrsCSV string) []string {
	pid := peer.ID(h.ID()).String()
	if strings.TrimSpace(publicAddrsCSV) == "" {
		return hostAddrsWithP2P(h)
	}
	raw := splitCSV(publicAddrsCSV)
	var out []string
	for _, a := range raw {
		a = addP2PIfMissing(a, pid)
		out = append(out, a)
	}
	return out
}

// relayAddrsWithCircuit 将一组标准的 Peer 地址转换为 Relay 使用的 "circuit" 地址。
// 例如: /ip4/1.2.3.4/tcp/4001/p2p/PeerID -> /ip4/1.2.3.4/tcp/4001/p2p/PeerID/p2p-circuit
func relayAddrsWithCircuit(base []string) []string {
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

// logRequests 是一个 HTTP 中间件，用于记录每个请求的基本信息和处理耗时。
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", clientIP(r), r.Method, r.URL.Path, time.Since(start))
	})
}

// loadOrCreateIdentity 从指定路径加载 libp2p 的私钥。
// 如果文件不存在，则生成一个新的私钥并保存到该路径，以确保服务器重启后 PeerID 不变。
func loadOrCreateIdentity(path string) (crypto.PrivKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return crypto.UnmarshalPrivateKey(b)
	}
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	// 确保目录存在
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// 以安全的权限写入私钥文件
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
