// cmd/wormhole-server/main.go
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

	_ "modernc.org/sqlite" // CGO-free SQLite driver
)

// -------------------- 控制面存储结构 --------------------

type plateStatus string

const (
	statusWaiting plateStatus = "waiting"
	statusPaired  plateStatus = "paired"
	// 不再向客户端暴露 "expired"；统一用 failed
	statusFailed plateStatus = "failed"
)

type nameplateRow struct {
	Nameplate   string
	CreatedAt   int64 // unix seconds (UTC)
	TTLSeconds  int64
	ClaimedMask int64 // bit0=host, bit1=connect
	Consumed    int64 // 0/1
	FailCount   int64
	LastIP      sql.NullString
}

type controlDB struct {
	mu sync.Mutex // 保护分配流程的小临界区
	db *sql.DB
}

func openControlDB(path string) (*controlDB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
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

func (c *controlDB) close() error { return c.db.Close() }

func (c *controlDB) insertNew(nameplate string, ttl time.Duration, now time.Time, ip string) error {
	_, err := c.db.Exec(`INSERT INTO nameplates(nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip)
VALUES(?, ?, ?, 0, 0, 0, ?)`, nameplate, now.UTC().Unix(), int64(ttl/time.Second), ip)
	return err
}

func (c *controlDB) load(nameplate string) (*nameplateRow, error) {
	row := c.db.QueryRow(`SELECT nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip FROM nameplates WHERE nameplate=?`, nameplate)
	var r nameplateRow
	if err := row.Scan(&r.Nameplate, &r.CreatedAt, &r.TTLSeconds, &r.ClaimedMask, &r.Consumed, &r.FailCount, &r.LastIP); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *nameplateRow) expired(at time.Time) bool {
	expires := time.Unix(r.CreatedAt, 0).UTC().Add(time.Duration(r.TTLSeconds) * time.Second)
	return at.UTC().After(expires)
}

func (c *controlDB) incrFail(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET fail_count = fail_count + 1 WHERE nameplate=?`, nameplate)
	return err
}

func (c *controlDB) delete(nameplate string) error {
	_, err := c.db.Exec(`DELETE FROM nameplates WHERE nameplate=?`, nameplate)
	return err
}

// claim 对“相同侧重复认领”与“无效 side”进行 fail_count++，
// 对过期的 nameplate 直接从数据库删除并返回 failed。
func (c *controlDB) claim(nameplate, side string, now time.Time, ip string) (plateStatus, *nameplateRow, error) {
	r, err := c.load(nameplate)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 不暴露不存在/过期，统一 failed
			return statusFailed, nil, nil
		}
		return "", nil, err
	}
	// 过期即删除，避免被探测
	if r.expired(now) {
		_ = c.delete(nameplate)
		return statusFailed, nil, nil
	}
	if r.Consumed != 0 {
		return statusFailed, r, nil
	}

	var bit int64
	switch strings.ToLower(side) {
	case "host", "a":
		bit = 1
	case "connect", "b":
		bit = 2
	default:
		// side 无效：计失败
		_ = c.incrFail(nameplate)
		return statusFailed, r, nil
	}

	newMask := r.ClaimedMask | bit
	if newMask == r.ClaimedMask {
		// 重复 claim 同侧：计失败
		_ = c.incrFail(nameplate)
		return statusFailed, r, nil
	}

	if _, err := c.db.Exec(`UPDATE nameplates SET claimed_mask=?, last_ip=? WHERE nameplate=?`, newMask, ip, nameplate); err != nil {
		return "", nil, err
	}
	r.ClaimedMask = newMask
	r.LastIP = sql.NullString{String: ip, Valid: true}

	if newMask == 3 {
		return statusPaired, r, nil
	}
	return statusWaiting, r, nil
}

func (c *controlDB) consume(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET consumed=1 WHERE nameplate=?`, nameplate)
	return err
}

func (c *controlDB) cleanupExpired(now time.Time) (int64, error) {
	res, err := c.db.Exec(`DELETE FROM nameplates WHERE (created_at + ttl_seconds) < ? OR consumed=1`, now.UTC().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// -------------------- HTTP 控制面 --------------------

type addrBundle struct {
	Namespace string   `json:"namespace"`
	Addrs     []string `json:"addrs"`
}

type ConnectionInfo struct {
	Rendezvous addrBundle `json:"rendezvous"`
	Relay      addrBundle `json:"relay"`
	Bootstrap  []string   `json:"bootstrap,omitempty"`
	Topic      string     `json:"topic"`
}

type allocateResponse struct {
	Nameplate string    `json:"nameplate"`
	ExpiresAt time.Time `json:"expires_at"`
	ConnectionInfo
}

type claimRequest struct {
	Nameplate string `json:"nameplate"`
	Side      string `json:"side"` // "host"/"connect"
}

type claimResponse struct {
	Status    plateStatus `json:"status"` // waiting/paired/failed
	ExpiresAt time.Time   `json:"expires_at"`
	ConnectionInfo
}

type consumeRequest struct {
	Nameplate string `json:"nameplate"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	// 尽量拿到真实 IP（若前有反代，可读取 X-Forwarded-For）
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

// -------------------- 简单频控（IP 维度） --------------------

type ipLimiter struct {
	mu         sync.Mutex
	reqs       map[string][]time.Time
	fails      map[string][]time.Time
	reqWindow  time.Duration
	maxReqs    int
	failWindow time.Duration
	maxFails   int
}

func newIPLimiter(reqWindow time.Duration, maxReqs int, failWindow time.Duration, maxFails int) *ipLimiter {
	l := &ipLimiter{
		reqs:       make(map[string][]time.Time),
		fails:      make(map[string][]time.Time),
		reqWindow:  reqWindow,
		maxReqs:    maxReqs,
		failWindow: failWindow,
		maxFails:   maxFails,
	}
	return l
}

func (l *ipLimiter) pruneLocked(now time.Time) {
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

func (l *ipLimiter) allow(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	// 频次
	arr := append(l.reqs[ip], now)
	l.reqs[ip] = arr
	if len(arr) > l.maxReqs {
		// 计算建议等待时间（最早一条出窗即可）
		wait := l.reqWindow - now.Sub(arr[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}
	// 失败阈值
	if fails := l.fails[ip]; len(fails) > l.maxFails {
		wait := l.failWindow - now.Sub(fails[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}
	return true, 0
}

func (l *ipLimiter) recordFail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	l.fails[ip] = append(l.fails[ip], now)
}

// -------------------- 服务器主程序 --------------------

func main() {
	var listenAddrs string
	var dbPath string
	var ctrlListen string
	var ctrlDBPath string
	var rzvNamespace string
	var ttlStr string
	var digits int
	var bootstrapCSV string
	var publicAddrsCSV string

	// 频控参数
	var rateReqWindowStr string
	var rateMaxReqs int
	var rateFailWindowStr string
	var rateMaxFails int

	flag.StringVar(&listenAddrs, "listen", "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4002/ws", "comma-separated multiaddrs for libp2p")
	flag.StringVar(&dbPath, "rendezvous-db", "./rendezvous.db", "sqlite path for rendezvous")
	flag.StringVar(&ctrlListen, "control-listen", ":8080", "http control-plane listen addr")
	flag.StringVar(&ctrlDBPath, "control-db", "./control.db", "sqlite path for control-plane")
	flag.StringVar(&rzvNamespace, "rendezvous-namespace", "wormhole", "rendezvous namespace")
	flag.StringVar(&ttlStr, "nameplate-ttl", "30m", "nameplate TTL, e.g. 10m/30m")
	flag.IntVar(&digits, "nameplate-digits", 3, "nameplate digits (3-4 recommended)")
	flag.StringVar(&bootstrapCSV, "bootstrap", "", "comma-separated bootstrap dnsaddr/multiaddrs (optional)")
	flag.StringVar(&publicAddrsCSV, "public-addrs", "", "comma-separated public announce addrs (multiaddr/dnsaddr). If set, overrides automatic hostAddrs")

	flag.StringVar(&rateReqWindowStr, "rate-req-window", "1m", "per-IP request rate window")
	flag.IntVar(&rateMaxReqs, "rate-max-reqs", 120, "max requests per IP within req-window")
	flag.StringVar(&rateFailWindowStr, "rate-fail-window", "10m", "per-IP failures window")
	flag.IntVar(&rateMaxFails, "rate-max-fails", 30, "max failures per IP within fail-window")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// 生成持久 PeerKey（生产可落盘，这里演示内存）
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		log.Fatal(err)
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
		// 作为公共节点启动 Relay v2 hop 服务（Circuit Relay v2 规范）
		// 官方已提供 EnableRelayService 在可达时自动运行，无需再手动 relay.New(h)。
		libp2p.EnableRelayService(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	// Rendezvous 服务 + SQLite
	rzvDB, err := rzvsqlite.OpenDB(ctx, dbPath)
	if err != nil {
		log.Fatalf("open rendezvous db: %v", err)
	}
	defer rzvDB.Close()
	_ = rzv.NewRendezvousService(h, rzvDB) // 挂到 host，处理 /rendezvous/1.0.0

	// 控制面数据库
	ctrlDB, err := openControlDB(ctrlDBPath)
	if err != nil {
		log.Fatalf("open control db: %v", err)
	}
	defer ctrlDB.close()

	// 启动周期清理（过期/已消费）
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for range t.C {
			if n, err := ctrlDB.cleanupExpired(time.Now()); err == nil && n > 0 {
				log.Printf("[gc] cleaned %d nameplates", n)
			}
		}
	}()

	// 打印信息
	fmt.Println("wormhole-server up.")
	fmt.Printf("PeerID: %s\n", h.ID().String())
	fmt.Println("Listen addresses:")
	for _, a := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", a, peer.ID(h.ID()))
	}

	// 选择对外发布地址
	advertised := advertisedAddrsWithP2P(h, publicAddrsCSV)

	// HTTP 控制面
	mux := http.NewServeMux()

	// 频控检查的装饰器
	withRateLimit := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			ok, wait := ipRate.allow(ip, time.Now())
			if !ok {
				// RFC 6585 建议附带 Retry-After
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		}
	}

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

	mux.HandleFunc("/v1/claim", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req claimRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// 解析失败视作一次“失败行为”，计入 IP 失败窗口
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

		// 统一构造 expires：若 row 为空，用当前时间（不暴露是否存在）
		var exp time.Time
		if row != nil {
			exp = time.Unix(row.CreatedAt, 0).UTC().Add(time.Duration(row.TTLSeconds) * time.Second)
		} else {
			exp = time.Now().UTC()
		}

		// 若判定为 failed，也把该 IP 计入失败窗口
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

	mux.HandleFunc("/v1/consume", func(w http.ResponseWriter, r *http.Request) {
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
	})

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

	// 等待退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	fmt.Println("bye")
}

// -------------------- 工具函数 --------------------

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
		// 检查是否已存在且未过期
		row, err := db.load(code)
		if err == nil && !row.expired(now) && row.Consumed == 0 {
			continue // 占用中，换一个
		}
		if err := db.insertNew(code, ttl, now, ip); err != nil {
			// 竞争冲突，重试
			continue
		}
		return code, now.UTC().Add(ttl), nil
	}
	return "", time.Time{}, fmt.Errorf("exhausted allocating nameplate")
}

func hostAddrsWithP2P(h host.Host) []string {
	pid := peer.ID(h.ID()).String()
	var out []string
	for _, a := range h.Addrs() {
		out = append(out, fmt.Sprintf("%s/p2p/%s", a, pid))
	}
	return out
}

func addP2PIfMissing(addr, pid string) string {
	if strings.Contains(addr, "/p2p/") {
		return addr
	}
	return fmt.Sprintf("%s/p2p/%s", addr, pid)
}

// 选择对外发布地址：若设置了 -public-addrs，则优先使用；否则回退到本机监听地址。
// 无论来源如何，都补齐 /p2p/<PeerID>
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

// Relay 地址补上 /p2p-circuit，使之成为完整的中继入口地址：
//
//	<transport>/p2p/<RelayPeerID>/p2p-circuit
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

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start))
	})
}
