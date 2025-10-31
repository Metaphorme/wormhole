package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	rzv "github.com/waku-org/go-libp2p-rendezvous"
	rzvsqlite "github.com/waku-org/go-libp2p-rendezvous/db/sqlite"

	"github.com/Metaphorme/wormhole/pkg/models"
	"github.com/Metaphorme/wormhole/pkg/server"
)

// ----------------- 测试工具 -----------------

type testServer struct {
	httpServer *httptest.Server
	baseURL    string
	host       peer.ID
	hostAddrs  []string
}

type serverConfig struct {
	ttl          time.Duration
	digits       int
	namespace    string
	bootstrapCSV string
	publicAddrs  string
	reqWindow    time.Duration
	maxReqs      int
	failWindow   time.Duration
	maxFails     int
}

func startWormholeServerForTest(t *testing.T, cfg serverConfig) *testServer {
	t.Helper()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "wormhole.db")
	identityPath := filepath.Join(tmp, "server.key")

	// 加载/创建持久身份
	priv, err := server.LoadOrCreateIdentity(identityPath)
	if err != nil {
		t.Fatalf("loadOrCreateIdentity: %v", err)
	}

	// libp2p 主机 (在 127.0.0.1 上使用 TCP，随机端口 -> 对测试友好)
	// 端口 0 => 选择任意空闲端口 (非常适合测试)。
	addrTCP := mustMA(t, "/ip4/127.0.0.1/tcp/0")
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.ListenAddrs(addrTCP),
	)
	if err != nil {
		t.Fatalf("libp2p.New: %v", err)
	}

	// Rendezvous 服务与控制平面共享同一个 sqlite 文件。
	ctx := context.Background()
	rdb, err := rzvsqlite.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("open rendezvous db: %v", err)
	}
	_ = rzv.NewRendezvousService(h, rdb)

	ctrlDB, err := server.OpenControlDB(dbPath)
	if err != nil {
		t.Fatalf("open control db: %v", err)
	}

	advertised := server.AdvertisedAddrsWithP2P(h, cfg.publicAddrs)

	// HTTP mux (main.go 处理程序的副本，闭包捕获了局部变量)
	mux := http.NewServeMux()
	ipRate := server.NewIPLimiter(cfg.reqWindow, cfg.maxReqs, cfg.failWindow, cfg.maxFails)

	withRateLimit := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := server.ClientIP(r)
			if ok, wait := ipRate.Allow(ip, time.Now()); !ok {
				w.Header().Set("Retry-After", strings.TrimSuffix((wait).Round(time.Second).String(), "0s"))
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
		ip := server.ClientIP(r)
		np, exp, err := server.AllocateNameplate(ctrlDB, cfg.digits, cfg.ttl, time.Now(), ip)
		if err != nil {
			http.Error(w, "allocate failed", http.StatusInternalServerError)
			return
		}
		resp := models.AllocateResponse{
			Nameplate: np,
			ExpiresAt: exp,
			ConnectionInfo: models.ConnectionInfo{
				Rendezvous: models.AddrBundle{Namespace: cfg.namespace, Addrs: advertised},
				Relay:      models.AddrBundle{Namespace: "circuit-relay-v2", Addrs: server.RelayAddrsWithCircuit(advertised)},
				Bootstrap:  server.SplitCSV(cfg.bootstrapCSV),
				Topic:      "/wormhole/" + np,
			},
		}
		server.WriteJSON(w, http.StatusOK, resp)
	}))

	mux.HandleFunc("/v1/claim", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req models.ClaimRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Nameplate == "" || req.Side == "" {
			ipRate.RecordFail(server.ClientIP(r), time.Now())
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		ip := server.ClientIP(r)
		st, row, err := ctrlDB.Claim(req.Nameplate, req.Side, time.Now(), ip)
		if err != nil {
			http.Error(w, "claim failed", http.StatusInternalServerError)
			return
		}
		var exp time.Time
		if row != nil {
			exp = time.Unix(row.CreatedAt, 0).UTC().Add(time.Duration(row.TTLSeconds) * time.Second)
		} else {
			exp = time.Now().UTC()
		}
		if st == server.StatusFailed {
			ipRate.RecordFail(ip, time.Now())
		}
		resp := models.ClaimResponse{
			Status:    string(st),
			ExpiresAt: exp,
			ConnectionInfo: models.ConnectionInfo{
				Rendezvous: models.AddrBundle{Namespace: cfg.namespace, Addrs: advertised},
				Relay:      models.AddrBundle{Namespace: "circuit-relay-v2", Addrs: server.RelayAddrsWithCircuit(advertised)},
				Bootstrap:  server.SplitCSV(cfg.bootstrapCSV),
				Topic:      "/wormhole/" + req.Nameplate,
			},
		}
		server.WriteJSON(w, http.StatusOK, resp)
	}))

	mux.HandleFunc("/v1/consume", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req models.ConsumeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Nameplate == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := ctrlDB.Consume(req.Nameplate); err != nil {
			http.Error(w, "consume failed", http.StatusInternalServerError)
			return
		}
		server.WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}))

	mux.HandleFunc("/v1/fail", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req models.FailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Nameplate == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := ctrlDB.FailAndConsume(req.Nameplate); err != nil {
			http.Error(w, "fail-and-consume failed", http.StatusInternalServerError)
			return
		}
		server.WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}))

	ts := httptest.NewServer(server.LogRequests(mux))

	t.Cleanup(func() {
		ts.Close()
		ctrlDB.Close()
		_ = rdb.Close()
		_ = h.Close()
	})

	return &testServer{
		httpServer: ts,
		baseURL:    ts.URL,
		host:       h.ID(),
		hostAddrs:  advertised,
	}
}

func mustMA(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("bad multiaddr %q: %v", s, err)
	}
	return a
}

func postJSON[T any](t *testing.T, base, path string, body any, hdr map[string]string) (T, *http.Response) {
	t.Helper()
	var zero T
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, resp
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out, resp
}

// ----------------- 测试 -----------------

func TestAllocateClaimConsumeFlow(t *testing.T) {
	s := startWormholeServerForTest(t, serverConfig{
		ttl:          2 * time.Minute,
		digits:       3,
		namespace:    "wormhole-test",
		reqWindow:    1 * time.Second,
		maxReqs:      100,
		failWindow:   1 * time.Minute,
		maxFails:     100,
		bootstrapCSV: "",
	})

	// 1) 分配
	alloc, _ := postJSON[models.AllocateResponse](t, s.baseURL, "/v1/allocate", map[string]any{}, nil)
	if len(alloc.Nameplate) != 3 {
		t.Fatalf("unexpected nameplate length: %q", alloc.Nameplate)
	}
	if !strings.HasPrefix(alloc.Topic, "/wormhole/"+alloc.Nameplate) {
		t.Fatalf("topic mismatch: %s", alloc.Topic)
	}
	// rendezvous/relay 地址应该是广播地址 + /p2p-circuit
	if len(alloc.Rendezvous.Addrs) == 0 || len(alloc.Relay.Addrs) == 0 {
		t.Fatalf("missing advertised addresses")
	}
	for _, a := range alloc.Relay.Addrs {
		if !strings.Contains(a, "/p2p-circuit") {
			t.Fatalf("relay address missing /p2p-circuit: %s", a)
		}
	}

	// 2) 主机端声明 -> 等待中
	cl1, _ := postJSON[models.ClaimResponse](t, s.baseURL, "/v1/claim", models.ClaimRequest{
		Nameplate: alloc.Nameplate,
		Side:      "host",
	}, nil)
	if cl1.Status != string(server.StatusWaiting) {
		t.Fatalf("expect waiting, got %s", cl1.Status)
	}

	// 3) 连接端声明 -> 已配对
	cl2, _ := postJSON[models.ClaimResponse](t, s.baseURL, "/v1/claim", models.ClaimRequest{
		Nameplate: alloc.Nameplate,
		Side:      "connect",
	}, nil)
	if cl2.Status != string(server.StatusPaired) {
		t.Fatalf("expect paired, got %s", cl2.Status)
	}

	// 4) 消费 -> 成功
	var ok map[string]string
	ok, _ = postJSON[map[string]string](t, s.baseURL, "/v1/consume", models.ConsumeRequest{
		Nameplate: alloc.Nameplate,
	}, nil)
	if ok["ok"] != "true" {
		t.Fatalf("consume not ok: %+v", ok)
	}

	// 5) 再次声明 -> 失败
	cl3, _ := postJSON[models.ClaimResponse](t, s.baseURL, "/v1/claim", models.ClaimRequest{
		Nameplate: alloc.Nameplate,
		Side:      "host",
	}, nil)
	if cl3.Status != string(server.StatusFailed) {
		t.Fatalf("expect failed after consumed, got %s", cl3.Status)
	}
}

func TestFailEndpointIsIdempotent(t *testing.T) {
	s := startWormholeServerForTest(t, serverConfig{
		ttl:        1 * time.Minute,
		digits:     3,
		namespace:  "wormhole-test",
		reqWindow:  1 * time.Second,
		maxReqs:    100,
		failWindow: 1 * time.Minute,
		maxFails:   100,
	})
	alloc, _ := postJSON[models.AllocateResponse](t, s.baseURL, "/v1/allocate", map[string]any{}, nil)

	// 第一次失败
	first, _ := postJSON[map[string]string](t, s.baseURL, "/v1/fail", models.FailRequest{Nameplate: alloc.Nameplate}, nil)
	if first["ok"] != "true" {
		t.Fatalf("first fail not ok: %+v", first)
	}
	// 第二次失败 (幂等)
	second, _ := postJSON[map[string]string](t, s.baseURL, "/v1/fail", models.FailRequest{Nameplate: alloc.Nameplate}, nil)
	if second["ok"] != "true" {
		t.Fatalf("second fail not ok: %+v", second)
	}
}

func TestRateLimitHits429(t *testing.T) {
	s := startWormholeServerForTest(t, serverConfig{
		ttl:        1 * time.Minute,
		digits:     3,
		namespace:  "wormhole-test",
		reqWindow:  300 * time.Millisecond, // 很小的时间窗口
		maxReqs:    3,                      // 允许 3 次快速调用
		failWindow: 1 * time.Minute,
		maxFails:   100,
	})
	hdr := map[string]string{"X-Forwarded-For": "203.0.113.9"} // 用于速率限制窗口的固定 IP

	// 3 次快速成功的调用
	for i := 0; i < 3; i++ {
		_, resp := postJSON[models.AllocateResponse](t, s.baseURL, "/v1/allocate", map[string]any{}, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("unexpected status on warmup %d: %d", i, resp.StatusCode)
		}
	}
	// 第 4 次应该收到 429
	_, resp := postJSON[models.AllocateResponse](t, s.baseURL, "/v1/allocate", map[string]any{}, hdr)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expect 429, got %d", resp.StatusCode)
	}
}

func TestRendezvousRegisterAndDiscover(t *testing.T) {
	// 我们使用的 Rendezvous 客户端 API：在服务器对等节点上进行 Register/Discover。
	s := startWormholeServerForTest(t, serverConfig{
		ttl:        2 * time.Minute,
		digits:     3,
		namespace:  "wormhole-test",
		reqWindow:  1 * time.Second,
		maxReqs:    100,
		failWindow: 1 * time.Minute,
		maxFails:   100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 两个本地 libp2p 主机 (TCP, 临时端口)，分别用于 A 和 B。
	hA, err := libp2p.New(libp2p.Transport(tcp.NewTCPTransport), libp2p.ListenAddrs(mustMA(t, "/ip4/127.0.0.1/tcp/0")))
	if err != nil {
		t.Fatalf("new host A: %v", err)
	}
	defer hA.Close()
	hB, err := libp2p.New(libp2p.Transport(tcp.NewTCPTransport), libp2p.ListenAddrs(mustMA(t, "/ip4/127.0.0.1/tcp/0")))
	if err != nil {
		t.Fatalf("new host B: %v", err)
	}
	defer hB.Close()

	// A 和 B 都拨号连接到 rendezvous 服务器
	pi := peer.AddrInfo{
		ID:    s.host,
		Addrs: mustMultiaddrs(t, s.hostAddrs),
	}
	if err := hA.Connect(ctx, pi); err != nil {
		t.Fatalf("A connect to server: %v", err)
	}
	if err := hB.Connect(ctx, pi); err != nil {
		t.Fatalf("B connect to server: %v", err)
	}

	// A 注册；B 发现。
	rcA := rzv.NewRendezvousClient(hA, s.host)
	rcB := rzv.NewRendezvousClient(hB, s.host)

	if _, err := rcA.Register(ctx, "wormhole-test", int((2 * time.Hour).Seconds())); err != nil {
		t.Fatalf("A register: %v", err)
	}

	// 短暂轮询 discover 直到我们看到 A
	var found peer.AddrInfo
	ok := false
	for i := 0; i < 10 && !ok; i++ {
		infos, _, err := rcB.Discover(ctx, "wormhole-test", 10, nil)
		if err == nil {
			for _, inf := range infos {
				if inf.ID == hA.ID() {
					found = inf
					ok = true
					break
				}
			}
		}
		if !ok {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatalf("B did not discover A via rendezvous")
	}

	// 额外测试：B 可以使用发现的地址连接到 A。
	if err := hB.Connect(ctx, found); err != nil {
		t.Fatalf("B connect A: %v", err)
	}
}

// 辅助函数：将字符串地址转换为 []multiaddr.Multiaddr
func mustMultiaddrs(t *testing.T, ss []string) (out []ma.Multiaddr) {
	t.Helper()
	for _, s := range ss {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("bad addr from server: %s: %v", s, err)
		}
		out = append(out, a)
	}
	return
}
