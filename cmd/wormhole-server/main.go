package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
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

	"github.com/Metaphorme/wormhole/pkg/server"
)

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

	// 创建 IP 频率限制器
	ipRate := server.NewIPLimiter(reqWin, rateMaxReqs, failWin, rateMaxFails)

	// --- Libp2p Host 初始化 ---
	// 加载或创建持久化的私钥，以确保服务器有固定的 PeerID
	priv, err := server.LoadOrCreateIdentity(identityPath)
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
		// 启用 Relay v2 的 "hop" 服务，使该节点可以作为公共中继节点
		libp2p.EnableRelayService(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	// --- 服务启动 ---
	// 启动 Rendezvous 服务，并使用与控制面相同的 SQLite 数据库文件
	rzvDB, err := rzvsqlite.OpenDB(ctx, dbPath)
	if err != nil {
		log.Fatalf("open rendezvous db: %v", err)
	}
	defer rzvDB.Close()
	_ = rzv.NewRendezvousService(h, rzvDB) // 将服务注册到 libp2p host，处理 /rendezvous/1.0.0 协议

	// 初始化控制面数据库
	ctrlDB, err := server.OpenControlDB(dbPath)
	if err != nil {
		log.Fatalf("open control db: %v", err)
	}
	defer ctrlDB.Close()

	// 启动一个后台 goroutine，每分钟清理一次过期的密码牌
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for range t.C {
			if n, err := ctrlDB.CleanupExpired(time.Now()); err == nil && n > 0 {
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

	// 确定并组合对外宣告的地址
	advertised := server.AdvertisedAddrsWithP2P(h, publicAddrsCSV)
	relayAddrs := server.RelayAddrsWithCircuit(advertised)
	bootstrap := server.SplitCSV(bootstrapCSV)

	// --- HTTP 控制面服务器配置 ---
	handlers := server.NewHTTPHandlers(
		ctrlDB,
		ipRate,
		rzvNamespace,
		advertised,
		relayAddrs,
		bootstrap,
		ttl,
		digits,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/allocate", handlers.WithRateLimit(handlers.HandleAllocate))
	mux.HandleFunc("/v1/claim", handlers.WithRateLimit(handlers.HandleClaim))
	mux.HandleFunc("/v1/consume", handlers.WithRateLimit(handlers.HandleConsume))
	mux.HandleFunc("/v1/fail", handlers.WithRateLimit(handlers.HandleFail))

	srv := &http.Server{
		Addr:              ctrlListen,
		Handler:           server.LogRequests(mux),
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
	// 等待信号，然后给服务器 5 秒钟来关闭
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(ctxShutdown)
	fmt.Println("bye")
}
