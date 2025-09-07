package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	ma "github.com/multiformats/go-multiaddr"

	readline "github.com/chzyer/readline"
)

func ctxT(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	if d == 0 {
		d = 15 * time.Second
	}
	return context.WithTimeout(context.Background(), d)
}

func newLoopbackHost(t *testing.T) host.Host {
	t.Helper()
	// 仅回环 TCP，避免 CI/本机环境的 QUIC/HolePunching 干扰
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func connect(t *testing.T, a, b host.Host) {
	t.Helper()
	ai := peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}
	ctx, cancel := ctxT(t, 10*time.Second)
	defer cancel()
	if err := a.Connect(ctx, ai); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func newTestUI(t *testing.T) *uiConsole {
	t.Helper()
	// 使用可填充的 stdin（io.ReadCloser）+ 内存 stdout，避免真实 TTY 依赖
	inRC, inW := readline.NewFillableStdin(bytes.NewBuffer(nil))
	var out bytes.Buffer
	rl, err := readline.NewEx(&readline.Config{
		Prompt:                 "",
		HistoryFile:            "",
		HistoryLimit:           0,
		DisableAutoSaveHistory: true,
		HistorySearchFold:      true,

		Stdin:       inRC, // io.ReadCloser
		StdinWriter: inW,  // 可在需要时向 stdin 写入脚本化输入
		Stdout:      &out,
		Stderr:      io.Discard,

		UniqueEditLine: true,
		// 如需：可按需设置 FuncIsTerminal/FuncMakeRaw/FuncExitRaw/ForceUseInteractive
	})
	if err != nil {
		t.Fatalf("readline.NewEx: %v", err)
	}
	t.Cleanup(func() { _ = rl.Close() })
	return &uiConsole{rl: rl, defaultPrompt: ""}
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestFrameReadWrite_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	payload := []byte("hello frame")
	go func() {
		_ = writeFrame(a, 0x42, payload)
	}()

	typ, got, err := readFrame(b)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != 0x42 || !bytes.Equal(got, payload) {
		t.Fatalf("mismatch typ=%x got=%q", typ, string(got))
	}
}

func TestFrameReadWrite_TooLarge(t *testing.T) {
	var hdr [9]byte
	hdr[0] = 0x7A
	// > 1<<31
	binary.LittleEndian.PutUint64(hdr[1:], uint64((1<<31)+1))
	_, _, err := readFrame(bytes.NewReader(hdr[:]))
	if err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("want frame too large, got %v", err)
	}
}

func TestHTTPPostJSON_RetryAfter(t *testing.T) {
	type resp struct {
		OK bool `json:"ok"`
	}

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0") // seconds
			http.Error(w, "please retry", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(resp{OK: true})
	}))
	defer srv.Close()

	var out resp
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()
	if err := httpPostJSON(ctx, srv.URL, "/v1/x", map[string]int{"a": 1}, &out); err != nil {
		t.Fatalf("httpPostJSON: %v", err)
	}
	if !out.OK {
		t.Fatal("response not OK")
	}
}

func TestEffWords_And_Emoji_SAS(t *testing.T) {
	ws := effWords()
	if len(ws) < 1000 {
		t.Fatalf("eff words too few: %d", len(ws))
	}
	if len(emojiList()) != 64 {
		t.Fatalf("emoji list must be 64 items for 6-bit mapping")
	}
	// SAS 稳定性
	K := []byte("0123456789abcdef0123456789abcdef")
	tr1 := []byte("tr-1")
	tr2 := []byte("tr-2")
	s1 := sasFromKey(K, tr1)
	s2 := sasFromKey(K, tr1)
	s3 := sasFromKey(K, tr2)
	if s1 != s2 || s1 == s3 {
		t.Fatalf("SAS not deterministic or not transcript-bound")
	}
	// HKDF 长度与前缀
	if got := len(hkdfBytes(K, "confirm", tr1, 32)); got != 32 {
		t.Fatalf("hkdfBytes length mismatch: %d", got)
	}
}

func TestParseP2pAddrInfos(t *testing.T) {
	// 构造两个 host，用它们的 PeerID 来保证 /p2p/<id> 可解析
	h1 := newLoopbackHost(t)
	h2 := newLoopbackHost(t)
	addrs := []string{
		"/ip4/127.0.0.1/tcp/1234/p2p/" + h1.ID().String(),
		"/ip4/127.0.0.1/tcp/5678/p2p/" + h2.ID().String(),
		// 带 /p2p-circuit 片段，parseP2pAddrInfos 会裁剪掉
		"/ip4/127.0.0.1/tcp/5678/p2p/" + h2.ID().String() + "/p2p-circuit/p2p/" + h1.ID().String(),
	}
	ais, err := parseP2pAddrInfos(addrs)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ais) != 2 {
		t.Fatalf("want 2 unique peers, got %d", len(ais))
	}
}

func TestIsUnspecified_And_Private(t *testing.T) {
	mk := func(s string) ma.Multiaddr {
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr: %v", err)
		}
		return m
	}
	if !isUnspecified(mk("/ip4/0.0.0.0/tcp/0")) || !isUnspecified(mk("/ip6/::/tcp/0")) {
		t.Fatalf("unspecified detection failed")
	}
	if !isLoopbackOrPrivate(mk("/ip4/127.0.0.1/tcp/1")) || !isLoopbackOrPrivate(mk("/ip4/10.0.0.1/tcp/1")) {
		t.Fatalf("loopback/private detection failed")
	}
}

func TestTransportHint(t *testing.T) {
	cases := []struct {
		s string
		h string
	}{
		{"/ip4/127.0.0.1/udp/1234/quic-v1", "quic-v1"},
		{"/ip4/127.0.0.1/tcp/1234/ws", "ws"},
		{"/ip4/127.0.0.1/tcp/1234", "tcp"},
		{"/ip4/127.0.0.1/udp/9999", "udp"},
	}
	for _, c := range cases {
		m, _ := ma.NewMultiaddr(c.s)
		got := transportHint(m)
		if got != c.h {
			t.Fatalf("transportHint(%s) = %s, want %s", c.s, got, c.h)
		}
	}
}

func TestPAKE_RunAndConfirm(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short")
	}
	A := newLoopbackHost(t)
	B := newLoopbackHost(t)
	connect(t, A, B)

	const pass = "correct horse battery staple"
	const nameplate = "999"
	// 使用任意测试协议打开 stream；runPAKEAndConfirm 使用我们显式提供的 proto 来构建 transcript
	const testProto protocol.ID = "/wormhole/pake-test/1.0.0"

	resB := make(chan []byte, 1)
	errB := make(chan error, 1)
	B.SetStreamHandler(testProto, func(s network.Stream) {
		defer s.Close()
		K, err := runPAKEAndConfirm(context.Background(), s, false, pass, nameplate, protoChat, B.ID(), s.Conn().RemotePeer())
		if err != nil {
			errB <- err
			return
		}
		resB <- K
	})

	ctx, cancel := ctxT(t, 10*time.Second)
	defer cancel()
	s, err := A.NewStream(ctx, B.ID(), testProto)
	if err != nil {
		t.Fatalf("new stream: %v", err)
	}
	K1, err := runPAKEAndConfirm(ctx, s, true, pass, nameplate, protoChat, A.ID(), s.Conn().RemotePeer())
	if err != nil {
		t.Fatalf("dialer runPAKE: %v", err)
	}
	select {
	case e := <-errB:
		t.Fatalf("responder runPAKE: %v", e)
	case K2 := <-resB:
		if !bytes.Equal(K1, K2) {
			t.Fatal("shared key mismatch")
		}
		// 再次确认：SAS & xfer-seed 派生一致
		trC := buildTranscript(nameplate, protoChat, A.ID(), B.ID())
		if sasFromKey(K1, trC) != sasFromKey(K2, trC) {
			t.Fatal("SAS mismatch")
		}
		trX := buildTranscript(nameplate, protoXfer, A.ID(), B.ID())
		seed1 := binary.LittleEndian.Uint64(hkdfBytes(K1, "xfer-xxh3-seed", trX, 8))
		seed2 := binary.LittleEndian.Uint64(hkdfBytes(K2, "xfer-xxh3-seed", trX, 8))
		if seed1 != seed2 {
			t.Fatal("xfer seed mismatch")
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting PAKE responder")
	}
}

func TestXfer_File_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short")
	}
	// 固定种子：绕过 PAKE，直接验证 XFER 协议与哈希校验
	const seed uint64 = 0xdeadbeefcafebabe

	S := newLoopbackHost(t)
	R := newLoopbackHost(t)
	connect(t, S, R)

	outDir := t.TempDir()
	uiR := newTestUI(t)
	askYes := func(_ string, _ time.Duration) bool { return true }

	// 接收端设置 handler
	R.SetStreamHandler(protoXfer, func(xs network.Stream) {
		handleIncomingXfer(context.Background(), R, xs, outDir, askYes, uiR, seed)
	})

	// 发送端准备文件
	srcDir := t.TempDir()
	data := bytes.Repeat([]byte("ABCdef123!@#"), 4096) // ~48KB
	src := writeTempFile(t, srcDir, "one.bin", data)

	uiS := newTestUI(t)
	ctx, cancel := ctxT(t, 20*time.Second)
	defer cancel()
	if err := sendXfer(ctx, S, R.ID(), "file", src, uiS, seed); err != nil {
		t.Fatalf("sendXfer(file): %v", err)
	}

	dst := filepath.Join(outDir, "one.bin")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("file content mismatch")
	}
}

func TestXfer_Dir_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short")
	}
	const seed uint64 = 0x0123456789abcdef

	S := newLoopbackHost(t)
	R := newLoopbackHost(t)
	connect(t, S, R)

	outDir := t.TempDir()
	uiR := newTestUI(t)
	askYes := func(_ string, _ time.Duration) bool { return true }

	R.SetStreamHandler(protoXfer, func(xs network.Stream) {
		handleIncomingXfer(context.Background(), R, xs, outDir, askYes, uiR, seed)
	})

	// 构造目录（含空文件与子目录）
	srcRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(srcRoot, "sub/a"), 0o755)
	writeTempFile(t, srcRoot, "sub/a/aa.txt", []byte("hello A"))
	writeTempFile(t, srcRoot, "sub/bb.txt", []byte("hello B"))
	writeTempFile(t, srcRoot, "empty.bin", nil)

	uiS := newTestUI(t)
	ctx, cancel := ctxT(t, 30*time.Second)
	defer cancel()
	if err := sendXfer(ctx, S, R.ID(), "dir", srcRoot, uiS, seed); err != nil {
		t.Fatalf("sendXfer(dir): %v", err)
	}

	// 校验目标存在并内容一致
	checkSame := func(rel string) {
		src := filepath.Join(srcRoot, rel)
		dst := filepath.Join(outDir, rel)
		s, _ := os.ReadFile(src)
		d, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		if !bytes.Equal(s, d) {
			t.Fatalf("dir file mismatch: %s", rel)
		}
	}
	checkSame("sub/a/aa.txt")
	checkSame("sub/bb.txt")
	checkSame("empty.bin")
}

func TestXfer_OfferRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short")
	}
	const seed uint64 = 123

	S := newLoopbackHost(t)
	R := newLoopbackHost(t)
	connect(t, S, R)

	outDir := t.TempDir()
	uiR := newTestUI(t)
	askNo := func(_ string, _ time.Duration) bool { return false } // 拒绝

	R.SetStreamHandler(protoXfer, func(xs network.Stream) {
		handleIncomingXfer(context.Background(), R, xs, outDir, askNo, uiR, seed)
	})

	srcDir := t.TempDir()
	src := writeTempFile(t, srcDir, "nope.txt", []byte("xxx"))
	uiS := newTestUI(t)

	ctx, cancel := ctxT(t, 10*time.Second)
	defer cancel()
	err := sendXfer(ctx, S, R.ID(), "file", src, uiS, seed)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}
