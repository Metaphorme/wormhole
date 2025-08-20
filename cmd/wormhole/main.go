package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	spake2 "salsa.debian.org/vasudev/gospake2"
	_ "salsa.debian.org/vasudev/gospake2/ed25519group"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	client "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	pingsvc "github.com/libp2p/go-libp2p/p2p/protocol/ping"

	ma "github.com/multiformats/go-multiaddr"
	rzv "github.com/waku-org/go-libp2p-rendezvous"

	// 统一交互 UI 与进度条
	readline "github.com/chzyer/readline"
	mpb "github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// ---------- 常量与协议 ----------
const (
	chatHello  = "##HELLO"
	chatAccept = "##ACCEPT"
	chatReject = "##REJECT"
	chatBye    = "##BYE"
)

var (
	protoChat = protocol.ID("/wormhole/1.0.0/chat")
	protoXfer = protocol.ID("/wormhole/1.0.0/xfer")
)

//go:embed eff_short_wordlist_2_0.txt
var effShortWordlist []byte

// ---------- 控制面（与 server 协议保持一致） ----------
type addrBundle struct {
	Namespace string   `json:"namespace"`
	Addrs     []string `json:"addrs"`
}
type allocateResponse struct {
	Nameplate  string     `json:"nameplate"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Rendezvous addrBundle `json:"rendezvous"`
	Relay      addrBundle `json:"relay"`
	Bootstrap  []string   `json:"bootstrap,omitempty"`
	Topic      string     `json:"topic"`
}
type claimRequest struct {
	Nameplate string `json:"nameplate"`
	Side      string `json:"side"`
}
type claimResponse struct {
	Status     string     `json:"status"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Rendezvous addrBundle `json:"rendezvous"`
	Relay      addrBundle `json:"relay"`
	Bootstrap  []string   `json:"bootstrap,omitempty"`
	Topic      string     `json:"topic"`
}
type consumeRequest struct {
	Nameplate string `json:"nameplate"`
}

// ---------- 小工具 ----------
var verbose bool // 全局：是否打印详尽日志

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func ts() string {
	// 握手、询问等关键提示加时间戳
	return time.Now().Format("2006-01-02 15:04:05")
}

// 统一 UI：使用 readline，解决提示符被打断问题，且支持 ←/→ 前缀
type uiConsole struct {
	rl            *readline.Instance
	mu            sync.Mutex
	defaultPrompt string
}

func newUI(prompt string) (*uiConsole, error) {
	rl, err := readline.New(prompt)
	if err != nil {
		return nil, err
	}
	return &uiConsole{rl: rl, defaultPrompt: prompt}, nil
}
func (ui *uiConsole) Close() { _ = ui.rl.Close() } // 注意：有时会阻塞到下一次按键

func (ui *uiConsole) setPrompt(p string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.rl.SetPrompt(p)
	ui.rl.Refresh()
}
func (ui *uiConsole) resetPrompt() { ui.setPrompt(ui.defaultPrompt) }

func (ui *uiConsole) println(msg string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	_, _ = ui.rl.Stdout().Write([]byte("\r" + msg + "\n"))
	ui.rl.Refresh()
}
func (ui *uiConsole) printf(format string, a ...any) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	_, _ = ui.rl.Stdout().Write([]byte("\r" + fmt.Sprintf(format, a...)))
	ui.rl.Refresh()
}
func (ui *uiConsole) logln(msg string) { ui.println(ts() + " " + msg) }
func (ui *uiConsole) logf(format string, a ...any) {
	ui.println(ts() + " " + fmt.Sprintf(format, a...))
}
func (ui *uiConsole) promptQuestion(q string) { ui.setPrompt(q) }
func (ui *uiConsole) promptQuestionAndRestore(q string) func() {
	ui.setPrompt(q)
	return func() { ui.resetPrompt() }
}

// EFF wordlist 2.0（行形如 "11111<TAB>word"）
func effWords() []string {
	lines := strings.Split(string(effShortWordlist), "\n")
	words := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		tab := strings.Split(ln, "\t")
		if len(tab) >= 2 {
			words = append(words, tab[1])
		}
	}
	return words
}
func randWord(ws []string) string {
	if len(ws) == 0 {
		return "word"
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ws))))
	return ws[nBig.Int64()]
}

func isUnspecified(a ma.Multiaddr) bool {
	if v4, _ := a.ValueForProtocol(ma.P_IP4); v4 != "" {
		return v4 == "0.0.0.0"
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		return v6 == "::"
	}
	return false
}
func isLoopbackOrPrivate(a ma.Multiaddr) bool {
	if v4, _ := a.ValueForProtocol(ma.P_IP4); v4 != "" {
		ip := net.ParseIP(v4)
		if ip == nil {
			return false
		}
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		ip := net.ParseIP(v6)
		if ip == nil {
			return false
		}
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return false
}

// HTTP JSON（带指数退避）
func httpPostJSON[T any](ctx context.Context, base, path string, body any, out *T) error {
	u := strings.TrimRight(base, "/") + path
	const maxAttempts = 5
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var buf io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			buf = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, buf)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if ctx.Err() != nil || attempt == maxAttempts {
				return err
			}
			select {
			case <-time.After(backoff):
				backoff = time.Duration(min64(int64(backoff*2), int64(30*time.Second)))
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode/100 == 2 {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		if attempt == maxAttempts {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if n, err := time.ParseDuration(strings.TrimSpace(ra) + "s"); err == nil {
				select {
				case <-time.After(n):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		select {
		case <-time.After(backoff):
			backoff = time.Duration(min64(int64(backoff*2), int64(30*time.Second)))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return context.DeadlineExceeded
}

func parseP2pAddrInfos(addrs []string) ([]peer.AddrInfo, error) {
	seen := make(map[peer.ID]bool)
	var out []peer.AddrInfo
	for _, s := range addrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if idx := strings.Index(s, "/p2p-circuit"); idx >= 0 {
			s = s[:idx]
		}
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(m)
		if err != nil || ai.ID == "" {
			continue
		}
		if seen[ai.ID] {
			continue
		}
		seen[ai.ID] = true
		out = append(out, *ai)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid /p2p addrs")
	}
	return out, nil
}

// ---------- 帧编解码（给 XFER 与 PAKE 子握手用） ----------
func writeFrame(w io.Writer, typ byte, payload []byte) error {
	var hdr [9]byte
	hdr[0] = typ
	binary.LittleEndian.PutUint64(hdr[1:], uint64(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}
func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	n := binary.LittleEndian.Uint64(hdr[1:])
	if n > (1 << 31) {
		return 0, nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, int(n))
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
	}
	return typ, buf, nil
}

// ---------- XFER（简化可靠实现） ----------
const (
	frameOffer    = byte(0x01)
	frameAccept   = byte(0x02)
	frameReject   = byte(0x03)
	frameFileHdr  = byte(0x04)
	frameChunk    = byte(0x05)
	frameFileDone = byte(0x06)
	frameXferDone = byte(0x07)
	frameError    = byte(0x7F)
	chunkSize     = 1 << 20 // 1MiB
)

type xferOffer struct {
	Kind  string `json:"kind"`           // text|file|dir
	Name  string `json:"name,omitempty"` // file/dir 名或虚拟名
	Size  int64  `json:"size,omitempty"` // text/file 总字节
	Files int    `json:"files,omitempty"`
}

// ---------- 进度条 ----------
func newFileBar(p *mpb.Progress, name string, total int64) *mpb.Bar {
	return p.New(total,
		mpb.BarStyle(),
		mpb.BarPriority(0),        // 置顶：当前文件
		mpb.BarRemoveOnComplete(), // 完成后移除
		mpb.PrependDecorators(
			decor.Name(name+" ", decor.WC{C: decor.DindentRight}),
			decor.CountersKibiByte("% .1f / % .1f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" | "),
			// FIX: 用 EWMA 速度，短文件也能稳定显示
			decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30),
			decor.Name(" | "),
			decor.EwmaETA(decor.ET_STYLE_MMSS, 30),
		),
	)
}

func newTotalBar(p *mpb.Progress, total int64) *mpb.Bar {
	return p.New(total,
		mpb.BarStyle(),
		mpb.BarPriority(1), // 总体放在第二行
		mpb.PrependDecorators(
			decor.Name("TOTAL ", decor.WC{C: decor.DindentRight}),
			decor.CountersKibiByte("% .1f / % .1f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" | "),
			// FIX: TOTAL 也显示 EWMA 速度
			decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30),
			decor.Name(" | "),
			decor.EwmaETA(decor.ET_STYLE_MMSS, 30),
		),
	)
}

func sendXfer(ctx context.Context, h host.Host, remote peer.ID, kind, arg string, ui *uiConsole) error {
	xs, err := h.NewStream(ctx, remote, protoXfer)
	if err != nil {
		return err
	}
	defer xs.Close()

	var off xferOffer
	switch kind {
	case "text":
		off = xferOffer{Kind: "text", Name: "message.txt", Size: int64(len(arg))}
	case "file":
		st, err := os.Stat(arg)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("not a regular file")
		}
		off = xferOffer{Kind: "file", Name: filepath.Base(arg), Size: st.Size()}
	case "dir":
		cnt := 0
		var total int64
		filepath.WalkDir(arg, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if st, er := os.Stat(path); er == nil && st.Mode().IsRegular() {
					cnt++
					total += st.Size()
				}
			}
			return nil
		})
		off = xferOffer{Kind: "dir", Name: filepath.Base(arg), Files: cnt, Size: total}
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}

	b, _ := json.Marshal(off)
	if err := writeFrame(xs, frameOffer, b); err != nil {
		return err
	}
	typ, _, err := readFrame(xs)
	if err != nil {
		return err
	}
	if typ == frameReject {
		return fmt.Errorf("peer rejected")
	}
	if typ != frameAccept {
		return fmt.Errorf("unexpected response")
	}

	// 进度条容器（仅 file/dir）
	var p *mpb.Progress
	var fileBar, totalBar *mpb.Bar
	if (off.Kind == "file" && off.Size > 0) || (off.Kind == "dir" && off.Size > 0) {
		p = mpb.New(
			mpb.WithWidth(64),
			// FIX: 稍微快一点的刷新，短传输更容易看到速度
			mpb.WithRefreshRate(120*time.Millisecond),
			// ✅ 渲染到 stderr，避免和 readline 冲突
			mpb.WithOutput(os.Stderr),
		)
		if off.Kind == "file" && off.Size > 0 {
			fileBar = newFileBar(p, off.Name, off.Size)
		} else if off.Kind == "dir" && off.Size > 0 {
			totalBar = newTotalBar(p, off.Size)
		}
	} else if off.Kind == "file" && off.Size == 0 {
		ui.println("note: sending empty file; no per-file progress bar will be shown")
	}

	createdBar := func() bool { return fileBar != nil || totalBar != nil }

	// 发送单个文件（并驱动进度条）
	sendOneFile := func(name string, r io.Reader, size int64) error {
		// 目录模式：切换“当前文件”条
		if p != nil && totalBar != nil {
			if fileBar != nil {
				fileBar.Abort(true)
				fileBar.Wait()
			}
			if size > 0 {
				fileBar = newFileBar(p, name, size)
				// FIX: 调整起始时间，Average/EWMA 装饰器都受益
				fileBar.DecoratorAverageAdjust(time.Now())
			} else {
				fileBar = nil
			}
		}
		if fileBar != nil && totalBar == nil {
			fileBar.DecoratorAverageAdjust(time.Now())
		}
		if totalBar != nil {
			totalBar.DecoratorAverageAdjust(time.Now())
		}

		hdr := map[string]any{"name": name, "size": size}
		b, _ := json.Marshal(hdr)
		if err := writeFrame(xs, frameFileHdr, b); err != nil {
			return err
		}
		buf := make([]byte, chunkSize)
		var sent int64
		for {
			if size >= 0 && sent >= size {
				break
			}
			start := time.Now()
			n, er := r.Read(buf)
			if n > 0 {
				sent += int64(n)
				if err := writeFrame(xs, frameChunk, buf[:n]); err != nil {
					return err
				}
				// FIX: 使用 EWMA 计时更新，驱动 EwmaSpeed/EwmaETA
				if fileBar != nil {
					fileBar.EwmaIncrBy(n, time.Since(start))
				}
				if totalBar != nil {
					totalBar.EwmaIncrBy(n, time.Since(start))
				}
			}
			if er == io.EOF {
				break
			}
			if er != nil {
				return er
			}
		}
		if err := writeFrame(xs, frameFileDone, nil); err != nil {
			return err
		}
		if fileBar != nil {
			fileBar.SetTotal(size, true)
		}
		return nil
	}

	switch off.Kind {
	case "text":
		_ = sendOneFile(off.Name, strings.NewReader(arg), off.Size)
	case "file":
		f, err := os.Open(arg)
		if err != nil {
			return err
		}
		defer f.Close()
		_ = sendOneFile(off.Name, f, off.Size)
	case "dir":
		root := arg
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			st, er := os.Stat(path)
			if er != nil || !st.Mode().IsRegular() {
				return nil
			}
			f, er := os.Open(path)
			if er != nil {
				return nil
			}
			defer f.Close()
			_ = sendOneFile(rel, f, st.Size())
			return nil
		})
		if totalBar != nil {
			totalBar.SetTotal(off.Size, true)
		}
	}

	// 先通知接收端传输结束，再等待本地进度条退出
	if err := writeFrame(xs, frameXferDone, nil); err != nil {
		return err
	}
	if p != nil && createdBar() {
		p.Wait()
		ui.rl.Refresh()
	}
	_ = xs.CloseWrite()
	return nil
}

type promptReq struct {
	question string
	resp     chan bool
}

func tryDequeuePrompt(ch chan *promptReq) *promptReq {
	select {
	case p := <-ch:
		return p
	default:
		return nil
	}
}

func handleIncomingXfer(ctx context.Context, h host.Host, xs network.Stream, outDir string, askYesNo func(q string, timeout time.Duration) bool, ui *uiConsole) {
	defer xs.Close()
	typ, payload, err := readFrame(xs)
	if err != nil || typ != frameOffer {
		return
	}
	var off xferOffer
	_ = json.Unmarshal(payload, &off)

	info := ""
	switch off.Kind {
	case "text":
		info = fmt.Sprintf("Peer wants to send a TEXT (%d bytes).", off.Size)
	case "file":
		info = fmt.Sprintf("Peer wants to send file %q (%d bytes).", off.Name, off.Size)
	case "dir":
		info = fmt.Sprintf("Peer wants to send directory %q (%d files, total %d bytes).", off.Name, off.Files, off.Size)
	}
	ui.logln(info)
	if !askYesNo("Accept? [y/N]: ", 30*time.Second) {
		_ = writeFrame(xs, frameReject, nil)
		return
	}
	if err := writeFrame(xs, frameAccept, nil); err != nil {
		return
	}

	var fw *os.File
	var dstPath string
	for {
		typ, payload, err = readFrame(xs)
		if err != nil {
			return
		}
		switch typ {
		case frameFileHdr:
			var hdr struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
			}
			_ = json.Unmarshal(payload, &hdr)
			dstPath = filepath.Join(outDir, hdr.Name)
			_ = os.MkdirAll(filepath.Dir(dstPath), 0o755)
			fw, err = os.Create(dstPath)
			if err != nil {
				_ = writeFrame(xs, frameError, []byte(err.Error()))
				return
			}
		case frameChunk:
			if fw != nil {
				_, _ = fw.Write(payload)
			}
		case frameFileDone:
			if fw != nil {
				_ = fw.Close()
				fw = nil
				ui.println("← received: " + dstPath)
			}
		case frameXferDone:
			return
		case frameError:
			ui.println("← xfer error: " + string(payload))
			return
		default:
			return
		}
	}
}

// ---------- PAKE（SPAKE2）+ key-confirm + SAS ----------
const (
	framePakeMsg     = byte(0x10)
	framePakeConfirm = byte(0x11)
	framePakeAbort   = byte(0x1F)
)

func buildTranscript(nameplate string, proto protocol.ID, a, b peer.ID) []byte {
	ids := []string{a.String(), b.String()}
	if ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	s := strings.Join([]string{"wormhole-pake-v1", nameplate, string(proto), ids[0], ids[1]}, "|")
	return []byte(s)
}
func hkdfBytes(ikm []byte, label string, transcript []byte, n int) []byte {
	info := append([]byte(label+"|"), transcript...)
	r := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	_, _ = io.ReadFull(r, out)
	return out
}
func emojiList() []string {
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
func sasFromKey(K []byte, transcript []byte) string {
	em := emojiList()
	b := hkdfBytes(K, "sas", transcript, 4) // 32 bits
	acc := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	parts := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		idx := (acc >> (i * 6)) & 0x3F
		parts = append(parts, em[idx%uint32(len(em))])
	}
	return strings.Join(parts, " ")
}

// roleA=true 表示拨号端（A）；false 表示监听端（B）
func runPAKEAndConfirm(ctx context.Context, s network.Stream, roleA bool, passphrase, nameplate string, proto protocol.ID, local, remote peer.ID) ([]byte, error) {
	transcript := buildTranscript(nameplate, proto, local, remote)
	pw := spake2.NewPassword(passphrase)
	var state spake2.SPAKE2
	if roleA {
		state = spake2.SPAKE2A(pw, spake2.NewIdentityA(local.String()), spake2.NewIdentityB(remote.String()))
	} else {
		state = spake2.SPAKE2B(pw, spake2.NewIdentityA(remote.String()), spake2.NewIdentityB(local.String()))
	}

	my := state.Start()
	if roleA {
		if err := writeFrame(s, framePakeMsg, my); err != nil {
			return nil, err
		}
		typ, peerMsg, err := readFrame(s)
		if err != nil || typ != framePakeMsg {
			return nil, fmt.Errorf("pake: bad peer msg")
		}
		K, err := state.Finish(peerMsg)
		if err != nil {
			return nil, fmt.Errorf("pake finish: %w", err)
		}
		Kc := hkdfBytes(K, "confirm", transcript, 32)
		macA := hmac.New(sha256.New, Kc)
		macA.Write([]byte("A|"))
		macA.Write(transcript)
		if err := writeFrame(s, framePakeConfirm, macA.Sum(nil)); err != nil {
			return nil, err
		}
		typ, tagB, err := readFrame(s)
		if err != nil || typ != framePakeConfirm {
			return nil, fmt.Errorf("pake: no cB")
		}
		macB := hmac.New(sha256.New, Kc)
		macB.Write([]byte("B|"))
		macB.Write(transcript)
		if !hmac.Equal(macB.Sum(nil), tagB) {
			_ = writeFrame(s, framePakeAbort, nil)
			return nil, fmt.Errorf("pake: key-confirm failed (cB)")
		}
		return K, nil
	} else {
		typ, peerMsg, err := readFrame(s)
		if err != nil || typ != framePakeMsg {
			return nil, fmt.Errorf("pake: bad peer msg")
		}
		K, err := state.Finish(peerMsg)
		if err != nil {
			return nil, fmt.Errorf("pake finish: %w", err)
		}
		my2 := state.Start()
		if err := writeFrame(s, framePakeMsg, my2); err != nil {
			return nil, err
		}
		Kc := hkdfBytes(K, "confirm", transcript, 32)
		typ, tagA, err := readFrame(s)
		if err != nil || typ != framePakeConfirm {
			return nil, fmt.Errorf("pake: no cA")
		}
		macA := hmac.New(sha256.New, Kc)
		macA.Write([]byte("A|"))
		macA.Write(transcript)
		if !hmac.Equal(macA.Sum(nil), tagA) {
			_ = writeFrame(s, framePakeAbort, nil)
			return nil, fmt.Errorf("pake: key-confirm failed (cA)")
		}
		macB := hmac.New(sha256.New, Kc)
		macB.Write([]byte("B|"))
		macB.Write(transcript)
		if err := writeFrame(s, framePakeConfirm, macB.Sum(nil)); err != nil {
			return nil, err
		}
		return K, nil
	}
}

// ---------- /chat 会话（集成 PAKE + SAS + 路径提示） ----------
func readLineWithDeadline(rw *bufio.ReadWriter, s network.Stream, d time.Duration) (string, error) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	defer s.SetReadDeadline(time.Time{})
	line, err := rw.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func printConnSummary(ui *uiConsole, local, remote ma.Multiaddr) {
	ui.println("connected:")
	ui.println("  local : " + local.String())
	ui.println("  remote: " + remote.String())
}

func helpText() string {
	return `Commands:
  /send -t <text>          send a short text
  /send -f <file>          send a file
  /send -d <dir>           send a directory recursively
  /bye                     close the chat`
}

// ---- 路径识别（DIRECT / RELAY via <RelayID>） ----
var reRelayBeforeCircuit = regexp.MustCompile(`/p2p/([^/]+)/p2p-circuit`)

func transportHint(a ma.Multiaddr) string {
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

type pathInfo struct {
	Kind       string // "DIRECT" or "RELAY"
	RelayID    string // if Kind == RELAY
	RelayVia   string // base relay addr
	Transport  string
	LocalAddr  string
	RemoteAddr string
}

func classifyPath(c network.Conn) pathInfo {
	pi := pathInfo{
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
		pi.Transport = transportHint(rm)
		pi.RelayVia = rs[:strings.Index(rs, "/p2p-circuit")]
		return pi
	}
	if m := reRelayBeforeCircuit.FindStringSubmatch(ls); len(m) == 2 {
		pi.Kind = "RELAY"
		pi.RelayID = m[1]
		pi.Transport = transportHint(lm)
		pi.RelayVia = ls[:strings.Index(ls, "/p2p-circuit")]
		return pi
	}
	pi.Kind = "DIRECT"
	if strings.Contains(rs, "/p2p/") && !strings.Contains(rs, "/p2p-circuit") {
		pi.Transport = transportHint(rm)
	} else {
		pi.Transport = transportHint(lm)
	}
	return pi
}

func askYesNoWithReadline(ui *uiConsole, question string, timeout time.Duration, defaultNo bool) bool {
	restore := ui.promptQuestionAndRestore(question)
	defer restore()

	ansCh := make(chan string, 1)
	go func() {
		line, err := ui.rl.Readline()
		if err != nil {
			ansCh <- ""
			return
		}
		ansCh <- strings.TrimSpace(line)
	}()
	select {
	case a := <-ansCh:
		al := strings.ToLower(a)
		return al == "y" || al == "yes"
	case <-time.After(timeout):
		ui.println("")    // 换行美化
		return !defaultNo // 希望超时默认接受时返回 true；默认拒绝则 false
	}
}

func runAccepted(ctx context.Context, h host.Host, s network.Stream, outDir string, verify bool, nameplate, passphrase string) {
	// 如果（真正的）SIGINT 到达，立刻打断读并半关写，避免读循环阻塞
	go func() {
		<-ctx.Done()
		_ = s.CloseRead()  // 立刻让扫描器/reader返回错误（不等远端）
		_ = s.CloseWrite() // 通知对端我们不再写
	}()
	remote := s.Conn().RemotePeer()
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	ui, err := newUI("> ")
	if err != nil {
		fmt.Println("init console failed:", err)
		_ = s.Close()
		return
	}
	// FIX: 不使用 defer ui.Close()，避免 Close() 阻塞退出；改为需要时异步关闭

	// —— 握手：HELLO -> (PAKE+confirm) -> 人工确认 ——
	if s.Stat().Direction == network.DirInbound {
		line, err := readLineWithDeadline(rw, s, 30*time.Second)
		if err != nil || !strings.HasPrefix(line, chatHello) {
			ui.logln("handshake failed: did not receive valid HELLO in time")
			_ = s.Close()
			go ui.Close() // FIX: 异步关闭
			return
		}
		K, err := runPAKEAndConfirm(ctx, s, false, passphrase, nameplate, protoChat, h.ID(), remote)
		if err != nil {
			ui.logf("PAKE failed: %v", err)
			_ = s.Close()
			go ui.Close()
			return
		}
		sas := sasFromKey(K, buildTranscript(nameplate, protoChat, h.ID(), remote))
		ui.logf("Remote PeerID: %s | SAS: %s", remote.String(), sas)
		prompt := fmt.Sprintf("[%s] Confirm peer within 30s [y/N]: ", ts())
		accepted := askYesNoWithReadline(ui, prompt, 30*time.Second, true)
		if !accepted {
			fmt.Fprintln(rw, chatReject)
			_ = rw.Flush()
			_ = s.Close()
			go ui.Close()
			ui.logln("aborted")
			return
		}
		fmt.Fprintln(rw, chatAccept)
		if err := rw.Flush(); err != nil {
			_ = s.Close()
			go ui.Close()
			ui.logln("handshake failed: write accept error")
			return
		}
		peerAck, err := readLineWithDeadline(rw, s, 30*time.Second)
		if err != nil {
			_ = s.Close()
			go ui.Close()
			ui.logln("handshake failed: peer didn't confirm in time")
			return
		}
		switch strings.TrimSpace(peerAck) {
		case chatAccept:
		case chatReject:
			_ = s.Close()
			go ui.Close()
			ui.logln("handshake failed: peer rejected the verification")
			return
		default:
			_ = s.Close()
			go ui.Close()
			ui.logln("handshake failed: unexpected response")
			return
		}
	} else {
		fmt.Fprintf(rw, "%s %s\n", chatHello, h.ID().String())
		if err := rw.Flush(); err != nil {
			ui.logln("handshake failed: cannot write hello")
			_ = s.Close()
			go ui.Close()
			return
		}
		K, err := runPAKEAndConfirm(ctx, s, true, passphrase, nameplate, protoChat, h.ID(), remote)
		if err != nil {
			ui.logf("PAKE failed: %v", err)
			_ = s.Close()
			go ui.Close()
			return
		}
		sas := sasFromKey(K, buildTranscript(nameplate, protoChat, h.ID(), remote))
		ui.logf("Waiting for peer confirmation… | SAS: %s | remote=%s", sas, remote)

		localAccepted := true
		if verify {
			localAccepted = askYesNoWithReadline(ui,
				fmt.Sprintf("[%s] Verify peer locally within 30s [y/N]: ", ts()),
				30*time.Second, true)
			if !localAccepted {
				_ = s.Close()
				go ui.Close()
				ui.logln("local reject or timeout")
				return
			}
		}
		peerAck, err := readLineWithDeadline(rw, s, 30*time.Second)
		if err != nil {
			ui.logln("handshake failed: peer didn't confirm in time")
			_ = s.Close()
			go ui.Close()
			return
		}
		switch strings.TrimSpace(peerAck) {
		case chatAccept:
			fmt.Fprintln(rw, chatAccept)
			if err := rw.Flush(); err != nil {
				_ = s.Close()
				go ui.Close()
				ui.logln("handshake failed: write accept error")
				return
			}
		case chatReject:
			ui.logln("handshake failed: peer rejected the verification")
			_ = s.Close()
			go ui.Close()
			return
		default:
			ui.logln("handshake failed: unexpected response")
			_ = s.Close()
			go ui.Close()
			return
		}
	}

	printConnSummary(ui, s.Conn().LocalMultiaddr(), s.Conn().RemoteMultiaddr())

	// 路径展示
	pi := classifyPath(s.Conn())
	if pi.Kind == "RELAY" {
		ui.println(fmt.Sprintf("path: RELAY via %s (%s)", pi.RelayID, pi.Transport))
		if verbose {
			ui.println("via addr: " + pi.RelayVia)
		}
	} else {
		ui.println(fmt.Sprintf("path: DIRECT (%s)", pi.Transport))
	}

	// 安装 XFER handler + 提示通道
	promptCh := make(chan *promptReq, 4)
	askYesNo := func(q string, timeout time.Duration) bool {
		pr := &promptReq{question: q, resp: make(chan bool, 1)}
		ui.promptQuestion(q)
		promptCh <- pr
		select {
		case r := <-pr.resp:
			return r
		case <-time.After(timeout):
			ui.resetPrompt()
			return false
		}
	}
	h.SetStreamHandler(protoXfer, func(xs network.Stream) {
		go handleIncomingXfer(ctx, h, xs, outDir, askYesNo, ui)
	})
	defer h.RemoveStreamHandler(protoXfer)

	ui.println(helpText())
	ui.println("connected. type message to chat, or a command starting with '/'.")

	done := make(chan struct{})
	reasonCh := make(chan string, 1)
	var once sync.Once
	thisConn := s.Conn()

	// 连接断开时：立即停止 readline（异步 Close），结束输入循环
	notifiee := &network.NotifyBundle{
		DisconnectedF: func(_ network.Network, c network.Conn) {
			if c == thisConn {
				go ui.Close() // FIX: 异步关闭，避免阻塞
				once.Do(func() {
					reasonCh <- "peer disconnected"
					close(done)
				})
			}
		},
	}
	h.Network().Notify(notifiee)
	defer h.Network().StopNotify(notifiee)

	// 接收对端消息 → 安全打印
	go func() {
		r := bufio.NewScanner(rw.Reader)
		for r.Scan() {
			txt := r.Text()
			if strings.HasPrefix(txt, chatBye) {
				once.Do(func() {
					go ui.Close() // FIX: 异步关闭
					reasonCh <- "peer closed the chat"
					close(done)
				})
				return
			}
			if strings.TrimSpace(txt) == "" {
				continue
			}
			ui.println("← " + txt)
		}
		once.Do(func() {
			go ui.Close() // ✅ 对端读流结束也要关 UI，否则要按回车
			reasonCh <- "peer closed the stream"
			close(done)
		})
	}()

	// 输入循环（readline）
	go func() {
		w := rw.Writer

		handleSlash := func(cmd string) bool {
			switch {
			case cmd == "/bye":
				fmt.Fprintln(w, chatBye)
				_ = w.Flush()
				once.Do(func() {
					reasonCh <- "you closed the chat"
					close(done)
				})
				_ = s.CloseRead()  // 先打断本地读
				_ = s.CloseWrite() // 再半关写
				go ui.Close()
				return true
			case strings.HasPrefix(cmd, "/send "):
				rest := strings.TrimSpace(strings.TrimPrefix(cmd, "/send"))
				if rest == "" {
					ui.println("usage: /send -t <text> | -f <file> | -d <dir>")
					return true
				}
				as := strings.Fields(rest)
				var textArg, fileArg, dirArg string
				for i := 0; i < len(as); i++ {
					switch as[i] {
					case "-t":
						i++
						if i < len(as) {
							textArg = strings.Join(as[i:], " ")
							i = len(as)
						}
					case "-f":
						i++
						if i < len(as) {
							fileArg = as[i]
						}
					case "-d":
						i++
						if i < len(as) {
							dirArg = as[i]
						}
					}
				}
				kind := ""
				arg := ""
				switch {
				case textArg != "":
					kind, arg = "text", textArg
				case fileArg != "":
					kind, arg = "file", fileArg
				case dirArg != "":
					kind, arg = "dir", dirArg
				}
				if kind == "" {
					ui.println("usage: /send -t <text> | -f <file> | -d <dir>")
					return true
				}
				ui.println("sending...")
				if err := sendXfer(ctx, h, thisConn.RemotePeer(), kind, arg, ui); err != nil {
					ui.println("send failed: " + err.Error())
				} else {
					ui.println("xfer done.")
				}
				return true
			}
			return false
		}

		for {
			txt, err := ui.rl.Readline()
			if err != nil {
				// 关键点：第一次 Ctrl+C 不会触发 SIGINT，而是 ErrInterrupt
				if errors.Is(err, readline.ErrInterrupt) {
					// 当作本地 /bye：告诉对端，随后打断读并关 UI
					fmt.Fprintln(w, chatBye)
					_ = w.Flush()
					once.Do(func() {
						reasonCh <- "interrupted (^C)"
						close(done)
					})
					_ = s.CloseRead()
					_ = s.CloseWrite()
					go ui.Close()
					return
				}
				if errors.Is(err, io.EOF) {
					// Ctrl+D 空行 / stdin 关闭：也直接收尾
					once.Do(func() {
						reasonCh <- "stdin closed"
						close(done)
					})
					_ = s.CloseRead()
					_ = s.CloseWrite()
					go ui.Close()
					return
				}
				// 其它错误：保守处理为立即收尾
				once.Do(func() {
					reasonCh <- "readline error"
					close(done)
				})
				_ = s.CloseRead()
				_ = s.CloseWrite()
				go ui.Close()
				return
			}
			line := strings.TrimRight(txt, "\r\n")
			// 若有挂起的 yes/no 提示，本次输入用于回答
			if pending := tryDequeuePrompt(promptCh); pending != nil {
				al := strings.ToLower(strings.TrimSpace(line))
				pending.resp <- (al == "y" || al == "yes")
				ui.resetPrompt()
				continue
			}
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "/") {
				if handleSlash(trim) {
					continue
				}
			}
			if trim == "" {
				continue
			}
			ui.println("→ " + line)
			fmt.Fprintln(w, line)
			_ = w.Flush()
		}
	}()

	reason := <-reasonCh
	ui.println(reason)
	// 确保两侧都被打断并收尾
	_ = s.CloseRead()
	_ = s.CloseWrite()
	_ = s.Close()
	go ui.Close()
	// 函数直接返回，不做阻塞等待
}

// ---------- libp2p host & 连接/发现 ----------

// 基于服务端下发的静态 relay 候选，启用 AutoRelay 与 DCUtR，开启 NATPortMap
func newHost(staticRelay *peer.AddrInfo, extraListen []ma.Multiaddr) (host.Host, error) {
	opts := []libp2p.Option{
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
	}
	if staticRelay != nil {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{*staticRelay}))
	}
	if len(extraListen) > 0 {
		opts = append(opts, libp2p.ListenAddrs(extraListen...))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	pingsvc.NewPingService(h)
	if staticRelay != nil {
		h.Peerstore().AddAddrs(staticRelay.ID, staticRelay.Addrs, time.Hour)
	}
	return h, nil
}

func connectAny(ctx context.Context, h host.Host, addrs []peer.AddrInfo) (*peer.AddrInfo, error) {
	for _, ai := range addrs {
		if err := h.Connect(ctx, ai); err == nil {
			return &ai, nil
		}
	}
	return nil, fmt.Errorf("connectAny failed")
}

func reserveAnyRelay(ctx context.Context, h host.Host, relays []peer.AddrInfo) *peer.AddrInfo {
	for _, ai := range relays {
		_ = h.Connect(ctx, ai)
		if _, err := client.Reserve(ctx, h, ai); err == nil {
			return &ai
		}
	}
	return nil
}

// 构造“经 relay 的自我地址”
func buildCircuitSelfAddrs(relay *peer.AddrInfo, self peer.ID) []ma.Multiaddr {
	var out []ma.Multiaddr
	if relay == nil {
		return out
	}
	for _, ra := range relay.Addrs {
		s := ra.String()
		if !strings.Contains(s, "/p2p/") {
			s += "/p2p/" + relay.ID.String()
		}
		s += "/p2p-circuit/p2p/" + self.String()
		if via, err := ma.NewMultiaddr(s); err == nil {
			out = append(out, via)
		}
	}
	return out
}

func rendezvousAddrsFactory(h host.Host, reservedRelay *peer.AddrInfo, allowLocal bool) rzv.AddrsFactory {
	return func(addrs []ma.Multiaddr) []ma.Multiaddr {
		seen := make(map[string]bool)
		var out []ma.Multiaddr
		for _, a := range addrs {
			if isUnspecified(a) {
				continue
			}
			if allowLocal || !isLoopbackOrPrivate(a) {
				k := a.String()
				if !seen[k] {
					out = append(out, a)
					seen[k] = true
				}
			}
		}
		if reservedRelay != nil {
			for _, via := range buildCircuitSelfAddrs(reservedRelay, h.ID()) {
				k := via.String()
				if !seen[k] {
					out = append(out, via)
					seen[k] = true
				}
			}
		}
		if len(out) == 0 {
			return addrs
		}
		return out
	}
}

// 从远端 relayed 地址中提取它所用的中继
func mergeRelaysFromRemote(remote peer.AddrInfo, known []peer.AddrInfo) []peer.AddrInfo {
	merged := make(map[peer.ID]peer.AddrInfo)
	for _, r := range known {
		merged[r.ID] = r
	}
	for _, a := range remote.Addrs {
		s := a.String()
		idx := strings.Index(s, "/p2p-circuit")
		if idx < 0 {
			continue
		}
		base := s[:idx]
		m, err := ma.NewMultiaddr(base)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(m)
		if err != nil || ai.ID == "" {
			continue
		}
		if cur, ok := merged[ai.ID]; ok {
			cur.Addrs = append(cur.Addrs, ai.Addrs...)
			merged[ai.ID] = cur
		} else {
			merged[ai.ID] = *ai
		}
	}
	out := make([]peer.AddrInfo, 0, len(merged))
	for _, ai := range merged {
		out = append(out, ai)
	}
	return out
}

// 判断发现到的远端地址是否“全部为 relayed”
func allRelayedAddrs(ai peer.AddrInfo) bool {
	if len(ai.Addrs) == 0 {
		return false
	}
	for _, a := range ai.Addrs {
		if !strings.Contains(a.String(), "/p2p-circuit") {
			return false
		}
	}
	return true
}

// tryOpenChat：在窗口期内循环 Discover + 拨号
func tryOpenChat(ctx context.Context, h host.Host, rzvc rzv.RendezvousClient, topic string, relays []peer.AddrInfo, maxWait time.Duration, relayFirst bool) (network.Stream, error) {
	deadline := time.Now().Add(maxWait)
	var lastErr error

	for time.Now().Before(deadline) {
		infos, _, err := rzvc.Discover(ctx, topic, 64, nil)
		if err != nil || len(infos) == 0 {
			if err != nil {
				lastErr = fmt.Errorf("discover: %w", err)
			} else {
				lastErr = fmt.Errorf("discover: no peers yet")
			}
			time.Sleep(1200 * time.Millisecond)
			continue
		}

		dialDirect := func(remote peer.AddrInfo) (network.Stream, error) {
			dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			_ = h.Connect(dialCtx, remote)
			return h.NewStream(dialCtx, remote.ID, protoChat)
		}
		dialViaRelay := func(remote peer.AddrInfo, allRelays []peer.AddrInfo) (network.Stream, error) {
			if len(allRelays) == 0 {
				return nil, fmt.Errorf("no relays")
			}
			dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			for _, r := range allRelays {
				_ = h.Connect(dialCtx, r)
			}
			for _, r := range allRelays {
				for _, a := range r.Addrs {
					viaStr := a.String()
					if !strings.Contains(viaStr, "/p2p/") {
						viaStr += fmt.Sprintf("/p2p/%s", r.ID.String())
					}
					viaStr += fmt.Sprintf("/p2p-circuit/p2p/%s", remote.ID.String())
					if via, err := ma.NewMultiaddr(viaStr); err == nil {
						h.Peerstore().AddAddr(remote.ID, via, 2*time.Minute)
					}
				}
			}
			_ = h.Connect(dialCtx, remote)
			return h.NewStream(dialCtx, remote.ID, protoChat)
		}

		for _, remote := range infos {
			remoteRelays := mergeRelaysFromRemote(remote, relays)
			preferRelay := relayFirst || allRelayedAddrs(remote) || len(remoteRelays) > 0

			var s network.Stream
			if preferRelay {
				if s, err = dialViaRelay(remote, remoteRelays); err == nil {
					return s, nil
				}
				lastErr = err
				if s, err = dialDirect(remote); err == nil {
					return s, nil
				}
				lastErr = err
			} else {
				if s, err = dialDirect(remote); err == nil {
					return s, nil
				}
				lastErr = err
				if s, err = dialViaRelay(remote, remoteRelays); err == nil {
					return s, nil
				}
				lastErr = err
			}
		}
		time.Sleep(1200 * time.Millisecond)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to establish stream (no peers or no dialable addrs)")
	}
	return nil, lastErr
}

// ---------- 主函数 ----------
func main() {
	var controlURL string
	var code string
	var mode string
	var listen string
	var outDir string
	var verify bool
	var jsonOut bool
	var dlDir string

	flag.StringVar(&controlURL, "control", "http://127.0.0.1:8080", "control-plane base URL, e.g. http://ctrl:8080")
	flag.StringVar(&code, "code", "", "connect: code '<nameplate>-<word>-<word>'")
	flag.StringVar(&mode, "mode", "host", "host|connect")
	flag.StringVar(&listen, "listen", "", "optional listen multiaddrs (comma-separated)")
	flag.StringVar(&outDir, "outdir", ".", "directory to save incoming files")
	flag.StringVar(&dlDir, "download-dir", "", "download directory (alias of -outdir)")
	flag.BoolVar(&verify, "verify", true, "require local confirmation (y/N) on dialer side")
	flag.BoolVar(&jsonOut, "json", false, "emit JSON logs (reserved)")
	flag.BoolVar(&verbose, "verbose", false, "print verbose logs (reservation/announce addrs, etc.)")
	flag.Parse()
	_ = jsonOut

	if dlDir != "" {
		outDir = dlDir
	}

	// 自动“本机调试模式”判定
	isLocalDev := func(u string) bool {
		pu, err := url.Parse(u)
		if err != nil {
			return false
		}
		h := pu.Hostname()
		return h == "127.0.0.1" || h == "localhost"
	}(controlURL)

	// listen 补默认 loopback
	var extraListen []ma.Multiaddr
	if listen == "" && isLocalDev {
		def := []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
			"/ip4/127.0.0.1/tcp/0/ws",
		}
		for _, s := range def {
			a, _ := ma.NewMultiaddr(s)
			extraListen = append(extraListen, a)
		}
	} else if listen != "" {
		for _, s := range strings.Split(listen, ",") {
			a, err := ma.NewMultiaddr(strings.TrimSpace(s))
			if err != nil {
				log.Fatalf("bad listen: %v", err)
			}
			extraListen = append(extraListen, a)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var rendezvousAIs, relayAIs []peer.AddrInfo
	var topic string
	var nameplate string
	var passphrase string

	switch mode {
	case "host":
		var alloc allocateResponse
		if err := httpPostJSON(ctx, controlURL, "/v1/allocate", nil, &alloc); err != nil {
			log.Fatalf("allocate: %v", err)
		}
		nameplate = alloc.Nameplate
		topic = alloc.Topic
		var err error
		rendezvousAIs, err = parseP2pAddrInfos(alloc.Rendezvous.Addrs)
		if err != nil {
			log.Fatalf("rendezvous addrs: %v", err)
		}
		relayAIs, _ = parseP2pAddrInfos(alloc.Relay.Addrs)

		ws := effWords()
		w1, w2 := randWord(ws), randWord(ws)
		passphrase = fmt.Sprintf("%s-%s", w1, w2)
		fullCode := fmt.Sprintf("%s-%s", nameplate, passphrase)
		fmt.Printf("hosting at code=%q (expires: %s)\n", fullCode, alloc.ExpiresAt.UTC().Format(time.RFC3339))

	case "connect":
		if code == "" {
			log.Fatalf("please pass -code '<nameplate>-<word>-<word>'")
		}
		parts := strings.Split(code, "-")
		if len(parts) < 3 {
			log.Fatalf("bad code format: want '<nameplate>-<word>-<word>'")
		}
		nameplate = parts[0]
		passphrase = strings.Join(parts[1:], "-")
		var clm claimResponse
		if err := httpPostJSON(ctx, controlURL, "/v1/claim", claimRequest{Nameplate: nameplate, Side: "connect"}, &clm); err != nil {
			log.Fatalf("claim: %v", err)
		}
		if clm.Status == "failed" {
			log.Fatalf("claim failed (possibly invalid/expired/duplicate). Ask the host to allocate a new code and retry.")
		}
		topic = clm.Topic
		var err error
		rendezvousAIs, err = parseP2pAddrInfos(clm.Rendezvous.Addrs)
		if err != nil {
			log.Fatalf("rendezvous addrs: %v", err)
		}
		relayAIs, _ = parseP2pAddrInfos(clm.Relay.Addrs)

	default:
		log.Fatalf("unknown -mode %q", mode)
	}

	// —— 分离“候选中继”与“已预约中继” —— //
	var autoRelayCandidate *peer.AddrInfo
	if len(relayAIs) > 0 {
		autoRelayCandidate = &relayAIs[0]
	}
	var reservedRelay *peer.AddrInfo

	h, err := newHost(autoRelayCandidate, extraListen)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	// 连接 rendezvous
	if _, err := connectAny(ctx, h, rendezvousAIs); err != nil {
		log.Fatalf("connect rendezvous: %v", err)
	}

	// 预约任意可用 relay；仅当成功后才用于拼接 /p2p-circuit 自身地址
	if len(relayAIs) > 0 {
		if r := reserveAnyRelay(ctx, h, relayAIs); r == nil {
			if verbose {
				fmt.Println("warn: relay reservation failed (will still try direct & autorelay)")
			}
		} else {
			reservedRelay = r
			h.Peerstore().AddAddrs(reservedRelay.ID, reservedRelay.Addrs, time.Hour)
			h.ConnManager().Protect(reservedRelay.ID, "relay")
			if verbose {
				fmt.Printf("relay reservation OK via %s (%d addrs)\n", reservedRelay.ID, len(reservedRelay.Addrs))
			}
		}
	}

	// —— 按场景选择发布策略 —— //
	addrFac := rendezvousAddrsFactory(h, reservedRelay, isLocalDev)

	rzvPeer := rendezvousAIs[0].ID
	rp := rzv.NewRendezvousPoint(
		h, rzvPeer,
		rzv.ClientWithAddrsFactory(addrFac),
	)
	rzvc := rzv.NewRendezvousClientWithPoint(rp)

	// 调试输出：预览将发布给 rendezvous 的地址列表（仅 verbose）
	if verbose {
		pub := addrFac(h.Addrs())
		if len(pub) > 0 {
			fmt.Println("announce addrs:")
			for _, a := range pub {
				fmt.Println("  ", a.String())
			}
		}
	}

	switch mode {
	case "host":
		if _, err := rzvc.Register(ctx, topic, 120); err != nil {
			log.Fatalf("rendezvous register: %v", err)
		}
		inbound := make(chan network.Stream, 1)
		var acceptOnce sync.Once
		h.SetStreamHandler(protoChat, func(s network.Stream) {
			ok := false
			acceptOnce.Do(func() {
				ok = true
				h.RemoveStreamHandler(protoChat)
				go func() { inbound <- s }()
			})
			if !ok {
				_ = s.Reset()
			}
		})
		fmt.Println("waiting for peer…")
		var s network.Stream
		select {
		case s = <-inbound:
		case <-ctx.Done():
			return
		}
		go func() {
			_ = httpPostJSON(context.Background(), controlURL, "/v1/consume", consumeRequest{Nameplate: nameplate}, &struct{}{})
		}()
		runAccepted(ctx, h, s, outDir, verify, nameplate, passphrase)

	case "connect":
		relayFirst := isLocalDev
		s, err := tryOpenChat(ctx, h, rzvc, topic, relayAIs, 60*time.Second, relayFirst)
		if err != nil {
			log.Fatalf("open chat: %v", err)
		}
		runAccepted(ctx, h, s, outDir, verify, nameplate, passphrase)
	}
}
