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

	readline "github.com/chzyer/readline"
	mpb "github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	xxh3 "github.com/zeebo/xxh3"
)

// ---------- 聊天协议控制令牌 ----------
// 这些常量用于在聊天流中发送控制信号，例如建立连接、接受/拒绝验证和断开连接。
const (
	chatHello  = "##HELLO"
	chatAccept = "##ACCEPT"
	chatReject = "##REJECT"
	chatBye    = "##BYE"
)

// 定义了聊天和文件传输的 libp2p 协议 ID
var (
	protoChat = protocol.ID("/wormhole/1.0.0/chat")
	protoXfer = protocol.ID("/wormhole/1.0.0/xfer")
)

//go:embed eff_short_wordlist_2_0.txt
var effShortWordlist []byte

// ---------- ANSI 颜色代码 (遵循 NO_COLOR 环境变量) ----------
var colorEnabled = os.Getenv("NO_COLOR") == ""

// c 是一个辅助函数，用于给字符串添加 ANSI 颜色代码。
func c(s, code string) string {
	if !colorEnabled {
		return s
	}
	return code + s + "\x1b[0m"
}

const (
	cBold = "\x1b[1m"
	cDim  = "\x1b[2m"
	cCyan = "\x1b[36m"
	cYel  = "\x1b[33m"
)

// printPeerVerifyCard 打印对等节点验证信息卡片，包含其ID和短认证字符串(SAS)。
func printPeerVerifyCard(ui *uiConsole, remote peer.ID, sas string) {
	ui.println(c("┌─ Peer Verification ───────────────────────────────────────┐", cBold))
	ui.println("  ID  : " + c(remote.String(), cCyan))
	ui.println("  SAS : " + c(sas, cYel+cBold))
	ui.println(c("└───────────────────────────────────────────────────────────┘", cBold))
}

// printConnCard 打印连接摘要卡片，显示连接路径、本地和远程地址等信息。
func printConnCard(ui *uiConsole, pi pathInfo, local, remote ma.Multiaddr) {
	pathLine := ""
	if pi.Kind == "RELAY" {
		pathLine = fmt.Sprintf("RELAY via %s (%s)", pi.RelayID, pi.Transport)
	} else {
		pathLine = fmt.Sprintf("DIRECT (%s)", pi.Transport)
	}
	ui.println(c("┌─ Connection Summary ──────────────────────────────┐", cBold))
	ui.println("  path   : " + c(pathLine, cCyan))
	ui.println("  local  : " + local.String())
	ui.println("  remote : " + remote.String())
	if pi.Kind == "RELAY" && verbose {
		ui.println("  via    : " + pi.RelayVia)
	}
	ui.println(c("└───────────────────────────────────────────────────┘", cBold))
}

// ---------- 控制平面 API 数据结构 ----------
// 这些结构体用于与控制服务器进行JSON API通信，以分配、声明或消费一个"虫洞"代码。

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
type failRequest struct {
	Nameplate string `json:"nameplate"`
}

// ---------- 工具函数 ----------

var verbose bool // 全局标志，用于控制是否输出详细日志

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func ts() string { return time.Now().Format("2006-01-02 15:04:05") }

// uiConsole 是一个对 readline 库的封装，提供了线程安全的控制台 I/O 操作。
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
func (ui *uiConsole) Close() { _ = ui.rl.Close() }

func (ui *uiConsole) setPrompt(p string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.rl.SetPrompt(p)
	ui.rl.Refresh()
}
func (ui *uiConsole) resetPrompt() { ui.setPrompt(ui.defaultPrompt) }

// println 在刷新 readline 提示的同时打印一行消息，避免覆盖用户输入。
func (ui *uiConsole) println(msg string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	_, _ = ui.rl.Stdout().Write([]byte("\r" + msg + "\n"))
	ui.rl.Refresh()
}
func (ui *uiConsole) logln(msg string) { ui.println(c(ts(), cDim) + " " + msg) }
func (ui *uiConsole) logf(format string, a ...any) {
	ui.println(c(ts(), cDim) + " " + fmt.Sprintf(format, a...))
}
func (ui *uiConsole) promptQuestion(q string) { ui.setPrompt(q) }
func (ui *uiConsole) promptQuestionAndRestore(q string) func() {
	ui.setPrompt(q)
	return func() { ui.resetPrompt() }
}

// effWords 从嵌入的文本文件中解析 EFF 短词列表。
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

// randWord 从给定的单词列表中随机选择一个单词。
func randWord(ws []string) string {
	if len(ws) == 0 {
		return "word"
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ws))))
	return ws[nBig.Int64()]
}

// isUnspecified 检查一个 multiaddr 是否是未指定地址 (如 0.0.0.0 或 ::)。
func isUnspecified(a ma.Multiaddr) bool {
	if v4, _ := a.ValueForProtocol(ma.P_IP4); v4 != "" {
		return v4 == "0.0.0.0"
	}
	if v6, _ := a.ValueForProtocol(ma.P_IP6); v6 != "" {
		return v6 == "::"
	}
	return false
}

// isLoopbackOrPrivate 检查一个 multiaddr 是否是环回或私有地址。
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

// httpPostJSON 发送一个带指数退避重试的 HTTP POST 请求。
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

// parseP2pAddrInfos 解析字符串形式的 multiaddr 列表，并转换为 peer.AddrInfo 结构，同时按 PeerID 去重。
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

// ---------- 帧 I/O ----------
// 定义了一个简单的帧协议: [1字节类型 | 8字节长度 | 载荷]。
// 这用于在同一个流上传输不同类型的消息。

// writeFrame 将一个带类型的载荷写入 io.Writer。
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

// readFrame 从 io.Reader 读取一个帧。
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

// ---------- 文件传输 (XFER) 协议 ----------
const (
	// 文件传输协议的帧类型定义
	frameOffer    = byte(0x01) // 发送方 -> 接收方: 发送一个传输提议
	frameAccept   = byte(0x02) // 接收方 -> 发送方: 接受提议
	frameReject   = byte(0x03) // 接收方 -> 发送方: 拒绝提议
	frameFileHdr  = byte(0x04) // 发送方 -> 接收方: 单个文件的元数据 (名称, 大小, 哈希)
	frameChunk    = byte(0x05) // 发送方 -> 接收方: 文件数据块
	frameFileDone = byte(0x06) // 发送方 -> 接收方: 单个文件传输完成
	frameXferDone = byte(0x07) // 发送方 -> 接收方: 所有文件传输完成
	frameFileAck  = byte(0x08) // 接收方 -> 发送方: 文件哈希校验成功
	frameFileNack = byte(0x09) // 接收方 -> 发送方: 文件哈希校验失败

	frameError = byte(0x7F) // 任一方: 发生错误
	chunkSize  = 1 << 20    // 1MiB, 文件分块大小
)

// xferOffer 定义了文件传输提议的内容。
type xferOffer struct {
	Kind  string `json:"kind"`            // 类型: "file" 或 "dir"
	Name  string `json:"name,omitempty"`  // 文件或目录名
	Size  int64  `json:"size,omitempty"`  // 总字节数
	Files int    `json:"files,omitempty"` // 文件数量 (仅目录)
}

// ---------- 进度条 ----------

// newFileBar 为单个文件传输创建一个新的进度条。
func newFileBar(p *mpb.Progress, name string, total int64) *mpb.Bar {
	return p.New(total,
		mpb.BarStyle(),
		mpb.BarPriority(0),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(name+" ", decor.WC{C: decor.DindentRight}),
			decor.CountersKibiByte("% .1f / % .1f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" | "),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30),
			decor.Name(" | "),
			decor.EwmaETA(decor.ET_STYLE_MMSS, 30),
		),
	)
}

// newTotalBar 为目录传输创建一个显示总进度的进度条。
func newTotalBar(p *mpb.Progress, total int64) *mpb.Bar {
	return p.New(total,
		mpb.BarStyle(),
		mpb.BarPriority(1),
		mpb.PrependDecorators(
			decor.Name("TOTAL ", decor.WC{C: decor.DindentRight}),
			decor.CountersKibiByte("% .1f / % .1f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" | "),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30),
			decor.Name(" | "),
			decor.EwmaETA(decor.ET_STYLE_MMSS, 30),
		),
	)
}

// sendXfer 处理文件或目录的发送逻辑。
func sendXfer(ctx context.Context, h host.Host, remote peer.ID, kind, arg string, ui *uiConsole, seed uint64) error {
	xs, err := h.NewStream(ctx, remote, protoXfer)
	if err != nil {
		return err
	}
	defer xs.Close()

	// 1. 根据类型 (file/dir) 创建传输提议。
	var off xferOffer
	switch kind {
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

	// 2. 发送提议并等待对方响应。
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

	// 3. 初始化进度条。
	var p *mpb.Progress
	var fileBar, totalBar *mpb.Bar
	if (off.Kind == "file" && off.Size > 0) || (off.Kind == "dir" && off.Size > 0) {
		p = mpb.New(
			mpb.WithWidth(64),
			mpb.WithRefreshRate(120*time.Millisecond),
			mpb.WithOutput(os.Stderr),
		)
		if off.Kind == "dir" {
			totalBar = newTotalBar(p, off.Size)
		}
	} else if off.Kind == "file" && off.Size == 0 {
		ui.println("note: sending empty file")
	}
	createdBar := func() bool { return fileBar != nil || totalBar != nil }

	// 4. 定义发送单个文件的辅助函数，包含完整性校验和重试逻辑。
	sendOneAttempt := func(name string, r io.Reader, size int64, expectHash string) error {
		// 为当前文件创建或更新进度条
		if p != nil {
			if totalBar != nil && fileBar != nil {
				fileBar.Abort(true)
				fileBar.Wait()
			}
			if size > 0 {
				fileBar = newFileBar(p, name, size)
			} else {
				fileBar = nil // 零大小文件不显示进度条
			}
		}

		if fileBar != nil {
			fileBar.DecoratorAverageAdjust(time.Now())
		}
		if totalBar != nil {
			totalBar.DecoratorAverageAdjust(time.Now())
		}

		// 发送文件头信息 (元数据)
		hdr := map[string]any{
			"name": name,
			"size": size,
			"algo": "xxh3-128-seed",
			"hash": expectHash,
		}
		b, _ := json.Marshal(hdr)
		if err := writeFrame(xs, frameFileHdr, b); err != nil {
			return err
		}

		// 分块发送文件数据
		buf := make([]byte, chunkSize)
		var sent int64
		hw := xxh3.NewSeed(seed)
		for {
			if size >= 0 && sent >= size {
				break
			}
			start := time.Now()
			n, er := r.Read(buf)
			if n > 0 {
				sent += int64(n)
				_, _ = hw.Write(buf[:n])
				if err := writeFrame(xs, frameChunk, buf[:n]); err != nil {
					return err
				}
				// 更新进度条
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

		// 等待接收方的确认 (ACK/NACK)
		typ, _, err := readFrame(xs)
		if err != nil {
			return err
		}
		switch typ {
		case frameFileAck:
			sumBytes := hw.Sum128().Bytes()
			got := fmt.Sprintf("%x", sumBytes[:])
			if expectHash != "" && got != expectHash {
				return fmt.Errorf("sender self-check mismatched (unexpected)")
			}
			return nil
		case frameFileNack:
			return fmt.Errorf("receiver reported hash mismatch")
		default:
			return fmt.Errorf("unexpected response after file: 0x%02x", typ)
		}
	}

	// 5. 定义计算文件哈希的辅助函数。
	hashFile := func(path string) (string, int64, error) {
		f, err := os.Open(path)
		if err != nil {
			return "", 0, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return "", 0, err
		}
		h := xxh3.NewSeed(seed)
		if _, err := io.Copy(h, f); err != nil {
			return "", 0, err
		}
		sum := h.Sum128().Bytes()
		return fmt.Sprintf("%x", sum[:]), st.Size(), nil
	}

	// 6. 开始传输。
	failedFiles := make([]string, 0)
	const maxRetries = 3

	switch off.Kind {
	case "file":
		hv, sz, err := hashFile(arg)
		if err != nil {
			return err
		}
		if off.Size <= 0 {
			off.Size = sz
		}
		attempt := 0
		for {
			f, er := os.Open(arg)
			if er != nil {
				return er
			}
			err = sendOneAttempt(off.Name, f, off.Size, hv)
			_ = f.Close()
			if err == nil || attempt >= maxRetries {
				if err != nil {
					failedFiles = append(failedFiles, off.Name)
				}
				break
			}
			attempt++
			ui.println(fmt.Sprintf("hash mismatch, retrying %s (%d/%d)…", off.Name, attempt, maxRetries))
			time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
		}
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
			hv, _, er := hashFile(path)
			if er != nil {
				return nil
			}
			attempt := 0
			for {
				f, er2 := os.Open(path)
				if er2 != nil {
					return nil
				}
				e := sendOneAttempt(rel, f, st.Size(), hv)
				_ = f.Close()
				if e == nil || attempt >= maxRetries {
					if e != nil {
						failedFiles = append(failedFiles, rel)
					}
					break
				}
				attempt++
				ui.println(fmt.Sprintf("hash mismatch, retrying %s (%d/%d)…", rel, attempt, maxRetries))
				time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
			}
			return nil
		})
		if totalBar != nil {
			totalBar.SetTotal(off.Size, true)
		}
	}

	// 7. 发送传输结束信号并清理。
	if err := writeFrame(xs, frameXferDone, nil); err != nil {
		return err
	}
	if p != nil && createdBar() {
		p.Wait()
		ui.rl.Refresh()
	}
	_ = xs.CloseWrite()
	if len(failedFiles) > 0 {
		ui.println("some files failed integrity check and were not delivered:")
		for _, f := range failedFiles {
			ui.println("  - " + f)
		}
	}
	return nil
}

// promptReq 用于在主输入循环和需要用户输入的其他协程之间传递请求。
type promptReq struct {
	question string
	resp     chan bool
}

// tryDequeuePrompt 尝试从通道中非阻塞地取出一个提示请求。
func tryDequeuePrompt(ch chan *promptReq) *promptReq {
	select {
	case p := <-ch:
		return p
	default:
		return nil
	}
}

// handleIncomingXfer 处理接收文件或目录的逻辑。
func handleIncomingXfer(_ context.Context, _ host.Host, xs network.Stream, outDir string, askYesNo func(q string, timeout time.Duration) bool, ui *uiConsole, seed uint64) {
	defer xs.Close()
	// 1. 读取传输提议。
	typ, payload, err := readFrame(xs)
	if err != nil || typ != frameOffer {
		return
	}
	var off xferOffer
	_ = json.Unmarshal(payload, &off)

	// 2. 询问用户是否接受。
	info := ""
	switch off.Kind {
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

	// 3. 初始化进度条。
	var p *mpb.Progress
	var fileBar, totalBar *mpb.Bar
	if (off.Kind == "file" && off.Size > 0) || (off.Kind == "dir" && off.Size > 0) {
		p = mpb.New(
			mpb.WithWidth(64),
			mpb.WithRefreshRate(120*time.Millisecond),
			mpb.WithOutput(os.Stderr),
		)
		if off.Kind == "file" {
			fileBar = newFileBar(p, off.Name, off.Size)
		} else {
			totalBar = newTotalBar(p, off.Size)
		}
	}
	createdBar := func() bool { return p != nil && (fileBar != nil || totalBar != nil) }

	// 4. 循环处理接收到的帧。
	var fw *os.File
	var dstPath string
	var expectHash string
	var algo string
	failedFiles := make([]string, 0)
	hasher := xxh3.NewSeed(seed)
	lastTick := time.Now()

	for {
		typ, payload, err = readFrame(xs)
		if err != nil {
			return
		}
		switch typ {
		case frameFileHdr: // 收到文件头，准备写入文件
			var hdr struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
				Algo string `json:"algo"`
				Hash string `json:"hash"`
			}
			_ = json.Unmarshal(payload, &hdr)
			dstPath = filepath.Join(outDir, hdr.Name)
			_ = os.MkdirAll(filepath.Dir(dstPath), 0o755)
			fw, err = os.Create(dstPath)
			if err != nil {
				_ = writeFrame(xs, frameError, []byte(err.Error()))
				return
			}
			expectHash = strings.ToLower(strings.TrimSpace(hdr.Hash))
			algo = strings.ToLower(strings.TrimSpace(hdr.Algo))
			hasher.Reset()
			lastTick = time.Now()

			// 更新当前文件的进度条
			if p != nil {
				if totalBar != nil {
					if fileBar != nil {
						fileBar.Abort(true)
						fileBar.Wait()
					}
					if hdr.Size > 0 {
						fileBar = newFileBar(p, hdr.Name, hdr.Size)
						fileBar.DecoratorAverageAdjust(time.Now())
					} else {
						fileBar = nil
					}
				} else if fileBar == nil && hdr.Size > 0 {
					fileBar = newFileBar(p, hdr.Name, hdr.Size)
					fileBar.DecoratorAverageAdjust(time.Now())
				}
				if totalBar != nil {
					totalBar.DecoratorAverageAdjust(time.Now())
				}
			}

		case frameChunk: // 收到数据块，写入文件并更新哈希
			if fw != nil {
				_, _ = fw.Write(payload)
				_, _ = hasher.Write(payload)
				now := time.Now()
				dt := now.Sub(lastTick)
				lastTick = now
				if fileBar != nil {
					fileBar.EwmaIncrBy(len(payload), dt)
				}
				if totalBar != nil {
					totalBar.EwmaIncrBy(len(payload), dt)
				}
			}
		case frameFileDone: // 单个文件接收完成，校验哈希
			if fw != nil {
				_ = fw.Close()
				fw = nil
				sumBytes := hasher.Sum128().Bytes()
				got := fmt.Sprintf("%x", sumBytes[:])
				if algo != "xxh3-128-seed" || (expectHash != "" && got != expectHash) {
					// 校验失败，删除文件并发送 NACK
					_ = os.Remove(dstPath)
					_ = writeFrame(xs, frameFileNack, nil)
					failedFiles = append(failedFiles, dstPath)
					ui.println("✗ hash mismatch, removed: " + dstPath)
				} else {
					// 校验成功，发送 ACK
					if fileBar != nil {
						fileBar.SetTotal(fileBar.Current(), true)
					}
					_ = writeFrame(xs, frameFileAck, nil)
					ui.println("← received: " + dstPath)
				}
			}
		case frameXferDone: // 全部传输完成，清理并退出
			if len(failedFiles) > 0 {
				ui.println("warning: integrity check failed for the following files (removed):")
				for _, f := range failedFiles {
					ui.println("  - " + f)
				}
			}
			if p != nil && createdBar() {
				p.Wait()
				ui.rl.Refresh()
			}
			return
		case frameError: // 收到错误信息
			ui.println("← xfer error: " + string(payload))
			if p != nil && createdBar() {
				p.Wait()
				ui.rl.Refresh()
			}
			return
		default:
			return
		}
	}
}

// ---------- PAKE 密钥协商 + 密钥确认 + 短认证字符串(SAS) ----------
const (
	framePakeMsg     = byte(0x10) // PAKE 协议消息
	framePakeConfirm = byte(0x11) // 密钥确认消息
	framePakeAbort   = byte(0x1F) // 协商中止
)

// buildTranscript 构建一个唯一的会话摘要，用于密钥派生和确认。
// 它将双方的 PeerID 按字典序排序，以确保双方生成相同的摘要。
func buildTranscript(nameplate string, proto protocol.ID, a, b peer.ID) []byte {
	ids := []string{a.String(), b.String()}
	if ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	s := strings.Join([]string{"wormhole-pake-v1", nameplate, string(proto), ids[0], ids[1]}, "|")
	return []byte(s)
}

// hkdfBytes 使用 HKDF 从输入密钥材料(ikm)派生出指定长度的密钥。
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

// sasFromKey 从共享密钥生成一个短认证字符串(SAS)，由5个 emoji 组成，用于人工验证。
func sasFromKey(K []byte, transcript []byte) string {
	em := emojiList()
	b := hkdfBytes(K, "sas", transcript, 4) // 派生32位数据
	acc := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	parts := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		idx := (acc >> (i * 6)) & 0x3F // 每6位映射一个 emoji
		parts = append(parts, em[idx%uint32(len(em))])
	}
	return strings.Join(parts, " ")
}

// runPAKEAndConfirm 执行 SPAKE2 密钥协商和密钥确认流程。
// roleA=true 表示是发起方(Dialer)。
func runPAKEAndConfirm(_ context.Context, s network.Stream, roleA bool, passphrase, nameplate string, proto protocol.ID, local, remote peer.ID) ([]byte, error) {
	transcript := buildTranscript(nameplate, proto, local, remote)
	pw := spake2.NewPassword(passphrase)
	var state spake2.SPAKE2
	if roleA {
		state = spake2.SPAKE2A(pw, spake2.NewIdentityA(local.String()), spake2.NewIdentityB(remote.String()))
	} else {
		state = spake2.SPAKE2B(pw, spake2.NewIdentityA(remote.String()), spake2.NewIdentityB(local.String()))
	}

	my := state.Start()
	if roleA { // 发起方流程
		// 1. 发送自己的 PAKE 消息
		if err := writeFrame(s, framePakeMsg, my); err != nil {
			return nil, err
		}
		// 2. 接收对方的 PAKE 消息
		typ, peerMsg, err := readFrame(s)
		if err != nil || typ != framePakeMsg {
			return nil, fmt.Errorf("pake: bad peer msg")
		}
		// 3. 计算共享密钥 K
		K, err := state.Finish(peerMsg)
		if err != nil {
			return nil, fmt.Errorf("pake finish: %w", err)
		}
		// 4. 进行密钥确认：派生 Kc，计算并发送自己的 MAC
		Kc := hkdfBytes(K, "confirm", transcript, 32)
		macA := hmac.New(sha256.New, Kc)
		macA.Write([]byte("A|"))
		macA.Write(transcript)
		if err := writeFrame(s, framePakeConfirm, macA.Sum(nil)); err != nil {
			return nil, err
		}
		// 5. 接收并验证对方的 MAC
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
	} else { // 响应方流程 (与发起方对称)
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

// ---------- 聊天会话 (/chat) ----------

// readLineWithDeadline 从流中读取一行，带有超时。
func readLineWithDeadline(rw *bufio.ReadWriter, s network.Stream, d time.Duration) (string, error) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	defer s.SetReadDeadline(time.Time{})
	line, err := rw.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func helpText() string {
	return `Commands:
/peer                  show peer id & current path
/send -f <file>        send a file
/send -d <dir>         send a directory recursively
/bye                   close the chat`
}

// reRelayBeforeCircuit 用于从 multiaddr 中识别中继地址。
var reRelayBeforeCircuit = regexp.MustCompile(`/p2p/([^/]+)/p2p-circuit`)

// transportHint 从 multiaddr 中猜测传输协议类型。
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

// pathInfo 存储关于连接路径的分类信息。
type pathInfo struct {
	Kind       string // "DIRECT" 或 "RELAY"
	RelayID    string
	RelayVia   string
	Transport  string
	LocalAddr  string
	RemoteAddr string
}

// classifyPath 分析一个 libp2p 连接，判断它是直连还是通过中继。
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

// askYesNoWithReadline 向用户提问并等待 y/N 回答，有超时。
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
		ui.println("")
		return !defaultNo
	}
}

// 异步向控制服务器报告会话状态

func postConsumeAsync(controlURL, nameplate string) {
	go func() {
		_ = httpPostJSON(context.Background(), controlURL, "/v1/consume",
			consumeRequest{Nameplate: nameplate}, &struct{}{})
	}()
}
func postFailAsync(controlURL, nameplate string) {
	go func() {
		_ = httpPostJSON(context.Background(), controlURL, "/v1/fail",
			failRequest{Nameplate: nameplate}, &struct{}{})
	}()
}

// runAccepted 是在 P2P 连接建立后运行的核心函数，负责处理握手、聊天和文件传输。
func runAccepted(ctx context.Context, h host.Host, s network.Stream, controlURL, outDir string, verify bool, nameplate, passphrase string) {
	// 确保在上下文取消时关闭流
	go func() {
		<-ctx.Done()
		_ = s.CloseRead()
		_ = s.CloseWrite()
	}()
	remote := s.Conn().RemotePeer()
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	ui, err := newUI("> ")
	if err != nil {
		fmt.Println("init console failed:", err)
		_ = s.Close()
		return
	}

	handshakeSuccess := false
	var xferSeed uint64 // 用于文件传输完整性校验的种子
	defer func() {
		if !handshakeSuccess {
			postFailAsync(controlURL, nameplate)
		}
	}()

	// ---------- 握手流程 ----------
	// 包含 PAKE 协商、SAS 验证和用户确认。
	if s.Stat().Direction == network.DirInbound {
		// 作为被连接方 (Host)
		line, err := readLineWithDeadline(rw, s, 30*time.Second)
		if err != nil || !strings.HasPrefix(line, chatHello) {
			ui.logln("handshake failed: did not receive valid HELLO in time")
			_ = s.Close()
			go ui.Close()
			return
		}
		K, err := runPAKEAndConfirm(ctx, s, false, passphrase, nameplate, protoChat, h.ID(), remote)
		if err != nil {
			ui.logf("PAKE failed: %v", err)
			_ = s.Close()
			go ui.Close()
			return
		}
		// 从共享密钥派生出文件传输用的哈希种子
		xferSeed = binary.LittleEndian.Uint64(hkdfBytes(K, "xfer-xxh3-seed", buildTranscript(nameplate, protoXfer, h.ID(), remote), 8))

		// 生成并显示 SAS，等待用户确认
		sas := sasFromKey(K, buildTranscript(nameplate, protoChat, h.ID(), remote))
		printPeerVerifyCard(ui, remote, sas)
		prompt := fmt.Sprintf("%s Confirm peer within 30s [y/N]: ", ts())
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
			handshakeSuccess = true
			postConsumeAsync(controlURL, nameplate)
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
		// 作为连接方 (Connect)
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
		xferSeed = binary.LittleEndian.Uint64(hkdfBytes(K, "xfer-xxh3-seed", buildTranscript(nameplate, protoXfer, h.ID(), remote), 8))

		sas := sasFromKey(K, buildTranscript(nameplate, protoChat, h.ID(), remote))
		printPeerVerifyCard(ui, remote, sas)
		ui.logln("Waiting for peer confirmation…")

		localAccepted := true
		if verify {
			localAccepted = askYesNoWithReadline(ui,
				fmt.Sprintf("%s Verify peer locally within 30s [y/N]: ", ts()),
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
			handshakeSuccess = true
			postConsumeAsync(controlURL, nameplate)
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

	pi := classifyPath(s.Conn())
	printConnCard(ui, pi, s.Conn().LocalMultiaddr(), s.Conn().RemoteMultiaddr())

	// 设置文件传输流处理器
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
		go handleIncomingXfer(ctx, h, xs, outDir, askYesNo, ui, xferSeed)
	})
	defer h.RemoveStreamHandler(protoXfer)

	ui.println(helpText())
	ui.println("connected. type message to chat, or a command starting with '/'.")

	done := make(chan struct{})
	reasonCh := make(chan string, 1)
	var once sync.Once
	thisConn := s.Conn()

	// 监听连接断开事件
	notifiee := &network.NotifyBundle{
		DisconnectedF: func(_ network.Network, c network.Conn) {
			if c == thisConn {
				go ui.Close()
				once.Do(func() {
					reasonCh <- "peer disconnected"
					close(done)
				})
			}
		},
	}
	h.Network().Notify(notifiee)
	defer h.Network().StopNotify(notifiee)

	// 接收循环 (goroutine)
	go func() {
		r := bufio.NewScanner(rw.Reader)
		for r.Scan() {
			txt := r.Text()
			if strings.HasPrefix(txt, chatBye) {
				once.Do(func() {
					go ui.Close()
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
			go ui.Close()
			reasonCh <- "peer closed the stream"
			close(done)
		})
	}()

	// 用户输入循环 (goroutine)
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
				_ = s.CloseRead()
				_ = s.CloseWrite()
				go ui.Close()
				return true

			case cmd == "/peer":
				pi := classifyPath(thisConn)
				ui.println("peer id: " + thisConn.RemotePeer().String())
				if pi.Kind == "RELAY" {
					ui.println(fmt.Sprintf("path   : RELAY via %s (%s)", pi.RelayID, pi.Transport))
					if verbose {
						ui.println("via    : " + pi.RelayVia)
					}
				} else {
					ui.println(fmt.Sprintf("path   : DIRECT (%s)", pi.Transport))
				}
				ui.println("local  : " + thisConn.LocalMultiaddr().String())
				ui.println("remote : " + thisConn.RemoteMultiaddr().String())
				return true

			case strings.HasPrefix(cmd, "/send "):
				rest := strings.TrimSpace(strings.TrimPrefix(cmd, "/send"))
				if rest == "" {
					ui.println("usage: /send -f <file> | -d <dir>")
					return true
				}
				as := strings.Fields(rest)
				var fileArg, dirArg string
				for i := 0; i < len(as); i++ {
					switch as[i] {
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
				case fileArg != "":
					kind, arg = "file", fileArg
				case dirArg != "":
					kind, arg = "dir", dirArg
				}
				if kind == "" {
					ui.println("usage: /send -f <file> | -d <dir>")
					return true
				}
				ui.println("sending...")
				if err := sendXfer(ctx, h, thisConn.RemotePeer(), kind, arg, ui, xferSeed); err != nil {
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
				if errors.Is(err, readline.ErrInterrupt) {
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
					once.Do(func() {
						reasonCh <- "stdin closed"
						close(done)
					})
					_ = s.CloseRead()
					_ = s.CloseWrite()
					go ui.Close()
					return
				}
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
			// 检查是否有待处理的用户提示 (如文件接收确认)
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
			// 普通文本作为聊天消息发送
			ui.println("→ " + line)
			fmt.Fprintln(w, line)
			_ = w.Flush()
		}
	}()

	// 等待会话结束
	reason := <-reasonCh
	ui.println(reason)

	_ = s.CloseRead()
	_ = s.CloseWrite()
	_ = s.Close()
	go ui.Close()
}

// ---------- libp2p 主机和发现 ----------

// newHost 创建并配置一个新的 libp2p 主机实例。
func newHost(staticRelay *peer.AddrInfo, extraListen []ma.Multiaddr) (host.Host, error) {
	opts := []libp2p.Option{
		libp2p.NATPortMap(),         // 尝试使用 UPnP/NAT-PMP 进行端口映射
		libp2p.EnableHolePunching(), // 启用 NAT 穿透
	}
	if staticRelay != nil {
		// 配置一个静态中继节点，用于 AutoRelay
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{*staticRelay}))
	}
	if len(extraListen) > 0 {
		opts = append(opts, libp2p.ListenAddrs(extraListen...))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	pingsvc.NewPingService(h) // 启用 ping 服务以保持连接活跃
	if staticRelay != nil {
		h.Peerstore().AddAddrs(staticRelay.ID, staticRelay.Addrs, time.Hour)
	}
	return h, nil
}

// connectAny 尝试连接到地址列表中的任何一个节点，成功一个即返回。
func connectAny(ctx context.Context, h host.Host, addrs []peer.AddrInfo) (*peer.AddrInfo, error) {
	for _, ai := range addrs {
		if err := h.Connect(ctx, ai); err == nil {
			return &ai, nil
		}
	}
	return nil, fmt.Errorf("connectAny failed")
}

// reserveAnyRelay 尝试在给定的中继列表中预订一个槽位。
func reserveAnyRelay(ctx context.Context, h host.Host, relays []peer.AddrInfo) *peer.AddrInfo {
	for _, ai := range relays {
		_ = h.Connect(ctx, ai)
		if _, err := client.Reserve(ctx, h, ai); err == nil {
			return &ai
		}
	}
	return nil
}

// buildCircuitSelfAddrs 构建通过中继节点访问自身的 p2p-circuit 地址。
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

// rendezvousAddrsFactory 是一个地址工厂函数，用于过滤和添加要向汇合点宣告的地址。
func rendezvousAddrsFactory(h host.Host, reservedRelay *peer.AddrInfo, allowLocal bool) rzv.AddrsFactory {
	return func(addrs []ma.Multiaddr) []ma.Multiaddr {
		seen := make(map[string]bool)
		var out []ma.Multiaddr
		for _, a := range addrs {
			if isUnspecified(a) { // 过滤掉 0.0.0.0
				continue
			}
			if allowLocal || !isLoopbackOrPrivate(a) { // 过滤掉私有/环回地址
				k := a.String()
				if !seen[k] {
					out = append(out, a)
					seen[k] = true
				}
			}
		}
		// 添加通过已预订中继的 circuit 地址
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

// mergeRelaysFromRemote 将从远程节点地址中提取的中继信息与已知的中继列表合并。
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

// allRelayedAddrs 检查一个节点的所有地址是否都是中继地址。
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

// tryOpenChat 尝试通过汇合点发现对等节点并建立聊天流。
func tryOpenChat(ctx context.Context, h host.Host, rzvc rzv.RendezvousClient, topic string, relays []peer.AddrInfo, maxWait time.Duration, relayFirst bool) (network.Stream, error) {
	deadline := time.Now().Add(maxWait)
	var lastErr error

	for time.Now().Before(deadline) {
		// 1. 通过汇合点发现同一主题下的其他节点。
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

		// 2. 定义直连和通过中继连接的辅助函数。
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

		// 3. 遍历发现的节点，尝试建立连接。
		for _, remote := range infos {
			remoteRelays := mergeRelaysFromRemote(remote, relays)
			preferRelay := relayFirst || allRelayedAddrs(remote) || len(remoteRelays) > 0

			var s network.Stream
			var err error
			if preferRelay { // 优先尝试中继
				if s, err = dialViaRelay(remote, remoteRelays); err == nil {
					return s, nil
				}
				if s, err = dialDirect(remote); err == nil {
					return s, nil
				}
				lastErr = err
			} else { // 优先尝试直连
				if s, err = dialDirect(remote); err == nil {
					return s, nil
				}
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
	var codeShort string
	var mode string
	var listen string
	var outDir string
	var verify bool
	var jsonOut bool
	var dlDir string

	flag.StringVar(&controlURL, "control", "http://127.0.0.1:8080", "control-plane base URL, e.g. http://ctrl:8080")
	flag.StringVar(&code, "code", "", "join: code '<nameplate>-<word>-<word>'")
	flag.StringVar(&codeShort, "c", "", "alias of -code")
	flag.StringVar(&mode, "mode", "", "(deprecated) host|connect; auto-detected by -code/-c or positional code")
	flag.StringVar(&listen, "listen", "", "optional listen multiaddrs (comma-separated)")
	flag.StringVar(&outDir, "outdir", ".", "directory to save incoming files")
	flag.StringVar(&dlDir, "download-dir", "", "download directory (alias of -outdir)")
	flag.BoolVar(&verify, "verify", true, "require local confirmation (y/N) on dialer side")
	flag.BoolVar(&jsonOut, "json", false, "emit JSON logs (reserved)")
	flag.BoolVar(&verbose, "verbose", false, "print verbose logs (reservation/announce addrs, etc.)")
	flag.Parse()
	_ = jsonOut

	// 支持通过位置参数传递代码
	var codeRe = regexp.MustCompile(`^\d{3}-[a-z]+-[a-z]+$`)
	if code == "" && codeShort != "" {
		code = codeShort
	}
	if code == "" && flag.NArg() == 1 && codeRe.MatchString(flag.Arg(0)) {
		code = flag.Arg(0)
	}

	// 根据是否提供了 `-code` 参数来推断模式 (host 或 connect)
	inferred := "host"
	if code != "" {
		inferred = "connect"
	}
	if mode == "" {
		mode = inferred
	} else if mode != inferred {
		fmt.Println("warn: -mode is deprecated and conflicts with inferred mode; proceeding with -mode =", mode)
	}

	if dlDir != "" {
		outDir = dlDir
	}

	isLocalDev := func(u string) bool {
		pu, err := url.Parse(u)
		if err != nil {
			return false
		}
		h := pu.Hostname()
		return h == "127.0.0.1" || h == "localhost"
	}(controlURL)

	// 如果是本地开发环境，默认监听环回地址
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

	// 根据模式与控制服务器交互。
	if mode == "connect" {
		// 连接模式：使用给定的代码向服务器声明
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

	} else if mode != "host" {
		// 如果模式不是 "connect" 也不是 "host"，则为未知模式。
		log.Fatalf("unknown -mode %q", mode)
	}

	// 初始化 libp2p 主机
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

	// 注意：在 host 模式下，rendezvousAIs 在这里是空的，这没关系。
	// 它会在下面的主循环中被正确填充，然后才会去连接 rendezvous 服务器。
	// 而 connect 模式下，此时 rendezvousAIs 已经有值了。
	if mode == "connect" {
		// 连接到汇合点服务器
		if len(rendezvousAIs) == 0 {
			log.Fatalf("no rendezvous addrs found for connect mode")
		}
		if _, err := connectAny(ctx, h, rendezvousAIs); err != nil {
			log.Fatalf("connect rendezvous: %v", err)
		}
	}

	// 尝试预订一个中继槽位
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

	// 配置汇合点客户端
	addrFac := rendezvousAddrsFactory(h, reservedRelay, isLocalDev)

	// 延迟 rendezvous client 的初始化，直到我们确定有了 rendezvous 服务器的地址
	var rzvc rzv.RendezvousClient

	if verbose {
		pub := addrFac(h.Addrs())
		if len(pub) > 0 {
			fmt.Println("announce addrs:")
			for _, a := range pub {
				fmt.Println("   ", a.String())
			}
		}
	}

	// 根据模式执行不同的逻辑
	switch mode {
	case "host":
		// 启动一个无限循环，用于代码的自动轮换
		for {
			// 1. 主机模式：向服务器申请一个新的代码
			var alloc allocateResponse
			if err := httpPostJSON(ctx, controlURL, "/v1/allocate", nil, &alloc); err != nil {
				// 如果在启动时分配失败，则致命退出。如果在循环中失败，可以选择重试或退出。
				log.Fatalf("allocate: %v", err)
			}
			nameplate = alloc.Nameplate
			topic = alloc.Topic
			// 从服务器获取 rendezvous 和 relay 信息
			rendezvousAIs, err = parseP2pAddrInfos(alloc.Rendezvous.Addrs)
			if err != nil {
				log.Fatalf("rendezvous addrs: %v", err)
			}

			// 第一次循环时，连接到 rendezvous 服务器
			if rzvc == nil {
				if _, err := connectAny(ctx, h, rendezvousAIs); err != nil {
					log.Fatalf("connect rendezvous: %v", err)
				}
				// 初始化客户端
				rzvPeer := rendezvousAIs[0].ID
				rp := rzv.NewRendezvousPoint(h, rzvPeer, rzv.ClientWithAddrsFactory(addrFac))
				rzvc = rzv.NewRendezvousClientWithPoint(rp)
			}

			ws := effWords()
			w1, w2 := randWord(ws), randWord(ws)
			passphrase = fmt.Sprintf("%s-%s", w1, w2)
			fullCode := fmt.Sprintf("%s-%s", nameplate, passphrase)

			// 2. 打印新的代码信息，使用本地时区显示过期时间
			fmt.Printf("Starting session…\nYour code: %s\nAsk peer to run: wormhole -c %s\n(Expires: %s)\n",
				fullCode, fullCode, ts())

			// 3. 使用新主题在汇合点注册自己
			if _, err := rzvc.Register(ctx, topic, 120); err != nil {
				log.Printf("warn: rendezvous register failed: %v. will retry on next code rotation.", err)
				// 等待一小段时间后重试循环，避免快速失败导致API滥用
				time.Sleep(5 * time.Second)
				continue
			}

			// 4. 设置流处理器，准备接受连接
			inbound := make(chan network.Stream, 1)
			var acceptOnce sync.Once
			h.SetStreamHandler(protoChat, func(s network.Stream) {
				ok := false
				acceptOnce.Do(func() { // 只接受第一个连接
					ok = true
					h.RemoveStreamHandler(protoChat)
					go func() { inbound <- s }()
				})
				if !ok {
					_ = s.Reset()
				}
			})
			fmt.Println("waiting for peer…")

			// 5. 使用 select 等待连接、代码过期或程序中断
			var s network.Stream
			select {
			case s = <-inbound:
				// 成功接收连接，运行会话然后退出程序
				runAccepted(ctx, h, s, controlURL, outDir, verify, nameplate, passphrase)
				return // 会话结束，程序退出

			case <-time.After(time.Until(alloc.ExpiresAt)):
				// 等待直到代码过期。time.Until会计算出距离过期时间的时长。
				fmt.Println("\ncode expired, allocating a new one…")
				h.RemoveStreamHandler(protoChat) // 清理旧的处理器
				continue                         // 继续循环，获取新代码

			case <-ctx.Done():
				// 用户按下了 Ctrl+C
				fmt.Println("\nshutting down.")
				return // 退出程序
			}
		}

	case "connect":
		// 在 connect 模式下，现在才初始化 rendezvous client
		rzvPeer := rendezvousAIs[0].ID
		rp := rzv.NewRendezvousPoint(h, rzvPeer, rzv.ClientWithAddrsFactory(addrFac))
		rzvc = rzv.NewRendezvousClientWithPoint(rp)

		// 连接模式：通过汇合点发现主机并尝试连接
		relayFirst := isLocalDev
		s, err := tryOpenChat(ctx, h, rzvc, topic, relayAIs, 60*time.Second, relayFirst)
		if err != nil {
			log.Fatalf("open chat: %v", err)
		}
		runAccepted(ctx, h, s, controlURL, outDir, verify, nameplate, passphrase)
	}
}
