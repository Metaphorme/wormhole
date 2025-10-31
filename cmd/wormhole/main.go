package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	circuitv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	pingsvc "github.com/libp2p/go-libp2p/p2p/protocol/ping"

	ma "github.com/multiformats/go-multiaddr"
	rzv "github.com/waku-org/go-libp2p-rendezvous"

	readline "github.com/chzyer/readline"
	mpb "github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	xxh3 "github.com/zeebo/xxh3"

	"github.com/Metaphorme/wormhole/pkg/api"
	"github.com/Metaphorme/wormhole/pkg/client"
	"github.com/Metaphorme/wormhole/pkg/crypto"
	"github.com/Metaphorme/wormhole/pkg/models"
	"github.com/Metaphorme/wormhole/pkg/p2p"
	"github.com/Metaphorme/wormhole/pkg/session"
	uipkg "github.com/Metaphorme/wormhole/pkg/ui"
)

// 使用 pkg/models 中的聊天协议常量和协议 ID

//go:embed eff_short_wordlist_2_0.txt
var effShortWordlist []byte

// UI 和颜色代码已迁移到 pkg/ui

// ---------- 控制平面 API 数据结构 ----------
// 注意：已迁移到 pkg/models，这里不再重复定义

// ---------- 工具函数 ----------

var verbose bool // 全局标志，用于控制是否输出详细日志

// API 客户端辅助函数

// ts 返回当前时间戳字符串

// 颜色代码包装（使用 pkg/ui）
func c(s, code string) string { return uipkg.C(s, code) }

const (
	cBold = uipkg.CBold
	cDim  = uipkg.CDim
	cCyan = uipkg.CCyan
	cYel  = uipkg.CYel
)

func ts() string {
	return time.Now().Format("15:04:05")
}

func httpPostJSON[T any](ctx context.Context, base, path string, body any, out *T) error {
	c := api.NewClient(base)
	switch path {
	case "/v1/allocate":
		resp, err := c.Allocate(ctx)
		if err != nil {
			return err
		}
		// 直接复制值，因为 T 应该是 models.AllocateResponse
		if ptr, ok := any(out).(*models.AllocateResponse); ok {
			*ptr = *resp
			return nil
		}
		return fmt.Errorf("unexpected type for allocate response")
	case "/v1/claim":
		req, ok := body.(models.ClaimRequest)
		if !ok {
			return fmt.Errorf("invalid claim request type")
		}
		resp, err := c.Claim(ctx, req.Nameplate, req.Side)
		if err != nil {
			return err
		}
		if ptr, ok := any(out).(*models.ClaimResponse); ok {
			*ptr = *resp
			return nil
		}
		return fmt.Errorf("unexpected type for claim response")
	default:
		return fmt.Errorf("unknown path: %s", path)
	}
}

func postConsumeAsync(controlURL, nameplate string) {
	go func() {
		c := api.NewClient(controlURL)
		_ = c.Consume(context.Background(), nameplate)
	}()
}

func postFailAsync(controlURL, nameplate string) {
	go func() {
		c := api.NewClient(controlURL)
		_ = c.Fail(context.Background(), nameplate)
	}()
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// uiConsole 已迁移到 pkg/ui.Console
type uiConsole = uipkg.Console

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
	xs, err := h.NewStream(ctx, remote, models.ProtoXfer)
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
		ui.Println("note: sending empty file")
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
			ui.Println(fmt.Sprintf("hash mismatch, retrying %s (%d/%d)…", off.Name, attempt, maxRetries))
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
				ui.Println(fmt.Sprintf("hash mismatch, retrying %s (%d/%d)…", rel, attempt, maxRetries))
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
		ui.Refresh()
	}
	_ = xs.CloseWrite()
	if len(failedFiles) > 0 {
		ui.Println("some files failed integrity check and were not delivered:")
		for _, f := range failedFiles {
			ui.Println("  - " + f)
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
	ui.Logln(info)
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
					ui.Println("✗ hash mismatch, removed: " + dstPath)
				} else {
					// 校验成功，发送 ACK
					if fileBar != nil {
						fileBar.SetTotal(fileBar.Current(), true)
					}
					_ = writeFrame(xs, frameFileAck, nil)
					ui.Println("← received: " + dstPath)
				}
			}
		case frameXferDone: // 全部传输完成，清理并退出
			if len(failedFiles) > 0 {
				ui.Println("warning: integrity check failed for the following files (removed):")
				for _, f := range failedFiles {
					ui.Println("  - " + f)
				}
			}
			if p != nil && createdBar() {
				p.Wait()
				ui.Refresh()
			}
			return
		case frameError: // 收到错误信息
			ui.Println("← xfer error: " + string(payload))
			if p != nil && createdBar() {
				p.Wait()
				ui.Refresh()
			}
			return
		default:
			return
		}
	}
}

// ---------- 聊天会话 (/chat) ----------

// askYesNoWithReadline 向用户提问并等待 y/N 回答，有超时。
func askYesNoWithReadline(ui *uiConsole, question string, timeout time.Duration, defaultNo bool) bool {
	restore := ui.PromptQuestionAndRestore(question)
	defer restore()

	ansCh := make(chan string, 1)
	go func() {
		line, err := ui.Readline()
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
		ui.Println("")
		return !defaultNo
	}
}

// 异步向控制服务器报告会话状态

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

	ui, err := uipkg.NewConsole("> ")
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
		line, err := session.ReadLineWithDeadline(rw, s, 30*time.Second)
		if err != nil || !strings.HasPrefix(line, models.ChatHello) {
			ui.Logln("handshake failed: did not receive valid HELLO in time")
			_ = s.Close()
			go ui.Close()
			return
		}
		K, err := session.RunPAKEAndConfirm(ctx, s, false, passphrase, nameplate, models.ProtoChat, h.ID(), remote)
		if err != nil {
			ui.Logf("PAKE failed: %v", err)
			_ = s.Close()
			go ui.Close()
			return
		}
		// 从共享密钥派生出文件传输用的哈希种子
		xferSeed = binary.LittleEndian.Uint64(crypto.HkdfBytes(K, "xfer-xxh3-seed", crypto.BuildTranscript(nameplate, models.ProtoXfer, h.ID(), remote), 8))

		// 生成并显示 SAS，等待用户确认
		sas := crypto.SASFromKey(K, crypto.BuildTranscript(nameplate, models.ProtoChat, h.ID(), remote))
		uipkg.PrintPeerVerifyCard(ui, remote, sas)
		prompt := fmt.Sprintf("%s Confirm peer within 30s [y/N]: ", ts())
		accepted := askYesNoWithReadline(ui, prompt, 30*time.Second, true)
		if !accepted {
			fmt.Fprintln(rw, models.ChatReject)
			_ = rw.Flush()
			_ = s.Close()
			go ui.Close()
			ui.Logln("aborted")
			return
		}
		fmt.Fprintln(rw, models.ChatAccept)
		if err := rw.Flush(); err != nil {
			_ = s.Close()
			go ui.Close()
			ui.Logln("handshake failed: write accept error")
			return
		}
		peerAck, err := session.ReadLineWithDeadline(rw, s, 30*time.Second)
		if err != nil {
			_ = s.Close()
			go ui.Close()
			ui.Logln("handshake failed: peer didn't confirm in time")
			return
		}
		switch strings.TrimSpace(peerAck) {
		case models.ChatAccept:
			handshakeSuccess = true
			postConsumeAsync(controlURL, nameplate)
		case models.ChatReject:
			_ = s.Close()
			go ui.Close()
			ui.Logln("handshake failed: peer rejected the verification")
			return
		default:
			_ = s.Close()
			go ui.Close()
			ui.Logln("handshake failed: unexpected response")
			return
		}
	} else {
		// 作为连接方 (Connect)
		fmt.Fprintf(rw, "%s %s\n", models.ChatHello, h.ID().String())
		if err := rw.Flush(); err != nil {
			ui.Logln("handshake failed: cannot write hello")
			_ = s.Close()
			go ui.Close()
			return
		}
		K, err := session.RunPAKEAndConfirm(ctx, s, true, passphrase, nameplate, models.ProtoChat, h.ID(), remote)
		if err != nil {
			ui.Logf("PAKE failed: %v", err)
			_ = s.Close()
			go ui.Close()
			return
		}
		xferSeed = binary.LittleEndian.Uint64(crypto.HkdfBytes(K, "xfer-xxh3-seed", crypto.BuildTranscript(nameplate, models.ProtoXfer, h.ID(), remote), 8))

		sas := crypto.SASFromKey(K, crypto.BuildTranscript(nameplate, models.ProtoChat, h.ID(), remote))
		uipkg.PrintPeerVerifyCard(ui, remote, sas)
		ui.Logln("Waiting for peer confirmation…")

		localAccepted := true
		if verify {
			localAccepted = askYesNoWithReadline(ui,
				fmt.Sprintf("%s Verify peer locally within 30s [y/N]: ", ts()),
				30*time.Second, true)
			if !localAccepted {
				_ = s.Close()
				go ui.Close()
				ui.Logln("local reject or timeout")
				return
			}
		}
		peerAck, err := session.ReadLineWithDeadline(rw, s, 30*time.Second)
		if err != nil {
			ui.Logln("handshake failed: peer didn't confirm in time")
			_ = s.Close()
			go ui.Close()
			return
		}
		switch strings.TrimSpace(peerAck) {
		case models.ChatAccept:
			fmt.Fprintln(rw, models.ChatAccept)
			if err := rw.Flush(); err != nil {
				_ = s.Close()
				go ui.Close()
				ui.Logln("handshake failed: write accept error")
				return
			}
			handshakeSuccess = true
			postConsumeAsync(controlURL, nameplate)
		case models.ChatReject:
			ui.Logln("handshake failed: peer rejected the verification")
			_ = s.Close()
			go ui.Close()
			return
		default:
			ui.Logln("handshake failed: unexpected response")
			_ = s.Close()
			go ui.Close()
			return
		}
	}

	pi := p2p.ClassifyPath(s.Conn())
	uipkg.PrintConnCard(ui, pi, s.Conn().LocalMultiaddr(), s.Conn().RemoteMultiaddr(), verbose)

	// 设置文件传输流处理器
	promptCh := make(chan *promptReq, 4)
	askYesNo := func(q string, timeout time.Duration) bool {
		pr := &promptReq{question: q, resp: make(chan bool, 1)}
		ui.SetPrompt(q)
		promptCh <- pr
		select {
		case r := <-pr.resp:
			return r
		case <-time.After(timeout):
			ui.ResetPrompt()
			return false
		}
	}
	h.SetStreamHandler(models.ProtoXfer, func(xs network.Stream) {
		go handleIncomingXfer(ctx, h, xs, outDir, askYesNo, ui, xferSeed)
	})
	defer h.RemoveStreamHandler(models.ProtoXfer)

	ui.Println(session.HelpText())
	ui.Println("connected. type message to chat, or a command starting with '/'.")

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
			if strings.HasPrefix(txt, models.ChatBye) {
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
			ui.Println("← " + txt)
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
				fmt.Fprintln(w, models.ChatBye)
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
				pi := p2p.ClassifyPath(thisConn)
				ui.Println("peer id: " + thisConn.RemotePeer().String())
				if pi.Kind == "RELAY" {
					ui.Println(fmt.Sprintf("path   : RELAY via %s (%s)", pi.RelayID, pi.Transport))
					if verbose {
						ui.Println("via    : " + pi.RelayVia)
					}
				} else {
					ui.Println(fmt.Sprintf("path   : DIRECT (%s)", pi.Transport))
				}
				ui.Println("local  : " + thisConn.LocalMultiaddr().String())
				ui.Println("remote : " + thisConn.RemoteMultiaddr().String())
				return true

			case strings.HasPrefix(cmd, "/send "):
				rest := strings.TrimSpace(strings.TrimPrefix(cmd, "/send"))
				if rest == "" {
					ui.Println("usage: /send -f <file> | -d <dir>")
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
					ui.Println("usage: /send -f <file> | -d <dir>")
					return true
				}
				ui.Println("sending...")
				if err := sendXfer(ctx, h, thisConn.RemotePeer(), kind, arg, ui, xferSeed); err != nil {
					ui.Println("send failed: " + err.Error())
				} else {
					ui.Println("xfer done.")
				}
				return true
			}
			return false
		}

		for {
			txt, err := ui.Readline()
			if err != nil {
				if errors.Is(err, readline.ErrInterrupt) {
					fmt.Fprintln(w, models.ChatBye)
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
				ui.ResetPrompt()
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
			ui.Println("→ " + line)
			fmt.Fprintln(w, line)
			_ = w.Flush()
		}
	}()

	// 等待会话结束
	reason := <-reasonCh
	ui.Println(reason)

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
		if _, err := circuitv2.Reserve(ctx, h, ai); err == nil {
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
			if client.IsUnspecified(a) { // 过滤掉 0.0.0.0
				continue
			}
			if allowLocal || !client.IsLoopbackOrPrivate(a) { // 过滤掉私有/环回地址
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
			return h.NewStream(dialCtx, remote.ID, models.ProtoChat)
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
			return h.NewStream(dialCtx, remote.ID, models.ProtoChat)
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

	flag.StringVar(&controlURL, "control", "https://wormhole.pianlab.team", "control-plane base URL, e.g. http://ctrl:8080")
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
		var clm models.ClaimResponse
		if err := httpPostJSON(ctx, controlURL, "/v1/claim", models.ClaimRequest{Nameplate: nameplate, Side: "connect"}, &clm); err != nil {
			log.Fatalf("claim: %v", err)
		}
		if clm.Status == "failed" {
			log.Fatalf("claim failed (possibly invalid/expired/duplicate). Ask the host to allocate a new code and retry.")
		}
		topic = clm.Topic
		var err error
		rendezvousAIs, err = p2p.ParseAddrInfos(clm.Rendezvous.Addrs)
		if err != nil {
			log.Fatalf("rendezvous addrs: %v", err)
		}
		relayAIs, _ = p2p.ParseAddrInfos(clm.Relay.Addrs)

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

	// 打印自己的 PeerID
	fmt.Printf("Your PeerID: %s\n", h.ID().String())

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
			var alloc models.AllocateResponse
			if err := httpPostJSON(ctx, controlURL, "/v1/allocate", nil, &alloc); err != nil {
				// 如果在启动时分配失败，则致命退出。如果在循环中失败，可以选择重试或退出。
				log.Fatalf("allocate: %v", err)
			}
			nameplate = alloc.Nameplate
			topic = alloc.Topic
			// 从服务器获取 rendezvous 和 relay 信息
			rendezvousAIs, err = p2p.ParseAddrInfos(alloc.Rendezvous.Addrs)
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

			ws := client.EFFWords(effShortWordlist)
			w1, w2 := client.RandWord(ws), client.RandWord(ws)
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
			h.SetStreamHandler(models.ProtoChat, func(s network.Stream) {
				ok := false
				acceptOnce.Do(func() { // 只接受第一个连接
					ok = true
					h.RemoveStreamHandler(models.ProtoChat)
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
				h.RemoveStreamHandler(models.ProtoChat) // 清理旧的处理器
				continue                                // 继续循环，获取新代码

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
