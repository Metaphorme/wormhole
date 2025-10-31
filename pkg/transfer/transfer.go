package transfer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Metaphorme/wormhole/pkg/ui"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	xxh3 "github.com/zeebo/xxh3"
)

// 帧类型定义
const (
	FrameOffer    = byte(0x20)
	FrameAccept   = byte(0x21)
	FrameReject   = byte(0x22)
	FrameFileHdr  = byte(0x30)
	FrameChunk    = byte(0x31)
	FrameFileDone = byte(0x32)
	FrameFileAck  = byte(0x33)
	FrameFileNack = byte(0x34)
	FrameXferDone = byte(0x3F)
	ChunkSize     = 64 * 1024
)

// XferOffer 传输提议数据结构
type XferOffer struct {
	Kind  string `json:"kind"`  // "file" 或 "dir"
	Name  string `json:"name"`  // 文件名或目录名
	Size  int64  `json:"size"`  // 总大小（字节）
	Files int64  `json:"files"` // 文件数量（仅用于目录）
}

// WriteFrame 写入一个带类型和长度前缀的帧
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	hdr := [5]byte{typ}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame 读取一个帧，返回类型和内容
func ReadFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:])
	if length == 0 {
		return typ, nil, nil
	}
	if length > 512*1024*1024 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// NewFileBar 创建文件进度条
func NewFileBar(p *mpb.Progress, name string, total int64) *mpb.Bar {
	return p.AddBar(total,
		mpb.PrependDecorators(
			decor.Name(fmt.Sprintf("%-30s", truncateName(name, 30)), decor.WC{W: 32}),
		),
		mpb.AppendDecorators(
			decor.CountersKibiByte("% .2f / % .2f"),
			decor.Percentage(decor.WCSyncSpace),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 60, decor.WCSyncSpace),
		),
	)
}

// NewTotalBar 创建总进度条
func NewTotalBar(p *mpb.Progress, total int64) *mpb.Bar {
	return p.AddBar(total,
		mpb.PrependDecorators(
			decor.Name("Total", decor.WC{W: 32}),
		),
		mpb.AppendDecorators(
			decor.CountersKibiByte("% .2f / % .2f"),
			decor.Percentage(decor.WCSyncSpace),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 60, decor.WCSyncSpace),
		),
	)
}

func truncateName(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

// SendXfer 发送文件或目录
func SendXfer(ctx context.Context, h host.Host, remote peer.ID, kind, arg string, console *ui.Console, seed uint64) error {
	// 实现文件发送逻辑
	// 这里只是框架，具体实现需要从 main.go 中迁移
	return fmt.Errorf("not implemented yet")
}

// HandleIncomingXfer 处理接收文件或目录的逻辑
func HandleIncomingXfer(ctx context.Context, h host.Host, xs network.Stream, outDir string, askYesNo func(q string, timeout time.Duration) bool, console *ui.Console, seed uint64) {
	defer xs.Close()
	// 1. 读取传输提议
	typ, payload, err := ReadFrame(xs)
	if err != nil || typ != FrameOffer {
		return
	}
	var off XferOffer
	_ = json.Unmarshal(payload, &off)

	// 2. 询问用户是否接受
	info := ""
	switch off.Kind {
	case "file":
		info = fmt.Sprintf("Peer wants to send file %q (%d bytes).", off.Name, off.Size)
	case "dir":
		info = fmt.Sprintf("Peer wants to send directory %q (%d files, total %d bytes).", off.Name, off.Files, off.Size)
	}
	console.Logln(info)
	if !askYesNo("Accept? [y/N]: ", 30*time.Second) {
		_ = WriteFrame(xs, FrameReject, nil)
		return
	}
	if err := WriteFrame(xs, FrameAccept, nil); err != nil {
		return
	}

	// 3. 初始化进度条
	var p *mpb.Progress
	var fileBar, totalBar *mpb.Bar
	if (off.Kind == "file" && off.Size > 0) || (off.Kind == "dir" && off.Size > 0) {
		p = mpb.New(
			mpb.WithWidth(64),
			mpb.WithRefreshRate(120*time.Millisecond),
			mpb.WithOutput(os.Stderr),
		)
		if off.Kind == "file" {
			fileBar = NewFileBar(p, off.Name, off.Size)
		} else {
			totalBar = NewTotalBar(p, off.Size)
		}
	}
	createdBar := func() bool { return p != nil && (fileBar != nil || totalBar != nil) }

	// 4. 循环处理接收到的帧
	var fw *os.File
	var dstPath string
	var expectHash string
	failedFiles := make([]string, 0)
	hasher := xxh3.NewSeed(seed)
	lastTick := time.Now()

	for {
		typ, payload, err = ReadFrame(xs)
		if err != nil {
			return
		}
		switch typ {
		case FrameFileHdr:
			// 处理文件头
			var hdr map[string]any
			_ = json.Unmarshal(payload, &hdr)
			name, _ := hdr["name"].(string)
			size, _ := hdr["size"].(float64)
			_, _ = hdr["algo"].(string) // algo 暂时不使用
			expectHash, _ = hdr["hash"].(string)

			dstPath = filepath.Join(outDir, name)
			if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
				_ = WriteFrame(xs, FrameFileNack, nil)
				return
			}
			fw, err = os.Create(dstPath)
			if err != nil {
				_ = WriteFrame(xs, FrameFileNack, nil)
				return
			}
			hasher.Reset()
			if p != nil && off.Kind == "dir" && int64(size) > 0 {
				if fileBar != nil {
					fileBar.Abort(true)
					fileBar.Wait()
				}
				fileBar = NewFileBar(p, name, int64(size))
			}
			lastTick = time.Now()

		case FrameChunk:
			// 处理数据块
			if fw == nil {
				return
			}
			_, _ = hasher.Write(payload)
			if _, err := fw.Write(payload); err != nil {
				_ = fw.Close()
				_ = os.Remove(dstPath)
				_ = WriteFrame(xs, FrameFileNack, nil)
				return
			}
			elapsed := time.Since(lastTick)
			if fileBar != nil {
				fileBar.EwmaIncrBy(len(payload), elapsed)
			}
			if totalBar != nil {
				totalBar.EwmaIncrBy(len(payload), elapsed)
			}
			lastTick = time.Now()

		case FrameFileDone:
			// 文件接收完成，进行校验
			if fw != nil {
				_ = fw.Close()
				fw = nil
			}
			if fileBar != nil {
				fileBar.SetTotal(-1, true)
			}
			sum := hasher.Sum128().Bytes()
			got := fmt.Sprintf("%x", sum[:])
			if expectHash != "" && got != expectHash {
				_ = os.Remove(dstPath)
				_ = WriteFrame(xs, FrameFileNack, nil)
				failedFiles = append(failedFiles, filepath.Base(dstPath))
			} else {
				_ = WriteFrame(xs, FrameFileAck, nil)
			}

		case FrameXferDone:
			// 传输完成
			if totalBar != nil {
				totalBar.SetTotal(-1, true)
			}
			if p != nil && createdBar() {
				p.Wait()
			}
			if len(failedFiles) > 0 {
				console.Println("some files failed integrity check:")
				for _, f := range failedFiles {
					console.Println("  - " + f)
				}
			}
			return

		default:
			return
		}
	}
}
