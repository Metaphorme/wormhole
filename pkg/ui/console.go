package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/Metaphorme/wormhole/pkg/p2p"
)

// ANSI 颜色代码 (遵循 NO_COLOR 环境变量)
var colorEnabled = os.Getenv("NO_COLOR") == ""

// C 是一个辅助函数，用于给字符串添加 ANSI 颜色代码
func C(s, code string) string {
	if !colorEnabled {
		return s
	}
	return code + s + "\x1b[0m"
}

const (
	CBold = "\x1b[1m"
	CDim  = "\x1b[2m"
	CCyan = "\x1b[36m"
	CYel  = "\x1b[33m"
)

// Console 是一个对 readline 库的封装，提供了线程安全的控制台 I/O 操作
type Console struct {
	rl            *readline.Instance
	mu            sync.Mutex
	defaultPrompt string
}

// NewConsole 创建一个新的控制台实例
func NewConsole(prompt string) (*Console, error) {
	rl, err := readline.New(prompt)
	if err != nil {
		return nil, err
	}
	return &Console{rl: rl, defaultPrompt: prompt}, nil
}

// NewConsoleWithReadline 使用已有的 readline 实例创建控制台（主要用于测试）
func NewConsoleWithReadline(rl *readline.Instance, prompt string) *Console {
	return &Console{rl: rl, defaultPrompt: prompt}
}

// Close 关闭控制台
func (c *Console) Close() { _ = c.rl.Close() }

// SetPrompt 设置命令提示符
func (c *Console) SetPrompt(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rl.SetPrompt(p)
	c.rl.Refresh()
}

// ResetPrompt 重置命令提示符为默认值
func (c *Console) ResetPrompt() { c.SetPrompt(c.defaultPrompt) }

// Println 在刷新 readline 提示的同时打印一行消息，避免覆盖用户输入
func (c *Console) Println(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.rl.Stdout().Write([]byte("\r" + msg + "\n"))
	c.rl.Refresh()
}

// Logln 打印带时间戳的日志消息
func (c *Console) Logln(msg string) { c.Println(C(ts(), CDim) + " " + msg) }

// Logf 打印格式化的带时间戳的日志消息
func (c *Console) Logf(format string, a ...any) {
	c.Println(C(ts(), CDim) + " " + fmt.Sprintf(format, a...))
}

// PromptQuestion 设置一个问题提示符
func (c *Console) PromptQuestion(q string) { c.SetPrompt(q) }

// PromptQuestionAndRestore 设置一个问题提示符并返回一个恢复函数
func (c *Console) PromptQuestionAndRestore(q string) func() {
	c.SetPrompt(q)
	return func() { c.ResetPrompt() }
}

// Readline 读取一行用户输入
func (c *Console) Readline() (string, error) {
	return c.rl.Readline()
}

// Refresh 刷新提示符显示
func (c *Console) Refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rl.Refresh()
}

// ts 返回当前时间的格式化字符串
func ts() string { return time.Now().Format("2006-01-02 15:04:05") }

// PrintPeerVerifyCard 打印对等节点验证信息卡片，包含其ID和短认证字符串(SAS)
func PrintPeerVerifyCard(c *Console, remote peer.ID, sas string) {
	c.Println(C("┌─ Peer Verification ───────────────────────────────────────┐", CBold))
	c.Println("  ID  : " + C(remote.String(), CCyan))
	c.Println("  SAS : " + C(sas, CYel+CBold))
	c.Println(C("└───────────────────────────────────────────────────────────┘", CBold))
}

// PrintConnCard 打印连接摘要卡片，显示连接路径、本地和远程地址等信息
func PrintConnCard(c *Console, pi p2p.PathInfo, local, remote ma.Multiaddr, verbose bool) {
	pathLine := ""
	if pi.Kind == "RELAY" {
		pathLine = fmt.Sprintf("RELAY via %s (%s)", pi.RelayID, pi.Transport)
	} else {
		pathLine = fmt.Sprintf("DIRECT (%s)", pi.Transport)
	}
	c.Println(C("┌─ Connection Summary ──────────────────────────────┐", CBold))
	c.Println("  path   : " + C(pathLine, CCyan))
	c.Println("  local  : " + local.String())
	c.Println("  remote : " + remote.String())
	if pi.Kind == "RELAY" && verbose {
		c.Println("  via    : " + pi.RelayVia)
	}
	c.Println(C("└───────────────────────────────────────────────────┘", CBold))
}

// AskYesNo 向用户提问并等待 y/N 回答，有超时
func AskYesNo(c *Console, question string, timeout time.Duration, defaultNo bool) bool {
	restore := c.PromptQuestionAndRestore(question)
	defer restore()

	ansCh := make(chan string, 1)
	go func() {
		line, err := c.Readline()
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
		c.Println("")
		return !defaultNo
	}
}
