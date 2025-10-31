// Package examples 演示如何使用重构后的包
package examples

import (
	"context"
	"fmt"

	"github.com/Metaphorme/wormhole/pkg/api"
	"github.com/Metaphorme/wormhole/pkg/crypto"
	"github.com/Metaphorme/wormhole/pkg/models"
	"github.com/Metaphorme/wormhole/pkg/server"
	"github.com/Metaphorme/wormhole/pkg/ui"
)

// 示例1: 使用 API 客户端
func ExampleAPIClient() {
	// 创建 API 客户端
	client := api.NewClient("https://wormhole.example.com")

	ctx := context.Background()

	// 分配密码牌
	resp, err := client.Allocate(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Nameplate: %s\n", resp.Nameplate)
	fmt.Printf("Expires: %s\n", resp.ExpiresAt)

	// 认领密码牌
	claimResp, err := client.Claim(ctx, resp.Nameplate, "host")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Status: %s\n", claimResp.Status)

	// 标记为已消耗
	if err := client.Consume(ctx, resp.Nameplate); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
}

// 示例2: 使用加密模块
func ExampleCrypto() {
	// 这里只是示例，实际使用需要真实的 PeerID 和其他参数
	passphrase := "correct-horse-battery"
	nameplate := "123"
	_ = passphrase // 实际使用时需要传递给 PAKE
	_ = nameplate  // 实际使用时需要传递给 PAKE

	// 注意：这里省略了 protocol.ID 和 peer.ID 的创建，实际使用时需要提供
	// pakeState := crypto.NewPAKEState(true, passphrase, nameplate, proto, localID, remoteID)

	// 生成 SAS
	transcript := []byte("example-transcript")
	sharedKey := []byte("shared-secret-key")
	sas := crypto.SASFromKey(sharedKey, transcript)
	fmt.Printf("SAS: %s\n", sas)

	// HKDF 密钥派生
	derivedKey := crypto.HkdfBytes(sharedKey, "test-label", transcript, 32)
	fmt.Printf("Derived key length: %d\n", len(derivedKey))
}

// 示例3: 使用 UI 控制台
func ExampleConsole() {
	// 创建控制台
	console, err := ui.NewConsole("> ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer console.Close()

	// 打印日志
	console.Logln("Application started")
	console.Logf("Connection to %s established", "peer-id")

	// 打印彩色文本
	console.Println(ui.C("Important message", ui.CBold+ui.CCyan))

	// 询问用户
	// answer := ui.AskYesNo(console, "Continue? [y/N]: ", 30*time.Second, true)
}

// 示例4: 使用服务端数据库
func ExampleServerDatabase() {
	// 打开数据库
	db, err := server.OpenControlDB("./test.db")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer db.Close()

	// 插入新密码牌
	// err = db.InsertNew("123", 30*time.Minute, time.Now(), "192.168.1.1")

	// 加载密码牌
	// row, err := db.Load("123")

	// 认领密码牌
	// status, row, err := db.Claim("123", "host", time.Now(), "192.168.1.2")
}

// 示例5: 使用服务端频率限制器
func ExampleRateLimiter() {
	// 创建限制器: 1分钟内最多120个请求，10分钟内最多30次失败
	// limiter := server.NewIPLimiter(1*time.Minute, 120, 10*time.Minute, 30)

	// 检查请求是否允许
	// allowed, waitTime := limiter.Allow("192.168.1.1", time.Now())
	// if !allowed {
	//     fmt.Printf("Rate limited, retry after %v\n", waitTime)
	// }

	// 记录失败
	// limiter.RecordFail("192.168.1.1", time.Now())
}

// 示例6: 使用数据模型
func ExampleModels() {
	// 创建连接信息
	connInfo := models.ConnectionInfo{
		Rendezvous: models.AddrBundle{
			Namespace: "wormhole",
			Addrs:     []string{"/ip4/1.2.3.4/tcp/4001/p2p/PeerID"},
		},
		Relay: models.AddrBundle{
			Namespace: "circuit-relay-v2",
			Addrs:     []string{"/ip4/1.2.3.4/tcp/4001/p2p/PeerID/p2p-circuit"},
		},
		Topic: "/wormhole/123",
	}
	fmt.Printf("Topic: %s\n", connInfo.Topic)

	// 使用协议常量
	fmt.Printf("Chat protocol: %s\n", models.ProtoChat)
	fmt.Printf("Transfer protocol: %s\n", models.ProtoXfer)
}
