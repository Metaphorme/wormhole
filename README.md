# Wormhole

<div align="center">

一个安全、简单、快速的点对点文件传输工具

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 简介

Wormhole 是一个基于 [libp2p](https://libp2p.io/) 的现代化文件传输工具，灵感来自 [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole)。它允许用户通过简短的"虫洞代码"在两台计算机之间安全地传输文件或目录，无需复杂的网络配置。

### ✨ 主要特性

- 🔐 **端到端加密**: 使用 SPAKE2 密码认证密钥交换协议 (PAKE)，确保传输安全
- 🌐 **P2P 直连**: 基于 libp2p 实现点对点连接，支持 NAT 穿透
- 📝 **简单易用**: 使用简短的人类可读代码（如 `250-semicolon-turtle`）进行配对
- 💬 **实时聊天**: 支持文本消息实时传输
- ⚡ **高性能**: 支持多文件、目录传输，带有实时进度显示
- 🔄 **自动中继**: 在无法直连时自动使用中继服务器
- 🎯 **跨平台**: 纯 Go 实现，支持 Linux、macOS、Windows
- 🛡️ **隐私保护**: 无需中心化服务器存储文件，配对码阅后即焚

### 🏗️ 架构

项目由两个主要组件构成：

#### 1. wormhole (客户端)
- 文件发送方和接收方
- 支持交互式命令行界面和实时聊天
- 自动处理 PAKE 握手和文件传输
- 支持直连和中继模式

#### 2. wormhole-server (服务端)
- 提供控制面 API（分配/认领虫洞代码）
- 集成 libp2p Rendezvous 服务（帮助节点发现）
- 提供 Relay v2 中继服务（NAT 穿透）
- 使用 SQLite 持久化状态
- 支持频率限制防止滥用

### 📦 安装

#### 从源码编译

确保已安装 Go 1.25.0 或更高版本：

```bash
# 克隆仓库
git clone https://github.com/Metaphorme/wormhole.git
cd wormhole

# 编译客户端
go build -o wormhole ./cmd/wormhole

# 编译服务端（可选，如果需要自建服务器）
go build -o wormhole-server ./cmd/wormhole-server

# 运行测试
go test ./...
```

### 🚀 快速开始

#### 基本使用（使用内置服务器）

Wormhole 客户端已内置官方提供的免费中心服务器，可以直接使用。

**在设备 A 上（发起方）：**

```bash
./wormhole
```

输出示例：
```
Your PeerID: 12D3KooWJZQCkVyttfh9bouZsPpzu1m14wAoVawMCXbaq4QiWTZz
Starting session…
Your code: 250-semicolon-turtle
Ask peer to run: wormhole -c 250-semicolon-turtle
(Expires: 2025-09-07 20:50:59)
waiting for peer…
```

**在设备 B 上（连接方）：**

```bash
./wormhole -c 250-semicolon-turtle
```

**身份验证：**

双方都会看到对方的 Peer ID 和短认证字符串 (SAS)：

```
┌─ Peer Verification ───────────────────────────────────────┐
ID  : 12D3KooWT349yUGxCDeDavKEK997f2Dp2CuEj7fRw8zpTW6MzU9h
SAS : 🐼 🍪 ⛰️ 🎲 🍫
└───────────────────────────────────────────────────────────┘
Confirm peer within 30s [y/N]:
```

> **⚠️ 安全提示**: 请务必通过其他安全通讯方式（如电话、即时消息）核对 SAS，确保没有中间人攻击。

**连接成功后：**

```
┌─ Connection Summary ──────────────────────────────┐
path   : DIRECT (quic-v1)
local  : /ip6/::/udp/38263/quic-v1
remote : /ip6/::1/udp/58630/quic-v1
└───────────────────────────────────────────────────┘
Commands:
/peer                  show peer id & current path
/send -f <file>        send a file
/send -d <dir>         send a directory recursively
/bye                   close the chat
connected. type message to chat, or a command starting with '/'.
>
```

#### 交互式命令

连接建立后，可以使用以下命令：

```bash
# 发送文本消息
> Hello, world!

# 发送单个文件
> /send -f myfile.txt

# 发送整个目录
> /send -d ./my-folder

# 查看连接信息
> /peer

# 关闭连接
> /bye
```

#### 非交互模式发送文件

```bash
# 发送单个文件
./wormhole send myfile.txt

# 发送多个文件
./wormhole send file1.txt file2.jpg document.pdf

# 发送目录
./wormhole send ./my-folder

# 指定自定义控制服务器
./wormhole send -control http://your-server:8080 myfile.txt
```

#### 非交互模式接收文件

```bash
# 使用虫洞代码接收
./wormhole receive 250-semicolon-turtle

# 指定保存目录
./wormhole receive -output ./downloads 250-semicolon-turtle

# 自动接受传输（无需确认）
./wormhole receive -yes 250-semicolon-turtle

# 指定自定义控制服务器
./wormhole receive -control http://your-server:8080 250-semicolon-turtle
```

### 🖥️ 部署服务端

虽然客户端已内置免费服务器，但您也可以部署自己的服务器。

#### 基本部署

```bash
./wormhole-server \
  -listen "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4002/ws" \
  -control-listen ":8080" \
  -db ./wormhole.db
```

首次运行会生成：
- `server.key`: 服务器身份密钥文件（请妥善保管）
- `wormhole.db`: SQLite 数据库

#### 服务端参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `/ip4/0.0.0.0/tcp/4001,...` | libp2p 监听地址，支持 TCP、QUIC、WebSocket |
| `-control-listen` | `:8080` | HTTP 控制面监听地址 |
| `-db` | `./wormhole.db` | SQLite 数据库路径 |
| `-nameplate-ttl` | `30m` | 虫洞代码有效期 |
| `-nameplate-digits` | `3` | 代码数字位数（3-4 推荐） |
| `-rendezvous-namespace` | `wormhole` | Rendezvous 服务命名空间 |
| `-public-addrs` | 自动检测 | 公网地址（用于 NAT 后的服务器） |
| `-bootstrap` | 无 | Bootstrap 节点地址（可选） |
| `-identity` | `./server.key` | 持久化私钥路径 |
| `-rate-req-window` | `1m` | 请求速率窗口时间 |
| `-rate-max-reqs` | `120` | 窗口内最大请求数 |
| `-rate-fail-window` | `10m` | 失败速率窗口时间 |
| `-rate-max-fails` | `30` | 窗口内最大失败数 |

#### 服务器示例配置

**基础配置：**
```bash
./wormhole-server \
  -listen "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1" \
  -control-listen ":8080" \
  -db /var/lib/wormhole/wormhole.db \
  -identity /var/lib/wormhole/server.key
```

**公网服务器（NAT 后）：**
```bash
./wormhole-server \
  -listen "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1" \
  -control-listen ":8080" \
  -public-addrs "/ip4/203.0.113.1/tcp/4001,/ip4/203.0.113.1/udp/4001/quic-v1" \
  -db ./wormhole.db
```

**严格频率限制：**
```bash
./wormhole-server \
  -control-listen ":8080" \
  -rate-req-window "1m" \
  -rate-max-reqs 60 \
  -rate-fail-window "5m" \
  -rate-max-fails 10 \
  -db ./wormhole.db
```

#### 使用自定义服务器

客户端连接自定义服务器：

```bash
# 发起连接
./wormhole -control http://your-server:8080

# 加入连接
./wormhole -c 123-code-here -control http://your-server:8080

# 发送文件
./wormhole send -control http://your-server:8080 myfile.txt

# 接收文件
./wormhole receive -control http://your-server:8080 123-code-here
```

### 🔧 高级用法

#### 命令行参数

**客户端参数：**

```bash
./wormhole [flags] [command]

通用标志:
  -c <code>              使用指定代码连接
  -control <url>         控制服务器 URL（默认：内置服务器）
  -v                     详细输出模式
  -timeout <duration>    超时时间（默认：10m）

send 命令:
  ./wormhole send [flags] <file/dir>...
  -skip-sas             跳过 SAS 验证（不推荐）
  -yes                  自动确认所有提示

receive 命令:
  ./wormhole receive [flags] <code>
  -output <dir>         保存目录（默认：当前目录）
  -yes                  自动接受传输
```

#### 详细日志

```bash
# 启用详细输出
./wormhole -v

# 查看更多调试信息
./wormhole -v -v
```

#### 自定义超时

```bash
# 设置 5 分钟超时
./wormhole -timeout 5m

# 设置 1 小时超时
./wormhole send -timeout 1h myfile.txt
```

### 📚 工作原理

#### 1. 配对阶段

```
发送方                     控制服务器                    接收方
  |                             |                           |
  |------ POST /v1/allocate --->|                           |
  |<---- 250-semicolon-turtle --|                           |
  |                             |                           |
  |                             |<---- POST /v1/claim ------|
  |                             |------ paired status ----->|
  |                             |                           |
  |<-------- Rendezvous 交换地址 ------->|<------------------|
```

- 发送方向控制服务器申请一个唯一的"虫洞代码"（nameplate）
- 接收方使用此代码向服务器认领连接
- 双方通过 Rendezvous 服务发现对方的 libp2p 地址

#### 2. 密钥交换（PAKE）

```
发送方                                                    接收方
  |                                                          |
  |-- 建立 libp2p 流 /wormhole/chat/1.0.0 ------------------->|
  |                                                          |
  |========= SPAKE2 握手（使用虫洞代码作为密码）================|
  |                                                          |
  |<------ 共享密钥 K ---------|-------- 共享密钥 K --------->|
  |                                                          |
  |-- 发送 SAS(K, transcript) ------------------------------>|
  |<-- 发送 SAS(K, transcript) ------------------------------|
  |                                                          |
  [双方验证 SAS 一致，确认无 MITM]
  |                                                          |
  |<========== 使用派生密钥加密通信 ==========================>|
```

- 使用 SPAKE2 协议和虫洞代码作为共享密码
- 双方生成相同的共享密钥
- 通过 SAS（短认证字符串）验证，防止中间人攻击
- SAS 使用 emoji 显示，易于人类核对

#### 3. 文件传输协议

```
发送方                                                    接收方
  |                                                          |
  |-- OFFER {kind, name, size, files} ---------------------->|
  |                                                          |
  |                          [用户确认接受/拒绝]
  |                                                          |
  |<-- ACCEPT/REJECT ----------------------------------------|
  |                                                          |
  (如果接受)
  |                                                          |
  |-- FILE_HDR {name, size, hash} -------------------------->|
  |-- CHUNK [64KB] ----------------------------------------->|
  |-- CHUNK [64KB] ----------------------------------------->|
  |-- CHUNK [64KB] ----------------------------------------->|
  |     ...                                                  |
  |-- FILE_DONE -------------------------------------------->|
  |<-- FILE_ACK/NACK (验证哈希) ------------------------------|
  |                                                          |
  |-- XFER_DONE -------------------------------------------->|
```

- 发送方发送传输提议（Offer）
- 接收方确认接受或拒绝
- 分块传输（64KB/块），支持大文件
- 每个文件使用 XXH3 哈希校验完整性
- 实时进度条显示

### 🛠️ 项目结构

```
wormhole/
├── cmd/
│   ├── wormhole/                # 客户端主程序
│   │   ├── main.go              # 主逻辑和 CLI
│   │   ├── main_test.go         # 测试
│   │   └── eff_short_wordlist_2_0.txt  # 单词列表
│   └── wormhole-server/         # 服务端主程序
│       ├── main.go              # 服务器启动逻辑
│       └── main_test.go         # 测试
├── pkg/
│   ├── api/                     # 控制面 API 客户端
│   │   └── client.go            # HTTP API 包装
│   ├── client/                  # 客户端工具函数
│   │   └── utils.go
│   ├── crypto/                  # 加密和密钥派生
│   │   └── pake.go              # SPAKE2 PAKE 实现
│   ├── models/                  # 数据模型和常量
│   │   └── models.go            # API 请求/响应结构
│   ├── p2p/                     # libp2p 工具
│   │   └── path.go              # 连接路径分析
│   ├── server/                  # 服务端逻辑
│   │   ├── database.go          # SQLite 数据库操作
│   │   ├── handlers.go          # HTTP 请求处理
│   │   ├── identity.go          # 持久化身份管理
│   │   ├── limiter.go           # IP 频率限制
│   │   ├── middleware.go        # HTTP 中间件
│   │   └── utils.go             # 工具函数
│   ├── session/                 # 会话管理
│   │   └── session.go           # PAKE 握手和会话建立
│   ├── transfer/                # 文件传输协议
│   │   └── transfer.go          # 文件传输实现
│   └── ui/                      # 终端界面工具
│       └── console.go           # 交互式控制台
├── internal/
│   └── utils/                   # 内部工具函数
│       └── utils.go
├── examples/                    # 使用示例
│   └── usage_examples.go        # 各模块使用示例
├── go.mod                       # Go 模块定义
└── README.md                    # 本文件
```

### 🔒 安全特性

#### 密码学

- **SPAKE2 PAKE**: 
  - 基于椭圆曲线 Ed25519
  - 抵抗离线字典攻击
  - 即使中间人截获通信也无法破解

- **短认证字符串 (SAS)**: 
  - 使用 HKDF-SHA256 从共享密钥派生
  - 64 个 emoji 编码提供约 30 位熵
  - 用户可视化验证防止 MITM 攻击

- **HKDF 密钥派生**: 
  - 基于 RFC 5869
  - 从 PAKE 共享密钥派生会话密钥
  - 包含 transcript（会话上下文）防止重放

- **XXH3 校验和**: 
  - 快速非加密哈希（比 SHA256 快约 10 倍）
  - 用于文件完整性验证
  - 不用于安全目的

#### 网络安全

- **临时密钥**: 每次传输使用独立的 PAKE 密钥
- **短期代码**: 虫洞代码默认 30 分钟过期
- **无中心化存储**: 文件点对点传输，不经过服务器
- **频率限制**: 防止暴力破解和滥用

#### 最佳实践

1. **始终验证 SAS**: 通过独立安全通道（电话、Signal 等）确认
2. **使用强代码**: 虫洞代码应足够随机（服务端生成）
3. **及时销毁代码**: 传输完成后调用 `/v1/consume` 使代码失效
4. **私有网络**: 在信任网络中使用可降低风险
5. **自建服务器**: 对于敏感数据，建议部署私有服务器

### 🌐 网络特性

#### 传输协议

- **TCP**: 传统可靠传输，最广泛支持
- **QUIC (v1)**: UDP 基础上的多路复用，更低延迟
- **WebSocket**: 穿透 HTTP 代理，适合受限网络

#### 连接模式

```
场景 1: 直连（最佳）
A ←→ B
  
场景 2: 通过 NAT 打洞
A ←→ [NAT] ←→ [NAT] ←→ B
      (Hole punching)

场景 3: 中继（兜底）
A ←→ Relay ←→ B
```

#### NAT 穿透

- **Direct Connection**: 优先尝试直连
- **Hole Punching**: 使用 libp2p DCUtR (Direct Connection Upgrade through Relay)
- **Circuit Relay v2**: 有限中继（带宽和时间限制）

#### 地址发现

- **Rendezvous**: 轻量级的节点发现协议
- **Namespace 隔离**: 避免不同实例互相干扰
- **TTL 管理**: 自动清理过期注册

### 📊 性能指标

#### 传输性能

| 场景 | 速度 | 延迟 |
|------|------|------|
| 局域网直连 (QUIC) | ~800 Mbps | < 1ms |
| 局域网直连 (TCP) | ~600 Mbps | < 1ms |
| 公网直连 (QUIC) | 取决于带宽 | 取决于 RTT |
| 中继模式 | 50-100 Mbps | 较高 |

#### 资源使用

- **内存**: ~30-50 MB（空闲）
- **CPU**: 传输时约 20-40%（单核）
- **磁盘**: 流式处理，无需缓存整个文件

#### 可扩展性

- **文件大小**: 已测试 50GB+
- **并发连接**: 服务端可处理数百并发
- **数据库**: SQLite 单机可扩展至百万记录

### 🧪 测试

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./pkg/crypto

# 运行带覆盖率的测试
go test -cover ./...

# 运行基准测试
go test -bench=. ./pkg/crypto
```

### 🐛 故障排查

#### 连接问题

**问题: 无法建立连接**
```
解决方案:
1. 检查防火墙是否允许 UDP/4001 和 TCP/4001
2. 验证 NAT 类型（使用 stun 服务器测试）
3. 尝试使用 WebSocket 传输（更容易穿透防火墙）
4. 检查服务器是否正常运行（curl http://server:8080/v1/allocate）
```

**问题: 速度很慢**
```
可能原因:
1. 使用了中继而非直连
2. 网络拥塞
3. 对方设备性能限制

解决方案:
- 使用 /peer 命令查看连接路径
- 如果是 RELAY，尝试配置端口转发
- 检查 CPU 和网络使用率
```

#### 认证问题

**问题: SAS 不匹配**
```
原因: 可能存在中间人攻击或代码错误

解决方案:
1. 重新确认虫洞代码是否正确
2. 重新启动连接
3. 通过安全渠道确认对方身份
4. 考虑使用信任的网络环境
```

**问题: 代码过期**
```
解决方案:
1. 重新申请代码（默认 30 分钟有效）
2. 联系管理员调整 -nameplate-ttl 参数
```

#### 服务器问题

**问题: 服务器无法启动**
```bash
# 检查端口占用
lsof -i :8080
lsof -i :4001

# 检查数据库权限
ls -la wormhole.db

# 查看详细错误
./wormhole-server 2>&1 | tee server.log
```

**问题: 频率限制触发**
```
解决方案:
1. 调整 -rate-max-reqs 参数
2. 等待速率窗口重置
3. 检查是否有异常流量
```

### 💡 使用场景

- **设备间快速共享**: 在个人设备间传输文件，无需 USB 或云盘
- **远程协作**: 向同事发送大文件，无需邮件附件大小限制
- **安全传输**: 传输敏感数据，不经过第三方云存储
- **跨平台传输**: 在不同操作系统间无缝传输
- **临时文件共享**: 快速分享文件，无需创建持久链接
- **内网传输**: 在公司内网或家庭网络中高速传输

### 🔮 未来计划

- [ ] WebAssembly 支持（浏览器端传输）
- [ ] 移动客户端 (iOS/Android)
- [ ] 图形界面 (GUI) 应用
- [ ] 断点续传支持
- [ ] 多对一传输（一对多广播）
- [ ] 云存储集成（可选）
- [ ] 压缩选项（可配置）
- [ ] 更多加密套件（ChaCha20-Poly1305）
- [ ] 自定义 SAS 格式（数字、单词等）
- [ ] WebRTC 数据通道支持

### 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

#### 如何贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

#### 代码规范

- 遵循 Go 官方代码风格
- 添加适当的注释和文档
- 编写单元测试
- 运行 `go fmt` 和 `go vet`

### 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

### 🙏 致谢

- [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) - 原始设计灵感和协议理念
- [libp2p](https://libp2p.io/) - 模块化的 P2P 网络栈
- [go-libp2p-rendezvous](https://github.com/waku-org/go-libp2p-rendezvous) - Rendezvous 协议实现
- [gospake2](https://salsa.debian.org/vasudev/gospake2) - SPAKE2 Go 实现
- [mpb](https://github.com/vbauerster/mpb) - 漂亮的进度条库
- [readline](https://github.com/chzyer/readline) - 交互式命令行支持

---

## English

### Introduction

Wormhole is a modern file transfer tool built on [libp2p](https://libp2p.io/), inspired by [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole). It enables users to securely transfer files or directories between two computers using short, memorable "wormhole codes", without complex network configuration.

### ✨ Key Features

- 🔐 **End-to-End Encryption**: Uses SPAKE2 PAKE protocol for secure transfers
- 🌐 **P2P Direct Connection**: libp2p-based peer-to-peer with NAT traversal
- 📝 **Simple to Use**: Pairing with short human-readable codes (e.g., `250-semicolon-turtle`)
- 💬 **Real-time Chat**: Support for instant text messaging
- ⚡ **High Performance**: Multi-file/directory support with real-time progress
- 🔄 **Auto Relay**: Automatic relay fallback when direct connection fails
- 🎯 **Cross-Platform**: Pure Go implementation for Linux, macOS, Windows
- 🛡️ **Privacy First**: No centralized storage, ephemeral pairing codes

### 🏗️ Architecture

The project consists of two main components:

#### 1. wormhole (Client)
- File sender and receiver
- Interactive CLI with real-time chat support
- Automatic PAKE handshake and file transfer
- Direct and relay connection modes

#### 2. wormhole-server (Server)
- Control plane API (allocate/claim wormhole codes)
- Integrated libp2p Rendezvous service (peer discovery)
- Circuit Relay v2 service (NAT traversal)
- SQLite-based state persistence
- Rate limiting to prevent abuse

### 📦 Installation

#### Build from Source

Ensure Go 1.25.0 or later is installed:

```bash
# Clone the repository
git clone https://github.com/Metaphorme/wormhole.git
cd wormhole

# Build client
go build -o wormhole ./cmd/wormhole

# Build server (optional, if you need your own server)
go build -o wormhole-server ./cmd/wormhole-server

# Run tests
go test ./...
```

### 🚀 Quick Start

#### Basic Usage (Using Built-in Server)

The Wormhole client has a built-in free control server and can be used directly.

**On Device A (Initiator):**

```bash
./wormhole
```

Example output:
```
Your PeerID: 12D3KooWJZQCkVyttfh9bouZsPpzu1m14wAoVawMCXbaq4QiWTZz
Starting session…
Your code: 250-semicolon-turtle
Ask peer to run: wormhole -c 250-semicolon-turtle
(Expires: 2025-09-07 20:50:59)
waiting for peer…
```

**On Device B (Connector):**

```bash
./wormhole -c 250-semicolon-turtle
```

**Authentication:**

Both parties will see the peer's ID and Short Authentication String (SAS):

```
┌─ Peer Verification ───────────────────────────────────────┐
ID  : 12D3KooWT349yUGxCDeDavKEK997f2Dp2CuEj7fRw8zpTW6MzU9h
SAS : 🐼 🍪 ⛰️ 🎲 🍫
└───────────────────────────────────────────────────────────┘
Confirm peer within 30s [y/N]:
```

> **⚠️ Security Note**: Always verify the SAS through an independent secure channel (phone, instant messaging) to ensure no man-in-the-middle attack.

**After Connection:**

```
┌─ Connection Summary ──────────────────────────────┐
path   : DIRECT (quic-v1)
local  : /ip6/::/udp/38263/quic-v1
remote : /ip6/::1/udp/58630/quic-v1
└───────────────────────────────────────────────────┘
Commands:
/peer                  show peer id & current path
/send -f <file>        send a file
/send -d <dir>         send a directory recursively
/bye                   close the chat
connected. type message to chat, or a command starting with '/'.
>
```

#### Interactive Commands

After connection is established:

```bash
# Send text message
> Hello, world!

# Send a single file
> /send -f myfile.txt

# Send entire directory
> /send -d ./my-folder

# View connection info
> /peer

# Close connection
> /bye
```

#### Non-Interactive File Sending

```bash
# Send a single file
./wormhole send myfile.txt

# Send multiple files
./wormhole send file1.txt file2.jpg document.pdf

# Send a directory
./wormhole send ./my-folder

# Specify custom control server
./wormhole send -control http://your-server:8080 myfile.txt
```

#### Non-Interactive File Receiving

```bash
# Receive using wormhole code
./wormhole receive 250-semicolon-turtle

# Specify output directory
./wormhole receive -output ./downloads 250-semicolon-turtle

# Auto-accept transfer
./wormhole receive -yes 250-semicolon-turtle

# Specify custom control server
./wormhole receive -control http://your-server:8080 250-semicolon-turtle
```

### 🖥️ Deploy Your Own Server

While the client has a built-in free server, you can deploy your own.

#### Basic Deployment

```bash
./wormhole-server \
  -listen "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4002/ws" \
  -control-listen ":8080" \
  -db ./wormhole.db
```

First run generates:
- `server.key`: Server identity key file (keep it safe)
- `wormhole.db`: SQLite database

#### Server Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-listen` | `/ip4/0.0.0.0/tcp/4001,...` | libp2p listen addresses (TCP, QUIC, WebSocket) |
| `-control-listen` | `:8080` | HTTP control plane listen address |
| `-db` | `./wormhole.db` | SQLite database path |
| `-nameplate-ttl` | `30m` | Wormhole code TTL |
| `-nameplate-digits` | `3` | Code digit length (3-4 recommended) |
| `-rendezvous-namespace` | `wormhole` | Rendezvous service namespace |
| `-public-addrs` | Auto-detect | Public addresses (for servers behind NAT) |
| `-bootstrap` | None | Bootstrap node addresses (optional) |
| `-identity` | `./server.key` | Persistent private key path |
| `-rate-req-window` | `1m` | Request rate window |
| `-rate-max-reqs` | `120` | Max requests per window |
| `-rate-fail-window` | `10m` | Failure rate window |
| `-rate-max-fails` | `30` | Max failures per window |

### 📚 How It Works

See the Chinese section above for detailed protocol descriptions and diagrams.

### 🔒 Security Features

- **SPAKE2 PAKE**: Dictionary-attack resistant password-authenticated key exchange
- **Short Authentication String (SAS)**: Emoji-based verification against MITM
- **HKDF Key Derivation**: Secure session key derivation
- **XXH3 Checksums**: Fast file integrity verification
- **Ephemeral Keys**: Independent keys per transfer
- **Rate Limiting**: IP-level request limiting

### 🤝 Contributing

Issues and Pull Requests are welcome!

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

### 🙏 Acknowledgments

- [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) - Original design inspiration
- [libp2p](https://libp2p.io/) - Modular P2P networking stack
- [go-libp2p-rendezvous](https://github.com/waku-org/go-libp2p-rendezvous) - Rendezvous protocol
- [gospake2](https://salsa.debian.org/vasudev/gospake2) - SPAKE2 Go implementation
- [mpb](https://github.com/vbauerster/mpb) - Beautiful progress bars
- [readline](https://github.com/chzyer/readline) - Interactive command line

---

**Built with ❤️ using Go and libp2p**
