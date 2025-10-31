package server

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// LoadOrCreateIdentity 从指定路径加载 libp2p 的私钥
// 如果文件不存在，则生成一个新的私钥并保存到该路径，以确保服务器重启后 PeerID 不变
func LoadOrCreateIdentity(path string) (crypto.PrivKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return crypto.UnmarshalPrivateKey(b)
	}
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	// 确保目录存在
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// 以安全的权限写入私钥文件
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
