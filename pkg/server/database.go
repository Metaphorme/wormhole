package server

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // 引入 CGO-free 的 SQLite 驱动
)

// PlateStatus 定义了密码牌（nameplate）的几种状态
type PlateStatus string

const (
	// StatusWaiting 表示密码牌已被一方认领，正在等待另一方
	StatusWaiting PlateStatus = "waiting"
	// StatusPaired 表示密码牌已被双方认领，配对成功
	StatusPaired PlateStatus = "paired"
	// StatusFailed 表示密码牌无效，原因可能是过期、已被消耗、认领失败等
	StatusFailed PlateStatus = "failed"
)

// NameplateRow 对应数据库中 nameplates 表的一行记录
type NameplateRow struct {
	Nameplate   string         // 密码牌，即客户端使用的短码
	CreatedAt   int64          // 创建时间的 Unix 时间戳 (UTC)
	TTLSeconds  int64          // 有效期，单位秒
	ClaimedMask int64          // 认领状态掩码：bit0 代表 host(A)，bit1 代表 connect(B)。当值为3时表示双方都已认领
	Consumed    int64          // 是否已被消耗（成功建立连接后由客户端报告）。0 表示未消耗，1 表示已消耗
	FailCount   int64          // 失败计数器，用于记录无效认领等失败操作的次数
	LastIP      sql.NullString // 最后一次操作该记录的客户端 IP
}

// Expired 判断密码牌在给定的时间点是否已过期
func (r *NameplateRow) Expired(at time.Time) bool {
	expires := time.Unix(r.CreatedAt, 0).UTC().Add(time.Duration(r.TTLSeconds) * time.Second)
	return at.UTC().After(expires)
}

// ControlDB 是控制面数据库的封装，包含一个互斥锁以支持并发操作
type ControlDB struct {
	mu sync.Mutex
	db *sql.DB
}

// OpenControlDB 打开或创建一个 SQLite 数据库文件，并进行初始化配置
func OpenControlDB(path string) (*ControlDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 启用 WAL (Write-Ahead Logging) 模式，可以显著提高并发写入性能
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	// 设置忙碌超时时间，当数据库被锁定时，连接会等待最多5秒而不是立即返回错误
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	// 定义并执行数据库表结构（如果表不存在）
	schema := `
CREATE TABLE IF NOT EXISTS nameplates(
  nameplate TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  claimed_mask INTEGER NOT NULL DEFAULT 0,
  consumed INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_nameplates_created ON nameplates(created_at);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &ControlDB{db: db}, nil
}

// Close 关闭数据库连接
func (c *ControlDB) Close() error { return c.db.Close() }

// InsertNew 向数据库中插入一条新的密码牌记录
func (c *ControlDB) InsertNew(nameplate string, ttl time.Duration, now time.Time, ip string) error {
	_, err := c.db.Exec(`INSERT INTO nameplates(nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip)
VALUES(?, ?, ?, 0, 0, 0, ?)`, nameplate, now.UTC().Unix(), int64(ttl/time.Second), ip)
	return err
}

// Load 从数据库加载指定密码牌的信息
func (c *ControlDB) Load(nameplate string) (*NameplateRow, error) {
	row := c.db.QueryRow(`SELECT nameplate, created_at, ttl_seconds, claimed_mask, consumed, fail_count, last_ip FROM nameplates WHERE nameplate=?`, nameplate)
	var r NameplateRow
	if err := row.Scan(&r.Nameplate, &r.CreatedAt, &r.TTLSeconds, &r.ClaimedMask, &r.Consumed, &r.FailCount, &r.LastIP); err != nil {
		return nil, err
	}
	return &r, nil
}

// IncrFail 增加指定密码牌的失败计数
func (c *ControlDB) IncrFail(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET fail_count = fail_count + 1 WHERE nameplate=?`, nameplate)
	return err
}

// Delete 从数据库中删除指定的密码牌
func (c *ControlDB) Delete(nameplate string) error {
	_, err := c.db.Exec(`DELETE FROM nameplates WHERE nameplate=?`, nameplate)
	return err
}

// FailAndConsume 将密码牌标记为已消耗，并原子地增加失败计数（仅当之前未被消耗时）
// 这个操作是幂等的，用于客户端报告连接失败的场景
func (c *ControlDB) FailAndConsume(nameplate string) error {
	_, err := c.db.Exec(`
        UPDATE nameplates
           SET fail_count = fail_count + CASE WHEN consumed=0 THEN 1 ELSE 0 END,
               consumed   = 1
         WHERE nameplate = ?`, nameplate)
	return err
}

// Claim 处理客户端的认领请求，是核心业务逻辑之一
// 它会检查密码牌的有效性，处理重复认领和无效 side 的情况，并更新认领状态
// 如果密码牌已过期，会直接从数据库删除
func (c *ControlDB) Claim(nameplate, side string, now time.Time, ip string) (PlateStatus, *NameplateRow, error) {
	r, err := c.Load(nameplate)
	if err != nil {
		// 如果密码牌不存在，直接返回 failed 状态
		if err == sql.ErrNoRows {
			return StatusFailed, nil, nil
		}
		return "", nil, err
	}
	// 如果密码牌已过期，删除它并返回 failed
	if r.Expired(now) {
		_ = c.Delete(nameplate)
		return StatusFailed, nil, nil
	}
	// 如果密码牌已被消耗，返回 failed
	if r.Consumed != 0 {
		return StatusFailed, r, nil
	}

	var bit int64
	side = toLower(side)
	switch side {
	case "host", "a":
		bit = 1 // bit0 for host side
	case "connect", "b":
		bit = 2 // bit1 for connect side
	default:
		// 无效的 side 参数，增加失败计数并返回 failed
		_ = c.IncrFail(nameplate)
		return StatusFailed, r, nil
	}

	newMask := r.ClaimedMask | bit
	if newMask == r.ClaimedMask {
		// 重复认领同一侧，视为失败操作，增加失败计数
		_ = c.IncrFail(nameplate)
		return StatusFailed, r, nil
	}

	// 更新数据库中的认领掩码和最后操作IP
	if _, err := c.db.Exec(`UPDATE nameplates SET claimed_mask=?, last_ip=? WHERE nameplate=?`, newMask, ip, nameplate); err != nil {
		return "", nil, err
	}
	r.ClaimedMask = newMask
	r.LastIP = sql.NullString{String: ip, Valid: true}

	if newMask == 3 { // bit0 和 bit1 都被设置，表示双方都已认领
		return StatusPaired, r, nil
	}
	return StatusWaiting, r, nil
}

// Consume 将密码牌标记为已消耗，通常在客户端成功建立连接后调用
func (c *ControlDB) Consume(nameplate string) error {
	_, err := c.db.Exec(`UPDATE nameplates SET consumed=1 WHERE nameplate=?`, nameplate)
	return err
}

// CleanupExpired 定期清理数据库中已过期或已消耗的密码牌记录
func (c *ControlDB) CleanupExpired(now time.Time) (int64, error) {
	res, err := c.db.Exec(`DELETE FROM nameplates WHERE (created_at + ttl_seconds) < ? OR consumed=1`, now.UTC().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Lock 获取数据库锁
func (c *ControlDB) Lock() {
	c.mu.Lock()
}

// Unlock 释放数据库锁
func (c *ControlDB) Unlock() {
	c.mu.Unlock()
}

func toLower(s string) string {
	// 简单的 ASCII 小写转换
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
