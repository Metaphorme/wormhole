package server

import (
	"sync"
	"time"
)

// IPLimiter 实现了一个基于 IP 的频率限制器
// 它同时跟踪两个滑动窗口：一个是总请求频率，另一个是失败操作频率
type IPLimiter struct {
	mu         sync.Mutex
	reqs       map[string][]time.Time // 记录每个 IP 的请求时间戳
	fails      map[string][]time.Time // 记录每个 IP 的失败操作时间戳
	reqWindow  time.Duration          // 请求频率的统计窗口
	maxReqs    int                    // 窗口内最大请求数
	failWindow time.Duration          // 失败频率的统计窗口
	maxFails   int                    // 窗口内最大失败数
}

// NewIPLimiter 创建一个新的 IP 频率限制器实例
func NewIPLimiter(reqWindow time.Duration, maxReqs int, failWindow time.Duration, maxFails int) *IPLimiter {
	return &IPLimiter{
		reqs:       make(map[string][]time.Time),
		fails:      make(map[string][]time.Time),
		reqWindow:  reqWindow,
		maxReqs:    maxReqs,
		failWindow: failWindow,
		maxFails:   maxFails,
	}
}

// pruneLocked 清理两个map中已经移出滑动窗口的旧时间戳
// 这个方法不是线程安全的，需要在锁的保护下调用
func (l *IPLimiter) pruneLocked(now time.Time) {
	// 清理请求记录
	for ip, arr := range l.reqs {
		j := 0
		for _, t := range arr {
			if now.Sub(t) <= l.reqWindow {
				arr[j] = t
				j++
			}
		}
		if j == 0 {
			delete(l.reqs, ip)
		} else {
			l.reqs[ip] = arr[:j]
		}
	}
	// 清理失败记录
	for ip, arr := range l.fails {
		j := 0
		for _, t := range arr {
			if now.Sub(t) <= l.failWindow {
				arr[j] = t
				j++
			}
		}
		if j == 0 {
			delete(l.fails, ip)
		} else {
			l.fails[ip] = arr[:j]
		}
	}
}

// Allow 判断来自特定 IP 的请求是否应该被允许
// 如果不允许，它会返回 false 和一个建议的等待时间
func (l *IPLimiter) Allow(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	// 检查总请求频率
	arr := append(l.reqs[ip], now)
	l.reqs[ip] = arr
	if len(arr) > l.maxReqs {
		// 计算建议等待时间：等待直到最早的请求移出窗口
		wait := l.reqWindow - now.Sub(arr[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}

	// 检查失败操作频率
	if fails := l.fails[ip]; len(fails) > l.maxFails {
		wait := l.failWindow - now.Sub(fails[0])
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}

	return true, 0
}

// RecordFail 记录一次来自特定 IP 的失败操作
func (l *IPLimiter) RecordFail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	l.fails[ip] = append(l.fails[ip], now)
}
