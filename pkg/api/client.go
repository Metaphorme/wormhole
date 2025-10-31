package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Metaphorme/wormhole/pkg/models"
)

// Client 控制面 API 客户端
type Client struct {
	BaseURL string
}

// NewClient 创建一个新的 API 客户端
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/")}
}

// Allocate 向控制服务器申请一个新的密码牌
func (c *Client) Allocate(ctx context.Context) (*models.AllocateResponse, error) {
	var resp models.AllocateResponse
	if err := c.postJSON(ctx, "/v1/allocate", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Claim 认领一个密码牌的其中一侧
func (c *Client) Claim(ctx context.Context, nameplate, side string) (*models.ClaimResponse, error) {
	req := models.ClaimRequest{
		Nameplate: nameplate,
		Side:      side,
	}
	var resp models.ClaimResponse
	if err := c.postJSON(ctx, "/v1/claim", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Consume 将密码牌标记为已消耗
func (c *Client) Consume(ctx context.Context, nameplate string) error {
	req := models.ConsumeRequest{Nameplate: nameplate}
	var resp map[string]string
	return c.postJSON(ctx, "/v1/consume", req, &resp)
}

// Fail 将密码牌标记为失败
func (c *Client) Fail(ctx context.Context, nameplate string) error {
	req := models.FailRequest{Nameplate: nameplate}
	var resp map[string]string
	return c.postJSON(ctx, "/v1/fail", req, &resp)
}

// postJSON 发送一个带指数退避重试的 HTTP POST 请求
func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	u := c.BaseURL + path
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
				backoff = min64(backoff*2, 30*time.Second)
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
			backoff = min64(backoff*2, 30*time.Second)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("exhausted retries")
}

func min64(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
