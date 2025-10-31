package server

import (
	"log"
	"net/http"
	"time"
)

// LogRequests 是一个 HTTP 中间件，用于记录每个请求的基本信息和处理耗时
func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", ClientIP(r), r.Method, r.URL.Path, time.Since(start))
	})
}
