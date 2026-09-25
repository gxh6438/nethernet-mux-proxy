package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reIceUfrag  = regexp.MustCompile(`(?m)^a=ice-ufrag:\s*(\S+)`)
	reIcePwd    = regexp.MustCompile(`(?m)^a=ice-pwd:\s*(\S+)`)
	reCandParts = regexp.MustCompile(`(?m)^a=candidate:\S+\s+\d+\s+\S+\s+\d+\s+(\S+)\s+(\d+)`)
	reCandLine  = regexp.MustCompile(`(?m)^(a=candidate:\S+\s+\d+\s+\S+\s+\d+\s+)(\S+)(\s+)(\d+)(.*)$`)
)

// hopByHopHeaders 反向代理不应转发的逐跳头（RFC 7230 §6.1）。
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

const maxSDPSize = 1 << 20 // SDP 上限 1MB（正常 <100KB），防超大 body 攻击

type signalingServer struct {
	bds     string
	advIP   string
	advPort int
	table   *sessionTable
	client  *http.Client
}

func runSignaling(ctx context.Context, opts *options, table *sessionTable) error {
	s := &signalingServer{
		bds:     opts.BDS,
		advIP:   opts.AdvertiseIP,
		advPort: opts.AdvertisePort,
		table:   table,
		client: &http.Client{
			Timeout: 90 * time.Second, // BDS 全量收集 ICE 候选后才应答，放宽
			Transport: &http.Transport{
				MaxIdleConns:        256,
				MaxIdleConnsPerHost: 256,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/join", s.handle)  // GET 能力检查
	mux.HandleFunc("/v1/join/", s.handle) // POST SDP 交换
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound) // 其余路径不透传，减少暴露面
	})
	srv := &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,  // 防慢速头部攻击
		ReadTimeout:       95 * time.Second,  // SDP POST + 慢客户端
		WriteTimeout:      100 * time.Second, // 覆盖后端 90s ICE 收集
		IdleTimeout:       120 * time.Second,
	}

	// 先显式 Listen：失败（最常见为端口被占用）立即给出友好报错，
	// 而不是把错误塞进 channel 后以笼统日志退出。
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		fatalBind("TCP", opts.Listen, err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (s *signalingServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/join/") {
		s.handleSDPExchange(w, r)
		return
	}
	s.forwardRaw(w, r)
}

// forwardRaw 原样转发（GET /v1/join 能力检查等），剥离逐跳头。
func (s *signalingServer) forwardRaw(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest(r.Method, "http://"+s.bds+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()
	for _, h := range hopByHopHeaders {
		req.Header.Del(h)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "backend: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleSDPExchange 核心：转发 offer 原文，改写 answer 的候选地址。
// 注意：a=identity 断言只覆盖 a=fingerprint 行，候选行改写不破坏签名。
func (s *signalingServer) handleSDPExchange(w http.ResponseWriter, r *http.Request) {
	networkID := strings.TrimPrefix(r.URL.Path, "/v1/join/")
	r.Body = http.MaxBytesReader(w, r.Body, maxSDPSize)
	offer, err := io.ReadAll(r.Body)
	if err != nil || len(offer) == 0 {
		http.Error(w, "empty offer", http.StatusBadRequest)
		return
	}
	clientUfrag := firstSubmatch(reIceUfrag, string(offer))

	req, err := http.NewRequest(http.MethodPost, "http://"+s.bds+r.URL.Path, bytes.NewReader(offer))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/sdp")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[signal] 会话 %s：后端请求失败: %v", networkID, err)
		http.Error(w, "backend: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxSDPSize))

	if resp.StatusCode/100 != 2 || !strings.Contains(resp.Header.Get("Content-Type"), "sdp") || len(answer) < 20 {
		log.Printf("[signal] 会话 %s：后端异常应答 HTTP %d CT=%q body=%q",
			networkID, resp.StatusCode, resp.Header.Get("Content-Type"), truncateBody(answer, 80))
		w.WriteHeader(resp.StatusCode)
		w.Write(answer)
		return
	}

	serverUfrag := firstSubmatch(reIceUfrag, string(answer))
	icePwd := firstSubmatch(reIcePwd, string(answer))
	bdsAddrs := parseCandidateAddrs(string(answer))
	if len(bdsAddrs) == 0 {
		log.Printf("[signal] 会话 %s：answer 无候选地址（后端拒绝连接？）body=%q",
			networkID, truncateBody(answer, 120))
	} else if err := s.table.register(networkID, clientUfrag, serverUfrag, icePwd, bdsAddrs); err != nil {
		log.Printf("[signal] 会话 %s：%v，拒绝本次连接", networkID, err)
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	} else {
		log.Printf("[signal] 会话 %s 注册：clientUfrag=%q serverUfrag=%q BDS=%v → 改写通告 %s:%d",
			networkID, clientUfrag, serverUfrag, bdsAddrs[0], s.advIP, s.advPort)
	}

	rewritten := rewriteCandidates(string(answer), s.advIP, s.advPort)
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.WriteString(w, rewritten)
}

// parseCandidateAddrs 提取 answer 中全部候选地址（去重），
// 首个作为转发目标（BDS 实际绑定地址），全部端口用于反向解复用。
func parseCandidateAddrs(sdp string) []*net.UDPAddr {
	var out []*net.UDPAddr
	seen := map[string]bool{}
	for _, m := range reCandParts.FindAllStringSubmatch(sdp, -1) {
		key := m[1] + ":" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		port, _ := strconv.Atoi(m[2])
		ip := net.ParseIP(m[1])
		if ip == nil {
			ip = net.ParseIP("127.0.0.1") // mDNS 等非 IP 地址：兜底回环（同机部署）
		}
		out = append(out, &net.UDPAddr{IP: ip, Port: port})
	}
	return out
}

// rewriteCandidates 把所有 a=candidate 行的地址与端口替换为 mux 公网地址。
func rewriteCandidates(sdp, ip string, port int) string {
	repl := "${1}" + ip + "${3}" + strconv.Itoa(port) + "${5}"
	return reCandLine.ReplaceAllString(sdp, repl)
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func truncateBody(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
