package main

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// session 一次玩家连接：一条 HTTP 信令交换 + 一对 ufrag + BDS 内部 UDP 地址。
type session struct {
	networkID   string
	clientUfrag string
	serverUfrag string
	icePwd      string          // answer 的 a=ice-pwd：STUN MESSAGE-INTEGRITY 验证密钥
	relayTarget *net.UDPAddr    // BDS 分配的内部 UDP 地址（answer 中首个候选）
	bdsPorts    map[int]bool    // answer 中出现的所有内部端口（反向解复用键）
	addrs       map[string]bool // 已学习的客户端 ip:port（受 maxAddrs 限制）

	clientAddr atomic.Pointer[net.UDPAddr] // 最新活跃的客户端来源（反向流量目标）
	lastSeen   atomic.Int64                // unix nano：最后活跃时间
	revSeen    atomic.Bool                 // 是否已打"首个回包"日志
}

func (s *session) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

func (s *session) idleFor(d time.Duration) bool {
	return time.Since(time.Unix(0, s.lastSeen.Load())) > d
}

// snapshot 不可变路由快照：读路径 atomic.Load 零锁，写路径整体替换（copy-on-write）。
// 注册/认领/回收均为低频事件（每玩家连接 1~3 次），全量重建成本可忽略；
// 换来每包转发路径完全无锁。
type snapshot struct {
	byUfrag   map[string]*session
	byBdsPort map[int]*session
	byClient  map[string]*session
}

type sessionTable struct {
	mu  sync.Mutex // 只串行化写路径；读路径走快照
	cur atomic.Pointer[snapshot]

	sessions map[*session]bool // 权威会话集（gc 判活）

	idle        time.Duration
	maxSessions int
	maxAddrs    int  // 每会话可学习的客户端地址数上限（防地址表被刷爆）
	insecure    bool // true = 会话无 icePwd 时退回无验证认领（兼容非常规后端）

	relayed    atomic.Uint64 // 正向：客户端 → BDS
	relayedRev atomic.Uint64 // 反向：BDS → 客户端
	dropped    atomic.Uint64
	claimed    atomic.Uint64
	rejected   atomic.Uint64 // MIC 验证失败（疑似伪造/抢占）
	unknownBds atomic.Uint64 // 本机来源但端口不在会话表
}

func newSessionTable(idle time.Duration, maxSessions, maxAddrs int, insecure bool) *sessionTable {
	t := &sessionTable{
		sessions:    map[*session]bool{},
		idle:        idle,
		maxSessions: maxSessions,
		maxAddrs:    maxAddrs,
		insecure:    insecure,
	}
	t.cur.Store(&snapshot{
		byUfrag:   map[string]*session{},
		byBdsPort: map[int]*session{},
		byClient:  map[string]*session{},
	})
	return t
}

var errTooManySessions = errors.New("会话数已达上限")

// register 注册一次新连接（信令阶段完成，answer 已解析）。
// icePwd 为 answer 的 a=ice-pwd，用于后续 STUN 认领的完整性验证。
func (t *sessionTable) register(networkID, clientUfrag, serverUfrag, icePwd string, addrs []*net.UDPAddr) error {
	if len(addrs) == 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) >= t.maxSessions {
		return errTooManySessions
	}
	s := &session{
		networkID:   networkID,
		clientUfrag: clientUfrag,
		serverUfrag: serverUfrag,
		icePwd:      icePwd,
		relayTarget: addrs[0],
		bdsPorts:    map[int]bool{},
		addrs:       map[string]bool{},
	}
	s.touch()
	for _, a := range addrs {
		s.bdsPorts[a.Port] = true
	}
	for p := range s.bdsPorts {
		for old := range t.sessions {
			if old != s && old.bdsPorts[p] {
				// 正常 BDS 每连接独立 socket，端口不应重叠。最常见原因是
				// server-udp-ports 被固定为单端口：旧连接占着端口不放，
				// 新连接绑定失败成为死会话（客户端 Door 超时）。按最新会话
				// 处理并明确提示，避免静默串话。
				log.Printf("[session] 警告：会话 %s 与 %s 的 BDS 端口 %d 重叠，按最新会话处理。"+
					"若 BDS 配置了 server-udp-ports=%d（固定单端口），请注释掉该项并重启 BDS——"+
					"固定单端口会导致重连/第二个玩家失败，本代理不需要固定端口",
					old.networkID, s.networkID, p, p)
				break
			}
		}
	}
	t.sessions[s] = true
	t.rebuildLocked()
	return nil
}

// claim 未知来源首包认领：STUN USERNAME 定位会话 → MESSAGE-INTEGRITY 验证
// （key = 会话 icePwd，RFC 8445 短期凭证）→ 学习客户端地址。
// 这是安全模型的核心：伪造者即使拿到 ufrag，没有 ice-pwd 也无法通过 HMAC 验证，
// 因而被拒之门外（ice-pwd 仅在信令应答中出现，不经过公网 UDP）。
func (t *sessionTable) claim(uaddr *net.UDPAddr, b []byte) (*session, claimVerdict) {
	u := stunUsername(b)
	if u == "" {
		return nil, claimNotSTUN
	}
	s := lookupByUsername(t.cur.Load(), u)
	if s == nil {
		return nil, claimNoSession
	}
	if s.icePwd == "" {
		if !t.insecure {
			return nil, claimNoPwd
		}
	} else if v := stunVerify(b, s.icePwd); v != stunVerified {
		if v == stunBadIntegrity {
			return nil, claimBadMIC
		}
		return nil, claimNoMIC
	}

	t.mu.Lock()
	if !t.sessions[s] { // 验证期间被 gc 回收
		t.mu.Unlock()
		return nil, claimNoSession
	}
	key := uaddr.String()
	if !s.addrs[key] {
		if len(s.addrs) >= t.maxAddrs {
			t.mu.Unlock()
			return nil, claimTooManyAddrs
		}
		s.addrs[key] = true
		t.rebuildLocked() // 新地址入表：重建并原子发布新快照（低频路径）
	}
	s.clientAddr.Store(uaddr)
	s.touch()
	t.mu.Unlock()
	return s, claimOK
}

// lookupByUsername 按 STUN USERNAME（"serverUfrag:clientUfrag"，任一序）在快照中定位会话。
func lookupByUsername(snap *snapshot, u string) *session {
	parts := strings.SplitN(u, ":", 2)
	for _, p := range parts {
		if p == "" {
			continue
		}
		if s, ok := snap.byUfrag[p]; ok {
			return s
		}
	}
	return nil
}

// rebuildLocked 从权威会话集整体重建快照并原子发布（调用方持锁）。
func (t *sessionTable) rebuildLocked() {
	nb, np, nc := map[string]*session{}, map[int]*session{}, map[string]*session{}
	for s := range t.sessions {
		if s.clientUfrag != "" {
			nb[s.clientUfrag] = s
		}
		if s.serverUfrag != "" {
			nb[s.serverUfrag] = s
		}
		for p := range s.bdsPorts {
			np[p] = s
		}
		for k := range s.addrs {
			nc[k] = s
		}
	}
	t.cur.Store(&snapshot{byUfrag: nb, byBdsPort: np, byClient: nc})
}

func (t *sessionTable) gc() {
	t.mu.Lock()
	expired := 0
	for s := range t.sessions {
		if s.idleFor(t.idle) {
			delete(t.sessions, s)
			expired++
		}
	}
	if expired > 0 {
		t.rebuildLocked()
	}
	t.mu.Unlock()
	if expired > 0 {
		log.Printf("[gc] 回收 %d 个空闲会话", expired)
	}
}

func (t *sessionTable) count() int {
	t.mu.Lock()
	n := len(t.sessions)
	t.mu.Unlock()
	return n
}

func (t *sessionTable) logStats() {
	log.Printf("[stats] 会话=%d 正向=%d 反向=%d 认领=%d 拒绝=%d 丢弃=%d 未知BDS端口=%d",
		t.count(), t.relayed.Load(), t.relayedRev.Load(), t.claimed.Load(),
		t.rejected.Load(), t.dropped.Load(), t.unknownBds.Load())
}

// claimVerdict 认领结果，用于 mux 侧分类计数与日志。
type claimVerdict int

const (
	claimOK           claimVerdict = iota
	claimNotSTUN                   // 非 STUN 包（DTLS 等来自未知地址：ICE 检查未发生过，直接丢弃）
	claimNoSession                 // ufrag 不匹配任何会话
	claimNoMIC                     // STUN 包但无 MESSAGE-INTEGRITY 属性
	claimBadMIC                    // MESSAGE-INTEGRITY 验证失败（疑似伪造）
	claimNoPwd                     // 会话无 ice-pwd 且未开启 -insecure-claim
	claimTooManyAddrs              // 该会话客户端地址数超上限（疑似地址伪造刷表）
)
