package main

import (
	"log"
	"net"
	"time"
)

// runMux：单 UDP socket 承载所有玩家与全部 BDS 内部端口的双向转发。
//
// 转发决策（全部基于无锁快照，每包零锁竞争）：
//
//	客户端 → mux：
//	  已学习地址（快照 byClient 命中）→ 直接转发到该会话 relayTarget（热路径）；
//	  未知地址 → STUN 认领：USERNAME 定位会话 + MESSAGE-INTEGRITY 验证
//	  （HMAC key = 会话 ice-pwd，伪造者无法通过）→ 学习地址并转发。
//	BDS → mux：
//	  本机来源且端口 ∈ 快照 byBdsPort → 转给该会话最新活跃的客户端地址。
func runMux(bind string, t *sessionTable) {
	conn, err := net.ListenPacket("udp", bind)
	if err != nil {
		fatalBind("UDP", bind, err)
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		// 提高内核接收缓冲，降低高 pps 下的丢包
		_ = uc.SetReadBuffer(4 << 20)
	}
	log.Printf("[mux] UDP 监听 %s", conn.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("[mux] 读取错误: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		relayPacket(conn, t, buf[:n], src)
	}
}

func relayPacket(conn net.PacketConn, t *sessionTable, b []byte, src net.Addr) {
	uaddr, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	snap := t.cur.Load() // 无锁快照：读路径与写路径（注册/认领/gc）完全解耦

	// 正向快路径：已知客户端地址。刷新 clientAddr 为最新活跃来源——
	// 真实客户端会从多个本地 socket 发检查，回程必须跟随最新活跃者，
	// 否则回包会钉死在过期的 socket 上，导致 ICE 配对失败。
	if s := snap.byClient[uaddr.String()]; s != nil {
		s.touch()
		s.clientAddr.Store(uaddr)
		conn.WriteTo(b, s.relayTarget)
		t.relayed.Add(1)
		return
	}

	// 反向：本机来源且端口在会话表 → BDS 的回包。
	// （端口未命中时不能终止：同机部署的客户端来源也是本机地址，
	//   需落入下方认领路径；BDS 陈旧流量不匹配任何 ufrag，自然被拒）
	if isLocalAddr(uaddr) {
		if s := snap.byBdsPort[uaddr.Port]; s != nil {
			s.touch()
			if ca := s.clientAddr.Load(); ca != nil {
				conn.WriteTo(b, ca)
				t.relayedRev.Add(1)
				if !s.revSeen.Swap(true) {
					log.Printf("[mux] 会话 %s：首个回包 → %s（反向路径已打通）", s.networkID, ca)
				}
			} else {
				t.dropped.Add(1)
				log.Printf("[mux] 丢包：会话 %s：BDS 回包到达，但客户端地址尚未学习到", s.networkID)
			}
			return
		}
		// 端口未命中：继续尝试 STUN 认领（同机客户端首包场景）
	}

	// 未知来源（外部客户端首包，或本机端口未命中的流量）：
	// STUN 认领（含 MESSAGE-INTEGRITY 验证）。
	s, verdict := t.claim(uaddr, b)
	switch verdict {
	case claimOK:
		conn.WriteTo(b, s.relayTarget)
		t.relayed.Add(1)
		t.claimed.Add(1)
		log.Printf("[mux] 会话 %s 认领客户端 %s（MIC 验证通过）", s.networkID, uaddr)
	case claimBadMIC:
		t.rejected.Add(1)
		if t.rejected.Load() <= 5 {
			log.Printf("[mux] 拒绝来自 %s 的认领：MESSAGE-INTEGRITY 验证失败（疑似伪造）", uaddr)
		}
	case claimNoMIC:
		t.rejected.Add(1)
		if t.rejected.Load() <= 5 {
			log.Printf("[mux] 拒绝来自 %s 的认领：STUN 包缺少 MESSAGE-INTEGRITY", uaddr)
		}
	case claimNoPwd:
		t.dropped.Add(1)
		if t.dropped.Load() <= 3 {
			log.Printf("[mux] 会话无 ice-pwd 无法验证（后端异常？可用 -insecure-claim 退回无验证模式）：%s", uaddr)
		}
	case claimTooManyAddrs:
		t.rejected.Add(1)
		if t.rejected.Load() <= 5 {
			log.Printf("[mux] 拒绝来自 %s 的认领：该会话客户端地址数超上限（疑似刷表攻击）", uaddr)
		}
	default: // claimNotSTUN / claimNoSession
		t.dropped.Add(1)
		if isLocalAddr(uaddr) {
			// 本机来源且不匹配任何会话：多为 BDS 重启后的陈旧流量
			t.unknownBds.Add(1)
			if t.unknownBds.Load() <= 3 {
				log.Printf("[mux] 未知本机来源 %s 的 %d 字节无法认领（STUN用户=%q）已丢弃", uaddr, len(b), stunUsername(b))
			}
		} else if t.dropped.Load() <= 3 {
			log.Printf("[mux] 来自 %s 的 %d 字节无法认领（STUN用户=%q）已丢弃", uaddr, len(b), stunUsername(b))
		}
	}
}
