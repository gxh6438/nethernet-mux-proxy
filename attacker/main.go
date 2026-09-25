// attacker：mux 安全模型的攻击模拟器（仅用于沙箱验证，请勿用于真实环境）。
//
// 模拟三类攻击 + 一个对照组，全部通过真实 UDP 路径打到 mux：
//
//	A1. 知道目标会话 ufrag（STUN USERNAME 明文中可见）+ 猜测的密码 → 伪造 MIC
//	A2. 知道 ufrag 但不带 MESSAGE-INTEGRITY
//	A3. 非 STUN 垃圾字节
//	C.  对照组：自己的 ufrag + 信令应答里的 ice-pwd → 合法检查
//
// 预期：A1~A3 无任何响应（mux 拒绝转发，后端不可见）；
// C 收到 STUN Binding Success（证明"无响应"是安全拒绝而非网络故障）。
//
// USERNAME 格式说明：pion/ice 的 answer 端要求请求 USERNAME 精确等于
// "serverUfrag:clientUfrag"（RFC 8445 remote:local），对照组按此构造；
// 攻击组只需包含受害者的 ufrag 即可命中 mux 的会话定位，再交给 MIC 拦截。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun"
	"github.com/pion/webrtc/v3"
)

var (
	reUfrag = regexp.MustCompile(`(?m)^a=ice-ufrag:\s*(\S+)`)
	rePwd   = regexp.MustCompile(`(?m)^a=ice-pwd:\s*(\S+)`)
)

func firstMatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// buildCheck 构造 ICE connectivity check（STUN binding request）。
// withMIC=false 时不带 MESSAGE-INTEGRITY（攻击 A2）。
func buildCheck(username, pwd string, withMIC bool) (*stun.Message, []byte) {
	var tie [8]byte
	binary.BigEndian.PutUint64(tie[:], rand.Uint64())
	m := stun.MustBuild(
		stun.TransactionID,
		stun.BindingRequest,
		stun.Username(username),
		stun.RawAttribute{Type: stun.AttrPriority, Value: []byte{0, 0, 0x1e, 0xff}},
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: tie[:]},
	)
	if withMIC {
		if err := stun.NewShortTermIntegrity(pwd).AddTo(m); err != nil {
			log.Fatalf("构造 MESSAGE-INTEGRITY: %v", err)
		}
	}
	if err := stun.Fingerprint.AddTo(m); err != nil {
		log.Fatalf("构造 FINGERPRINT: %v", err)
	}
	return m, m.Raw
}

// drain 在时长 d 内收包，返回 (总包数, 其中与 txn 匹配的 Binding Success 数)。
func drain(sock net.PacketConn, d time.Duration, txn [stun.TransactionIDSize]byte) (int, int) {
	total, matched := 0, 0
	deadline := time.Now().Add(d)
	buf := make([]byte, 1500)
	for {
		_ = sock.SetReadDeadline(deadline)
		n, _, err := sock.ReadFrom(buf)
		if err != nil {
			return total, matched // 超时或错误：结束观察窗口
		}
		total++
		if !stun.IsMessage(buf[:n]) {
			continue
		}
		m := &stun.Message{Raw: buf[:n]}
		if err := m.Decode(); err != nil {
			continue
		}
		if m.Type == stun.BindingSuccess && m.TransactionID == txn {
			matched++
		}
	}
}

func waitGather(pc *webrtc.PeerConnection, timeout time.Duration) {
	done := make(chan struct{})
	once := false
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGathererState) {
		if s == webrtc.ICEGathererStateComplete && !once {
			once = true
			close(done)
		}
	})
	if pc.ICEGatheringState() == webrtc.ICEGatheringStateComplete {
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	server := flag.String("server", "http://127.0.0.1:19132", "代理信令地址")
	muxAddr := flag.String("mux", "127.0.0.1:19133", "mux UDP 地址")
	victim := flag.String("victim-ufrag", "", "受害会话的 ufrag（缺省 = 攻击自己的会话）")
	wait := flag.Duration("wait", 2*time.Second, "每次攻击后的观察窗口")
	flag.Parse()

	// --- 信令：注册自己的会话，拿到改写后 answer 的 serverUfrag 与 ice-pwd ---
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatalf("PeerConnection: %v", err)
	}
	// 需要至少一条 DataChannel，否则 offer 无 m=application 段（无 ice-ufrag）
	if _, err := pc.CreateDataChannel("attack", nil); err != nil {
		log.Fatalf("CreateDataChannel: %v", err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatalf("CreateOffer: %v", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatalf("SetLocalDescription: %v", err)
	}
	waitGather(pc, 5*time.Second)
	myUfrag := firstMatch(reUfrag, pc.LocalDescription().SDP)

	networkID := strconv.FormatUint(rand.Uint64(), 10)
	resp, err := http.Post(*server+"/v1/join/"+networkID, "application/sdp",
		strings.NewReader(pc.LocalDescription().SDP))
	if err != nil {
		log.Fatalf("信令失败: %v", err)
	}
	ans, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("信令 HTTP %d: %s", resp.StatusCode, string(ans))
	}
	srvUfrag := firstMatch(reUfrag, string(ans))
	icePwd := firstMatch(rePwd, string(ans))
	log.Printf("攻击者会话已注册：networkID=%s serverUfrag=%s icePwd=%.4s...（answer %d 字节）",
		networkID, srvUfrag, icePwd, len(ans))

	target := srvUfrag
	if *victim != "" {
		target = *victim
		log.Printf("攻击目标：受害会话 ufrag=%s", target)
	}

	sock, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Fatalf("UDP socket: %v", err)
	}
	defer sock.Close()
	muxUDP, err := net.ResolveUDPAddr("udp", *muxAddr)
	if err != nil {
		log.Fatalf("mux 地址: %v", err)
	}

	failed := 0
	expectSilence := func(name string, pkt []byte, count int) {
		for i := 0; i < count; i++ {
			if _, err := sock.WriteTo(pkt, muxUDP); err != nil {
				log.Fatalf("发送失败: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		total, _ := drain(sock, *wait, [stun.TransactionIDSize]byte{})
		if total == 0 {
			log.Printf("[PASS] %s：观察窗口内无任何响应（已被 mux 拒绝）", name)
		} else {
			failed++
			log.Printf("[FAIL] %s：收到 %d 个包（本应被拒绝！）", name, total)
		}
	}

	// A1：知道 ufrag + 猜密码（伪造 MESSAGE-INTEGRITY）
	_, raw := buildCheck(target+":rogue", "attacker-guessed-pwd", true)
	expectSilence("A1 伪造 MESSAGE-INTEGRITY（知道 ufrag + 猜密码）", raw, 5)

	// A2：知道 ufrag 但不带 MESSAGE-INTEGRITY
	_, raw = buildCheck(target+":rogue", "", false)
	expectSilence("A2 无 MESSAGE-INTEGRITY", raw, 3)

	// A3：非 STUN 垃圾
	expectSilence("A3 非 STUN 垃圾字节", []byte("NOT-STUN-AT-ALL"+strings.Repeat("X", 32)), 3)

	// C：对照组——自己的 ufrag + 信令应答中的 ice-pwd（合法检查）
	msg, raw := buildCheck(srvUfrag+":"+myUfrag, icePwd, true)
	if _, err := sock.WriteTo(raw, muxUDP); err != nil {
		log.Fatalf("发送失败: %v", err)
	}
	total, matched := drain(sock, *wait, msg.TransactionID)
	if matched > 0 {
		log.Printf("[PASS] C 对照组：收到 Binding Success（共 %d 包，事务匹配）——合法路径畅通", total)
	} else {
		failed++
		log.Printf("[FAIL] C 对照组：未收到事务匹配的 Binding Success（共 %d 包）", total)
	}

	fmt.Println()
	if failed > 0 {
		fmt.Printf("===== 攻击模拟结果：%d 项失败 =====\n", failed)
		os.Exit(1)
	}
	fmt.Println("===== 攻击模拟结果：全部通过（伪造被拒 / 合法放行）=====")
}
