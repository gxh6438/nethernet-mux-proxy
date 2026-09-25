// testclient：用 pion WebRTC 模拟基岩客户端，端到端验证 nethernet-mux-proxy。
//
//  1. 创建两个 DataChannel（对应基岩的 Reliable/Unreliable）并完整收集 ICE
//  2. POST offer 到代理信令端点（候选地址换成 TEST-NET，模拟公网客户端，
//     强制流量走 mux，杜绝同机直连造成的假阳性）
//  3. SetRemoteDescription(改写后的 answer)，观察 ICE/DTLS/DataChannel 状态
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pion/webrtc/v3"
)

var reCandAddr = regexp.MustCompile(`(?m)^(a=candidate:\S+\s+\d+\s+\S+\s+\d+\s+)(\S+)(\s+\d+.*)$`)

func main() {
	server := flag.String("server", "http://127.0.0.1:19132", "代理信令地址")
	duration := flag.Duration("duration", 25*time.Second, "观察时长")
	flag.Parse()

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatalf("PeerConnection: %v", err)
	}

	tr := true
	fa := false
	var zeroRetrans uint16 = 0
	reliable, err := pc.CreateDataChannel("ReliableDataChannel", &webrtc.DataChannelInit{Ordered: &tr})
	if err != nil {
		log.Fatalf("CreateDataChannel: %v", err)
	}
	unreliable, err := pc.CreateDataChannel("UnreliableDataChannel", &webrtc.DataChannelInit{Ordered: &fa, MaxRetransmits: &zeroRetrans})
	if err != nil {
		log.Fatalf("CreateDataChannel: %v", err)
	}

	reliable.OnOpen(func() {
		log.Printf("=== 成功：ReliableDataChannel 已打开（ICE+DTLS+SCTP 全部经 mux 打通）===")
		if err := reliable.SendText("hello from testclient"); err != nil {
			log.Printf("发送失败: %v", err)
		}
	})
	reliable.OnMessage(func(m webrtc.DataChannelMessage) {
		log.Printf("=== 成功：收到 BDS 回包 %d 字节（回程路径验证）===", len(m.Data))
	})
	unreliable.OnOpen(func() {
		log.Printf("=== 成功：UnreliableDataChannel 已打开 ===")
	})

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		log.Printf("PeerConnection 状态: %s", s)
		if s == webrtc.PeerConnectionStateFailed {
			log.Printf("!!! 连接失败")
		}
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		log.Printf("ICE 状态: %s", s)
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatalf("CreateOffer: %v", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatalf("SetLocalDescription: %v", err)
	}
	waitGather(pc, 5*time.Second)

	// 构造并附加自造身份（P-384 指纹 JWS + 自签 token，cpk=JWK）
	identKey, err := genIdentityKey()
	if err != nil {
		log.Fatalf("生成身份密钥: %v", err)
	}
	identB64, err := buildIdentityAttribute(pc.LocalDescription().SDP, identKey)
	if err != nil {
		log.Fatalf("构造身份: %v", err)
	}
	postedSDP := fakeNAT(attachIdentity(pc.LocalDescription().SDP, identB64))
	networkID := strconv.FormatUint(rand.Uint64(), 10)
	log.Printf("POST %s/v1/join/%s（offer %d 字节，候选已替换为 TEST-NET）", *server, networkID, len(postedSDP))

	resp, err := http.Post(*server+"/v1/join/"+networkID, "application/sdp", strings.NewReader(postedSDP))
	if err != nil {
		log.Fatalf("POST 失败: %v", err)
	}
	ans, _ := io.ReadAll(resp.Body)
	log.Printf("应答: HTTP %d, Content-Type=%q, %d 字节", resp.StatusCode, resp.Header.Get("Content-Type"), len(ans))
	fmt.Println("---- 改写后的 answer ----")
	fmt.Println(string(ans))
	fmt.Println("-------------------------")
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("信令失败（HTTP %d）", resp.StatusCode)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: string(ans),
	}); err != nil {
		log.Fatalf("SetRemoteDescription 失败: %v", err)
	}

	time.Sleep(*duration)
	log.Printf("观察期结束。最终状态: pc=%s ice=%s", pc.ConnectionState(), pc.ICEConnectionState())
}

// waitGather 等待 ICE 候选完整收集（基岩 NetherNet 要求 Full ICE）。
func waitGather(pc *webrtc.PeerConnection, timeout time.Duration) {
	done := make(chan struct{})
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGathererState) {
		if s == webrtc.ICEGathererStateComplete {
			close(done)
		}
	})
	if pc.ICEGatheringState() == webrtc.ICEGatheringStateComplete {
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
		log.Println("（候选收集超时，继续提交 offer）")
	}
}

// fakeNAT 把 offer 中候选地址替换为不可路由的 TEST-NET，
// 模拟真实公网客户端（其主机候选对服务器不可达，流量只能走 mux）。
func fakeNAT(sdp string) string {
	return reCandAddr.ReplaceAllString(sdp, "${1}192.0.2.1${3}")
}
