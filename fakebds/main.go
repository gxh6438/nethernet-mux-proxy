// fakebds：用 pion 实现的"假 BDS"——仅用于沙箱验证 nethernet-mux-proxy。
// 与真 BDS 的唯一差别：跳过 a=identity 验证（真 BDS 要求正版 Xbox token，
// 而身份对代理是透传的，不影响代理路径的验证有效性）。
// 每个 POST /v1/join/{id} 建一个 PeerConnection 并返回完整收集的 answer。
//
// -single-port 模拟真 BDS 的 server-udp-ports=<单端口>：所有 PeerConnection
// 的 ICE UDP socket 被限制到同一个端口，用于复现"端口受限面板服只能进
// 一个玩家"的问题（第二个连接绑定同端口失败）。
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pion/webrtc/v3"
)

func main() {
	singlePort := flag.Int("single-port", 0, "将所有 ICE UDP 绑定到该单端口（模拟 server-udp-ports=<单端口>；0 = 不限制）")
	flag.Parse()

	// -single-port 时构建受限的 API，否则用默认（自由端口）
	var api *webrtc.API
	if *singlePort != 0 {
		se := webrtc.SettingEngine{}
		se.SetEphemeralUDPPortRange(uint16(*singlePort), uint16(*singlePort))
		api = webrtc.NewAPI(webrtc.WithSettingEngine(se))
		log.Printf("[fakebds] 单端口限制模式：所有 ICE UDP 绑定 %d（模拟 server-udp-ports=%d）", *singlePort, *singlePort)
	}

	newPC := func() (*webrtc.PeerConnection, error) {
		if api != nil {
			return api.NewPeerConnection(webrtc.Configuration{})
		}
		return webrtc.NewPeerConnection(webrtc.Configuration{})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"name":"Fake BDS","protocol":2193,"version":"1.26.51","level":"test","players":0,"maxPlayers":10,"gameType":0}`)
	})
	mux.HandleFunc("/v1/join/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/join/")
		body, _ := io.ReadAll(r.Body)

		pc, err := newPC()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			log.Printf("[fakebds] 会话 %s：DataChannel %q 打开", id, dc.Label())
			dc.OnMessage(func(m webrtc.DataChannelMessage) {
				log.Printf("[fakebds] 会话 %s：通道 %q 收到 %d 字节，回显", id, dc.Label(), len(m.Data))
				dc.Send(append([]byte("echo:"), m.Data...))
			})
		})
		pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
			log.Printf("[fakebds] 会话 %s：ICE %s", id, s)
		})
		pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
			log.Printf("[fakebds] 会话 %s：PC %s", id, s)
		})

		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(body)}); err != nil {
			log.Printf("[fakebds] 会话 %s：SetRemoteDescription 失败: %v", id, err)
			http.Error(w, err.Error(), 400)
			return
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		gatherDone := make(chan struct{})
		once := false
		pc.OnICEGatheringStateChange(func(s webrtc.ICEGathererState) {
			if s == webrtc.ICEGathererStateComplete && !once {
				once = true
				close(gatherDone)
			}
		})
		if err := pc.SetLocalDescription(answer); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		select {
		case <-gatherDone:
		case <-time.After(5 * time.Second):
			log.Printf("[fakebds] 会话 %s：候选收集超时", id)
		}
		w.Header().Set("Content-Type", "application/sdp")
		io.WriteString(w, pc.LocalDescription().SDP)
		log.Printf("[fakebds] 会话 %s：已返回 answer", id)
	})

	log.Printf("[fakebds] 假 BDS 信令监听 127.0.0.1:25000")
	log.Fatal(http.ListenAndServe("127.0.0.1:25000", mux))
}
