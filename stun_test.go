package main

import (
	"net"
	"testing"

	"github.com/pion/stun"
)

// buildSTUNWithMIC 构造一个带 USERNAME + MESSAGE-INTEGRITY 的 binding request
// （模拟 ICE connectivity check，key = 服务端 ice-pwd）。
func buildSTUNWithMIC(username, pwd string) []byte {
	m := stun.MustBuild(
		stun.TransactionID,
		stun.BindingRequest,
		stun.Username(username),
	)
	if err := stun.NewShortTermIntegrity(pwd).AddTo(m); err != nil {
		panic(err)
	}
	return m.Raw
}

func TestStunUsername(t *testing.T) {
	b := buildSTUNWithMIC("srvfrag:clifrag", "secret")
	if got := stunUsername(b); got != "srvfrag:clifrag" {
		t.Fatalf("USERNAME = %q, want %q", got, "srvfrag:clifrag")
	}
	if got := stunUsername([]byte("garbage-not-stun")); got != "" {
		t.Fatalf("非 STUN 包应返回空串，得到 %q", got)
	}
	if got := stunUsername(b[:10]); got != "" {
		t.Fatalf("截断包应返回空串，得到 %q", got)
	}
}

func TestStunVerify(t *testing.T) {
	const pwd = "test-ice-pwd"
	b := buildSTUNWithMIC("srv:cli", pwd)

	// 正确密码 → 验证通过
	if v := stunVerify(b, pwd); v != stunVerified {
		t.Fatalf("正确密码应通过，verdict=%d", v)
	}

	// 验证过程不得修改原始字节（先留副本，verify 后比对）
	orig := append([]byte(nil), b...)
	if v := stunVerify(b, pwd); v != stunVerified {
		t.Fatalf("二次验证 verdict=%d", v)
	}
	if string(b) != string(orig) {
		t.Fatal("stunVerify 修改了原始包内容")
	}

	// 错误密码 → 疑似伪造
	if v := stunVerify(b, "wrong"); v != stunBadIntegrity {
		t.Fatalf("错误密码应判伪造，verdict=%d", v)
	}

	// 篡改一字节 → 验证失败
	tampered := append([]byte(nil), b...)
	tampered[len(tampered)-1] ^= 0xFF
	if v := stunVerify(tampered, pwd); v != stunBadIntegrity {
		t.Fatalf("篡改包应判伪造，verdict=%d", v)
	}

	// 无 MESSAGE-INTEGRITY → 拒绝
	noMIC := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Username("srv:cli")).Raw
	if v := stunVerify(noMIC, pwd); v != stunNoMIC {
		t.Fatalf("无 MIC 包 verdict=%d, want %d", v, stunNoMIC)
	}

	// 非 STUN → notSTUN
	if v := stunVerify([]byte("hello world"), pwd); v != stunNotSTUN {
		t.Fatalf("非 STUN verdict=%d", v)
	}
}

func TestClaimRequiresMIC(t *testing.T) {
	table := newSessionTable(0, 16, 4, false)
	bds := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	if err := table.register("netid1", "clifrag", "srvfrag", "secretpwd",
		[]*net.UDPAddr{bds}); err != nil {
		t.Fatal(err)
	}

	attacker := &net.UDPAddr{IP: net.ParseIP("203.0.113.66"), Port: 5555}

	// 知道 ufrag 但无 MIC → 拒绝（旧版的抢占攻击，现已修复）
	noMIC := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Username("srvfrag:clifrag")).Raw
	if _, v := table.claim(attacker, noMIC); v != claimNoMIC {
		t.Fatalf("无 MIC 认领 verdict=%d, want claimNoMIC", v)
	}

	// 知道 ufrag + 伪造 MIC（错误密码）→ 拒绝
	bad := buildSTUNWithMIC("srvfrag:clifrag", "guessed-pwd")
	if _, v := table.claim(attacker, bad); v != claimBadMIC {
		t.Fatalf("伪造 MIC 认领 verdict=%d, want claimBadMIC", v)
	}

	// 正确客户端（持有 ice-pwd）→ 认领成功
	good := buildSTUNWithMIC("srvfrag:clifrag", "secretpwd")
	s, v := table.claim(attacker, good)
	if v != claimOK || s == nil {
		t.Fatalf("合法认领 verdict=%d", v)
	}

	// 认领后：热路径 byClient 命中
	if table.cur.Load().byClient[attacker.String()] == nil {
		t.Fatal("认领后 byClient 未学习到地址")
	}

	// 攻击者无法再用合法客户端的身份触发地址学习超限之外的影响：
	// 新地址需要再次 MIC 验证
	attacker2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.66"), Port: 6666}
	if _, v := table.claim(attacker2, noMIC); v != claimNoMIC {
		t.Fatalf("第二个地址无 MIC 认领 verdict=%d", v)
	}
	if _, v := table.claim(attacker2, good); v != claimOK {
		t.Fatalf("第二个地址合法认领 verdict=%d", v)
	}
}

func TestMaxSessionsAndAddrs(t *testing.T) {
	table := newSessionTable(0, 1, 1, false)
	bds := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	if err := table.register("s1", "c1", "v1", "p1", []*net.UDPAddr{bds}); err != nil {
		t.Fatal(err)
	}
	if err := table.register("s2", "c2", "v2", "p2", []*net.UDPAddr{bds}); err != errTooManySessions {
		t.Fatalf("超过会话上限应报错，得到 %v", err)
	}

	// 每会话地址数上限 = 1：第二个地址认领被拒
	a1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	a2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222}
	g1 := buildSTUNWithMIC("v1:c1", "p1")
	g2 := buildSTUNWithMIC("v1:c1", "p1")
	if _, v := table.claim(a1, g1); v != claimOK {
		t.Fatalf("首个地址认领 verdict=%d", v)
	}
	if _, v := table.claim(a2, g2); v != claimTooManyAddrs {
		t.Fatalf("超限地址认领 verdict=%d, want claimTooManyAddrs", v)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/proxy.json"
	c := &config{Listen: ":19132", BDS: "127.0.0.1:19132", Mux: ":19133",
		AdvertiseIP: "203.0.113.10", AdvertisePort: 19133, Idle: "5m"}
	if err := saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if *got != *c {
		t.Fatalf("配置往返不一致: %+v vs %+v", got, c)
	}
	// 不存在的文件 → (nil, nil)
	if c, err := loadConfig(dir + "/none.json"); c != nil || err != nil {
		t.Fatalf("缺失文件应返回 nil,nil，得到 %v,%v", c, err)
	}
}
