package main

// 按 Mojang NetherNet 文档与 df-mc/go-nethernet identity.go 的格式构造 a=identity：
//   identityData = base64( {"assertion": "<JSON字符串: {fingerprints, token}>",
//                            "idp": {"domain": "...", "protocol": "default"}} )
//   fingerprints = detached ES384 JWS，负载为 offer 中 a=fingerprint 行的规范 JSON
//   token        = JWT，cpk claim 为本测试密钥的 JWK（自签，供 online-mode=false 的 BDS 结构校验）

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reFingerprint = regexp.MustCompile(`(?m)^a=fingerprint:(\S+)[ \t]+(\S+)`)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// es384Sign 生成 JOSE ES384 签名（P-1363：r||s 各 48 字节）。
func es384Sign(priv *ecdsa.PrivateKey, signingInput string) ([]byte, error) {
	h := sha512.Sum384([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return sig, nil
}

func genIdentityKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// buildIdentityAttribute 返回 base64 的 a=identity 值。
func buildIdentityAttribute(sdp string, priv *ecdsa.PrivateKey) (string, error) {
	// 1. 规范指纹负载（与 go-nethernet generateFingerprints 字节一致，无空格）
	var parts []string
	for _, m := range reFingerprint.FindAllStringSubmatch(sdp, -1) {
		parts = append(parts, fmt.Sprintf(`{"algorithm":%s,"digest":%s}`,
			strconv.Quote(m[1]), strconv.Quote(m[2])))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("offer 中无 a=fingerprint")
	}
	payload := `{"fingerprint":[` + strings.Join(parts, ",") + `]}`

	// 2. detached ES384 JWS：b64(header)..b64(sig)
	header := `{"alg":"ES384"}`
	fpSig, err := es384Sign(priv, b64u([]byte(header))+"."+b64u([]byte(payload)))
	if err != nil {
		return "", err
	}
	fingerprints := b64u([]byte(header)) + ".." + b64u(fpSig)

	// 3. 自签 token，cpk = P-384 公钥 JWK（26.40+ 客户端格式）
	pub := priv.Public().(*ecdsa.PublicKey)
	x := make([]byte, 48)
	y := make([]byte, 48)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	claims, err := json.Marshal(map[string]any{
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"cpk": jwk{Kty: "EC", Crv: "P-384", X: b64u(x), Y: b64u(y)},
	})
	if err != nil {
		return "", err
	}
	tokSig, err := es384Sign(priv, b64u([]byte(header))+"."+b64u(claims))
	if err != nil {
		return "", err
	}
	token := b64u([]byte(header)) + "." + b64u(claims) + "." + b64u(tokSig)

	// 4. assertion 为双重编码的 JSON 字符串
	assertion, err := json.Marshal(map[string]string{
		"fingerprints": fingerprints,
		"token":        token,
	})
	if err != nil {
		return "", err
	}

	// 5. 外层信封
	env, err := json.Marshal(map[string]any{
		"assertion": string(assertion),
		"idp": map[string]string{
			"domain":   "https://authorization.franchise.minecraft-services.net",
			"protocol": "default",
		},
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(env), nil
}

// attachIdentity 把 a=identity 插入首个 m= 行之前（会话级），沿用原 SDP 行尾风格。
func attachIdentity(sdp, identityB64 string) string {
	eol := "\n"
	if strings.Contains(sdp, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(sdp, "\n")
	idLine := "a=identity:" + identityB64
	out := make([]string, 0, len(lines)+1)
	inserted := false
	for _, l := range lines {
		if !inserted && strings.HasPrefix(l, "m=") {
			out = append(out, idLine)
			inserted = true
		}
		if strings.HasPrefix(l, "a=identity:") {
			continue // 幂等
		}
		out = append(out, l)
	}
	if !inserted {
		out = append(out, idLine)
	}
	return strings.Join(out, eol)
}
