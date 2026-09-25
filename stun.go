package main

import (
	"encoding/binary"

	"github.com/pion/stun"
)

// STUN 处理分两级：
//
//  1. stunUsername：零依赖的快速预筛（每会话仅对"未知来源首包"调用），
//     提取 binding request 的 USERNAME（"serverUfrag:clientUfrag"）。
//  2. stunVerify：用 pion/stun 做 RFC 5389/8445 短期凭证 MESSAGE-INTEGRITY
//     验证（HMAC-SHA1，key = answer 的 a=ice-pwd）。认领必须通过验证，
//     杜绝"知道 ufrag 即可抢占会话"的伪造攻击。
//
// 注：pion 的 MessageIntegrity.Check 会临时改写消息头 length 字段再恢复，
// 原始字节最终保持不变；此处仍在副本上验证，转发始终使用原 buffer，双保险。

const (
	stunMagicCookie = 0x2112A442
	stunHeaderLen   = 20
	attrUsername    = 0x0006
)

// stunVerdict STUN 验证结果。
type stunVerdict int

const (
	stunNotSTUN      stunVerdict = iota // 非 STUN 包 / 解析失败
	stunNoMIC                           // STUN 包但无 MESSAGE-INTEGRITY 属性
	stunBadIntegrity                    // MESSAGE-INTEGRITY 不匹配（疑似伪造）
	stunVerified                        // 验证通过
)

// stunUsername 返回 USERNAME 值（形如 "serverUfrag:clientUfrag"）；
// 非 STUN 包、无 USERNAME 或属性越界时返回空串。
func stunUsername(b []byte) string {
	if len(b) < stunHeaderLen {
		return ""
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return ""
	}
	mlen := int(binary.BigEndian.Uint16(b[2:4]))
	if stunHeaderLen+mlen > len(b) {
		mlen = len(b) - stunHeaderLen // 容忍长度不精确的实现对齐差异
	}
	off := stunHeaderLen
	end := stunHeaderLen + mlen
	for off+4 <= end {
		at := int(binary.BigEndian.Uint16(b[off : off+2]))
		al := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+al > end {
			break
		}
		if at == attrUsername && al > 0 {
			return string(b[off+4 : off+4+al])
		}
		off += 4 + (al+3)&^3 // 属性按 4 字节对齐
	}
	return ""
}

// stunVerify 完整验证 STUN 消息完整性。icePwd 为对端（BDS answer）的 a=ice-pwd。
func stunVerify(b []byte, icePwd string) stunVerdict {
	if !stun.IsMessage(b) {
		return stunNotSTUN
	}
	// pion Decode/Check 均不改变包内容（Check 临时改 length 后恢复），
	// 复制一份仅为防御第三方库回归，成本仅发生在每地址首包。
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if err := m.Decode(); err != nil {
		return stunNotSTUN
	}
	if _, err := m.Get(stun.AttrMessageIntegrity); err != nil {
		return stunNoMIC
	}
	if err := stun.NewShortTermIntegrity(icePwd).Check(m); err != nil {
		return stunBadIntegrity
	}
	return stunVerified
}
