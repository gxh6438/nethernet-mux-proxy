package main

// server.properties 自动检查与修正。
//
// 背景：BDS 的三个配置项直接决定代理能否正常工作，而它们恰恰是
// 面板模板最容易配错的地方（真实案例：server-udp-ports 被固定为
// 单端口 → 玩家重连必失败，客户端报 Door 错误且 BDS 无任何日志）。
//
// 	1. transport 必须是 nethernet（RakNet 模式下本代理无意义）
// 	2. server-udp-ports 必须保持注释（固定单端口 = 重连失败/第二玩家进不来）
// 	3. server-port 不能和代理的对外 TCP 端口相同（同机部署时端口冲突）
//
// 使用方式：把本程序放到 BDS 目录（server.properties 同级）运行，
// 向导结尾自动检查并询问是否修正；命令行模式加 -fix-bds 直接修正。
// 修正前自动备份原文件，绝不静默改动。

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// findServerProperties 找 BDS 配置文件：先查工作目录，再查程序所在目录
// （Windows 双击运行时两者相同；从别处启动终端时各不相同）。
func findServerProperties() string {
	dirs := []string{"."}
	if ex, err := os.Executable(); err == nil {
		if d := filepath.Dir(ex); d != "." {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		p := filepath.Join(d, "server.properties")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// readServerPort 读取生效的 server-port（跳过注释行；文件不存在返回 0，
// 文件存在但未配置返回 BDS 默认 19132）。供向导预填 BDS 地址。
func readServerPort(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := splitPropLine(line); ok && k == "server-port" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 19132
}

// splitPropLine 解析一行 "key=value"（容忍 BOM/空白/注释），非有效属性行返回 ok=false。
func splitPropLine(line string) (key, value string, ok bool) {
	line = strings.TrimSuffix(line, "\r")
	line = strings.TrimPrefix(line, "\uFEFF") // UTF-8 BOM
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!") {
		return "", "", false
	}
	k, v, has := strings.Cut(t, "=")
	if !has {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// spFix 一份修正计划（对文件内容的纯函数计算结果）。
type spFix struct {
	changes    []string // 人类可读的改动说明（空 = 无需改动）
	content    string   // 修正后的完整文件内容；无改动时与原文相同
	newBDSPort int      // server-port 被改时的新值（0 = 未改）
}

// planServerPropertiesFix 检查并计算修正（纯函数，不碰文件系统）。
// listenPort 为代理对外 TCP 端口；altServerPort 为冲突时预备的新端口
// （0 = 无法提供备选，跳过该项）；bdsLocal 表示 BDS 与代理同机
// （不同机时 server-port 与代理端口相同也不冲突）。
func planServerPropertiesFix(content string, listenPort, altServerPort int, bdsLocal bool) spFix {
	fix := spFix{content: content}
	if content == "" {
		return fix
	}

	eol := "\n"
	if strings.Contains(content, "\r\n") {
		eol = "\r\n"
	}
	hadTrailingNL := strings.HasSuffix(content, "\n")
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(content, "\r\n", "\n"), "\n"), "\n")

	var (
		hasTransport  bool
		transportOK   bool
		oldTransport  string
		udpPortIdx    = -1
		udpPortOld    string
		serverPortIdx = -1
		serverPortVal = 19132 // BDS 默认
		serverPortAct bool    // 是否有生效的 server-port 行
	)
	for i, line := range lines {
		k, v, ok := splitPropLine(line)
		if !ok {
			continue
		}
		switch k {
		case "transport":
			hasTransport = true
			oldTransport = v
			if v == "nethernet" {
				transportOK = true
			} else {
				lines[i] = "transport=nethernet"
			}
		case "server-udp-ports":
			udpPortIdx = i
			udpPortOld = v
		case "server-port":
			serverPortIdx = i
			serverPortAct = true
			if n, err := strconv.Atoi(v); err == nil {
				serverPortVal = n
			}
		}
	}

	// 1) transport
	switch {
	case !hasTransport:
		lines = append(lines, "transport=nethernet")
		fix.changes = append(fix.changes, "已添加 transport=nethernet（原文件缺失，默认 RakNet 无法使用本代理）")
	case !transportOK:
		fix.changes = append(fix.changes, fmt.Sprintf("transport 已从 %q 改为 nethernet", oldTransport))
	}

	// 2) server-udp-ports：生效即注释（值无论是多少都一样有害）
	if udpPortIdx >= 0 {
		lines[udpPortIdx] = "#server-udp-ports="
		if udpPortOld == "" {
			fix.changes = append(fix.changes, "server-udp-ports 已注释（空值配置无意义）")
		} else {
			fix.changes = append(fix.changes,
				fmt.Sprintf("server-udp-ports=%s 已注释（固定单端口会导致玩家重连失败、第二个玩家进不来）", udpPortOld))
		}
	}

	// 3) server-port 与代理监听端口同机冲突
	if bdsLocal && listenPort != 0 && serverPortVal == listenPort && altServerPort != 0 && altServerPort != listenPort {
		newLine := "server-port=" + strconv.Itoa(altServerPort)
		if serverPortIdx >= 0 && serverPortAct {
			lines[serverPortIdx] = newLine
		} else {
			lines = append(lines, newLine) // 原文件无生效行（默认值冲突）→ 追加
		}
		fix.newBDSPort = altServerPort
		fix.changes = append(fix.changes,
			fmt.Sprintf("server-port %d 与代理玩家端口冲突 → 已改为 %d（同机部署两者不能相同）", serverPortVal, altServerPort))
	}

	if len(fix.changes) == 0 {
		return fix
	}
	out := strings.Join(lines, eol)
	if hadTrailingNL {
		out += eol
	}
	fix.content = out
	return fix
}

// saveServerPropertiesFixed 备份原文件后写入修正内容（时间戳备份，不覆盖历史备份）。
func saveServerPropertiesFixed(path string, orig []byte, newContent string) error {
	bak := path + ".bak-" + time.Now().Format("20060102-150405")
	if err := os.WriteFile(bak, orig, 0o644); err != nil {
		return fmt.Errorf("备份原文件失败：%w", err)
	}
	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("写入修正失败：%w", err)
	}
	return nil
}
