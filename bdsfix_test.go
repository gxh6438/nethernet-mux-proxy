package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanFixNoChangesNeeded(t *testing.T) {
	src := "server-name=Test\ntransport=nethernet\nserver-port=19132\n#server-udp-ports=\n"
	fix := planServerPropertiesFix(src, 29011, 19131, true)
	if len(fix.changes) != 0 {
		t.Fatalf("配置正确时不应有改动，got %v", fix.changes)
	}
	if fix.content != src {
		t.Fatal("无改动时内容必须保持原样")
	}
}

func TestPlanFixTransport(t *testing.T) {
	// 错误值 → 改为 nethernet
	fix := planServerPropertiesFix("transport=raknet\nserver-port=19132\n", 29011, 0, true)
	if len(fix.changes) != 1 || !strings.Contains(fix.changes[0], "nethernet") {
		t.Fatalf("transport=raknet 应被修正，changes=%v", fix.changes)
	}
	if !strings.Contains(fix.content, "transport=nethernet") || strings.Contains(fix.content, "raknet") {
		t.Fatalf("修正后内容不对：%q", fix.content)
	}

	// 缺失 → 追加
	fix = planServerPropertiesFix("server-port=19132\n", 29011, 0, true)
	if len(fix.changes) != 1 || !strings.Contains(fix.content, "transport=nethernet") {
		t.Fatalf("transport 缺失应被追加，changes=%v content=%q", fix.changes, fix.content)
	}
}

func TestPlanFixUDPPortsActive(t *testing.T) {
	// 真实事故场景：面板模板固定单端口
	src := "transport=nethernet\nserver-port=19132\nserver-udp-ports=19132\n"
	fix := planServerPropertiesFix(src, 29011, 0, true)
	if len(fix.changes) != 1 {
		t.Fatalf("server-udp-ports=19132 应被注释，changes=%v", fix.changes)
	}
	if !strings.Contains(fix.changes[0], "重连失败") {
		t.Fatalf("改动说明应说明后果：%q", fix.changes[0])
	}
	for _, line := range strings.Split(fix.content, "\n") {
		if strings.HasPrefix(line, "server-udp-ports") {
			t.Fatalf("生效的 server-udp-ports 必须被注释：%q", fix.content)
		}
	}

	// 已注释 → 不动
	fix = planServerPropertiesFix("transport=nethernet\nserver-port=19132\n#server-udp-ports=19132\n", 29011, 0, true)
	if len(fix.changes) != 0 {
		t.Fatalf("已注释的 server-udp-ports 不应改动，changes=%v", fix.changes)
	}
}

func TestPlanFixServerPortConflict(t *testing.T) {
	// 同机 + 端口相同 → 换 BDS 端口
	src := "transport=nethernet\nserver-port=19132\n"
	fix := planServerPropertiesFix(src, 19132, 19131, true)
	if fix.newBDSPort != 19131 {
		t.Fatalf("冲突应改用备选端口 19131，got %d", fix.newBDSPort)
	}
	if !strings.Contains(fix.content, "server-port=19131") {
		t.Fatalf("内容应包含新端口：%q", fix.content)
	}

	// 不同机 → 相同端口也不冲突
	fix = planServerPropertiesFix(src, 19132, 19131, false)
	if fix.newBDSPort != 0 || len(fix.changes) != 0 {
		t.Fatalf("不同机时相同端口不算冲突，newBDSPort=%d changes=%v", fix.newBDSPort, fix.changes)
	}

	// server-port 行被注释（生效值为默认 19132）且冲突 → 追加生效行
	fix = planServerPropertiesFix("transport=nethernet\n#server-port=19132\n", 19132, 19131, true)
	if fix.newBDSPort != 19131 || !strings.Contains(fix.content, "\nserver-port=19131") {
		t.Fatalf("默认值冲突应追加生效行，newBDSPort=%d content=%q", fix.newBDSPort, fix.content)
	}

	// 无备选端口 → 跳过该项
	fix = planServerPropertiesFix(src, 19132, 0, true)
	if fix.newBDSPort != 0 {
		t.Fatalf("无备选端口时不应改动 server-port，got %d", fix.newBDSPort)
	}
}

func TestPlanFixPreservesEOLAndComments(t *testing.T) {
	src := "# 我的服务器配置\r\ntransport=raknet\r\nserver-port=19132\r\nlevel-name=world\r\n"
	fix := planServerPropertiesFix(src, 29011, 0, true)
	if !strings.Contains(fix.content, "\r\n") {
		t.Fatalf("CRLF 行尾必须保留：%q", fix.content)
	}
	if !strings.Contains(fix.content, "# 我的服务器配置") || !strings.Contains(fix.content, "level-name=world") {
		t.Fatalf("无关行必须原样保留：%q", fix.content)
	}
	if !strings.HasSuffix(fix.content, "\r\n") {
		t.Fatalf("结尾换行必须保留：%q", fix.content)
	}
}

func TestReadServerPort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.properties")

	// 生效行
	os.WriteFile(p, []byte("transport=nethernet\nserver-port=19131\n"), 0o644)
	if n := readServerPort(p); n != 19131 {
		t.Fatalf("应读到 19131，got %d", n)
	}
	// 只有注释行 → BDS 默认 19132
	os.WriteFile(p, []byte("#server-port=19131\n"), 0o644)
	if n := readServerPort(p); n != 19132 {
		t.Fatalf("无生效行应返回默认 19132，got %d", n)
	}
	// 文件不存在 → 0
	if n := readServerPort(filepath.Join(dir, "none.properties")); n != 0 {
		t.Fatalf("文件不存在应返回 0，got %d", n)
	}
}

func TestSaveServerPropertiesFixedBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.properties")
	orig := []byte("transport=raknet\nserver-port=19132\n")
	os.WriteFile(p, orig, 0o644)

	fix := planServerPropertiesFix(string(orig), 29011, 0, true)
	if err := saveServerPropertiesFixed(p, orig, fix.content); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "transport=nethernet") {
		t.Fatalf("文件应已修正：%q", got)
	}
	matches, _ := filepath.Glob(p + ".bak-*")
	if len(matches) != 1 {
		t.Fatalf("应恰好生成一个备份文件，got %v", matches)
	}
	bak, _ := os.ReadFile(matches[0])
	if string(bak) != string(orig) {
		t.Fatalf("备份必须是修正前的原始内容：%q", bak)
	}
}
