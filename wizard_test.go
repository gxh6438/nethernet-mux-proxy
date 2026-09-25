package main

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestFreeTCPPort(t *testing.T) {
	// 占住一个端口，freeTCPPort 应避开它（走系统随机分配）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	got := freeTCPPort(int(port))
	if got == port {
		t.Fatalf("freeTCPPort 返回了被占用端口 %d", port)
	}
	if got < 1 || got > 65535 {
		t.Fatalf("非法端口 %d", got)
	}

	// 空闲候选应直接命中
	if got := freeTCPPort(19132, 19130); got != 19132 && got != 19130 {
		t.Fatalf("候选全空闲时应返回其中之一，得到 %d", got)
	}
}

func TestHostIsLocal(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1", ""} {
		if !hostIsLocal(h) {
			t.Fatalf("%q 应判为本机", h)
		}
	}
	if hostIsLocal("203.0.113.1") {
		t.Fatal("外部 IP 不应判为本机")
	}
}

func TestMustPort(t *testing.T) {
	if got := mustPort("127.0.0.1:19132"); got != 19132 {
		t.Fatalf("got %d", got)
	}
	if got := mustPort(":19130"); got != 19130 {
		t.Fatalf("got %d", got)
	}
	if got := mustPort("not-addr"); got != 0 {
		t.Fatalf("非法地址应返回 0，got %d", got)
	}
}

func TestIsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	if _, err := net.Listen("tcp", addr); err == nil {
		t.Fatal("重复监听应失败")
	} else if !isAddrInUse(err) {
		t.Fatalf("应识别为端口占用: %v", err)
	}
	if isAddrInUse(errors.New("别的错误")) {
		t.Fatal("误判普通错误为端口占用")
	}
	if isAddrInUse(fmt.Errorf("wrapped: %w", errors.New("address already in use"))) {
		// 字符串匹配路径也应命中（跨平台兜底）
		return
	}
	t.Fatal("字符串匹配路径未命中 address already in use")
}
