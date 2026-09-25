package main

// 友好报错：启动类错误不再"闪退"——打印具体原因与解决办法，
// Windows 下等待用户按回车后再退出（双击运行时窗口不会一闪而过）。

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// fatal 打印错误与提示后退出（Windows 下先等回车）。
func fatal(format string, args ...any) {
	fmt.Println()
	fmt.Printf("［错误］"+format+"\n", args...)
	waitExit()
	os.Exit(1)
}

// fatalBind 端口监听失败的专项友好报错：翻译系统错误，
// 按可能性排序给出解决办法。
func fatalBind(proto, addr string, err error) {
	port := hostPortOnly(addr)
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("  ［启动失败］%s 端口 %s 没法监听\n", proto, addr)
	fmt.Printf("  系统报错：%v\n", err)
	fmt.Println("============================================================")
	fmt.Println()
	if isAddrInUse(err) {
		fmt.Println("  常见原因和解决办法（按可能性排序）：")
		fmt.Println()
		fmt.Printf("  1. 端口 %s 被其他程序占用\n", port)
		fmt.Println("     ▸ 最简单：删掉配置文件 proxy.json 重新运行本程序，")
		fmt.Println("       向导会自动挑一个没被占用的端口")
		if proto == "TCP" {
			fmt.Println("     ▸ 若是 BDS 服务端占的（它的 server-port 默认 19132）：")
			fmt.Println("       改 BDS 的 server.properties 为 server-port=19131，")
			fmt.Println("       再重新跑向导，第 2 步填 127.0.0.1:19131")
		}
		fmt.Println("     ▸ 查看是谁占的：")
		fmt.Printf("       Windows: netstat -ano | findstr :%s\n", port)
		fmt.Println("       （输出最后一列是进程号 PID，到任务管理器「详细信息」页")
		fmt.Printf("         按 PID 找到程序后关闭；Linux: ss -lntup | grep %s）\n", port)
		fmt.Println()
		fmt.Println("  2. 已经开着一个代理了")
		fmt.Println("     ▸ 关掉之前的代理窗口再启动")
	} else {
		fmt.Println("  排查建议：")
		fmt.Println()
		fmt.Println("  1. Linux 下使用 1024 以下的端口需要管理员权限，")
		fmt.Println("     建议改用 19132 这类大号端口")
		fmt.Println("  2. 检查地址写法是否正确，形如 :19132 或 127.0.0.1:19132")
		fmt.Println("  3. 删掉 proxy.json 重新运行向导")
	}
	waitExit()
	os.Exit(1)
}

// isAddrInUse 判断是否"端口已被占用"（兼容 Linux 与 Windows 的错误形式；
// Windows 上 WSAEADDRINUSE 与 syscall.EADDRINUSE 同为 10048，errors.Is 可命中）。
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "Only one usage of each socket address")
}
