//go:build windows

package main

// Windows 控制台兼容：UTF-8 输出代码页 + 启用 VT100 转义序列，
// 保证中文提示与横线样式在 cmd/PowerShell 下正常显示。
// 注：golang.org/x/sys 未封装 SetConsoleOutputCP，直接经 kernel32 调用。
import (
	"bufio"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

var procSetConsoleOutputCP = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleOutputCP")

func platformInit() {
	procSetConsoleOutputCP.Call(uintptr(65001)) // UTF-8 代码页
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil {
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}

// waitExit Windows：等用户按回车再退出，避免双击运行报错时窗口一闪而过。
func waitExit() {
	fmt.Print("\n按「回车键」退出...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
