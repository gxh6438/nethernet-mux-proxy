package main

// 交互式设置向导：面向零基础用户。直接运行 ./proxy（无参数且无 proxy.json）
// 即可进入，逐步提示输入，最终生成配置并可保存。

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func runWizard(savePath string) *config {
	w := bufio.NewReader(os.Stdin)
	fmt.Println("==========================================================")
	fmt.Println("  NetherNet Mux Proxy - 单端口复用前置代理（首次设置）")
	fmt.Println("  适用：Minecraft BDS 1.26.50+（transport=nethernet）")
	fmt.Println("  作用：对外只需 1 个 TCP + 1 个 UDP 端口，玩家数无上限")
	fmt.Println("----------------------------------------------------------")
	fmt.Println("  提示：直接按回车 = 使用 [方括号] 里的默认值")
	fmt.Println("==========================================================")

	c := &config{}

	// [1/5] 对外信令端口（TCP）
	fmt.Println()
	fmt.Println("[1/5] 玩家连接端口（TCP）")
	fmt.Println("      玩家在游戏里「添加服务器」时填写的端口")
	c.Listen = ":19132"
	if p, ok := askPort(w, "端口", 19132); ok {
		c.Listen = ":" + strconv.Itoa(p)
	}

	// [2/5] BDS 信令地址
	fmt.Println()
	fmt.Println("[2/5] BDS 信令地址（后端）")
	fmt.Println("      BDS 的 server-port；代理通常和 BDS 在同一台机器，保持默认即可")
	bds := askDefault(w, "地址", "127.0.0.1:19132")
	for {
		if _, _, err := net.SplitHostPort(bds); err != nil {
			fmt.Println("      × 格式应为 IP:端口，例如 127.0.0.1:19132")
			bds = askDefault(w, "地址", "127.0.0.1:19132")
			continue
		}
		break
	}
	c.BDS = bds
	fmt.Printf("      正在检测 %s ... ", bds)
	if conn, err := net.DialTimeout("tcp", bds, 1500*time.Millisecond); err == nil {
		conn.Close()
		fmt.Println("已连通")
	} else {
		fmt.Println("未连通（BDS 可能还没启动，可以稍后再启动，不影响保存配置）")
	}

	// [3/5] 对外 UDP 端口
	fmt.Println()
	fmt.Println("[3/5] 游戏流量端口（UDP）")
	fmt.Println("      所有玩家的游戏数据共用这一个端口；面板服请填面板分配的 UDP 端口")
	c.Mux = ":19133"
	if p, ok := askPort(w, "端口", 19133); ok {
		c.Mux = ":" + strconv.Itoa(p)
	}

	// [4/5] 公网 IP
	fmt.Println()
	fmt.Println("[4/5] 公网 IP（玩家实际能访问到的地址）")
	guessed := guessPublicIP()
	note := ""
	if ip := net.ParseIP(guessed); ip != nil && ip.IsPrivate() {
		note = "（检测到的是内网地址：局域网联机没问题；公网/面板部署请改填公网 IP）"
	}
	fmt.Printf("      自动检测: %s %s\n", guessed, note)
	ip := askDefault(w, "公网 IP", guessed)
	for net.ParseIP(ip) == nil {
		fmt.Println("      × 不是合法的 IP 地址，请重新输入（例如 203.0.113.10）")
		ip = askDefault(w, "公网 IP", guessed)
	}
	c.AdvertiseIP = ip

	// [5/5] 通告 UDP 端口（NAT 外部映射端口）
	fmt.Println()
	fmt.Println("[5/5] 对外通告的 UDP 端口（NAT 外部映射端口）")
	fmt.Println("      仅当面板/NAT 的外部 UDP 端口与 [3/5] 不同才需要修改")
	defAdv := mustPort(c.Mux)
	c.AdvertisePort = defAdv
	if p, ok := askPort(w, "端口", defAdv); ok {
		c.AdvertisePort = p
	}

	// 摘要
	fmt.Println()
	fmt.Println("----------------------------------------------------------")
	fmt.Println("配置摘要：")
	fmt.Printf("  玩家连接地址 : %s，端口 %d（TCP 信令）\n", c.AdvertiseIP, mustPort(c.Listen))
	fmt.Printf("  游戏 UDP 端口: %d（对外通告 %d）\n", mustPort(c.Mux), c.AdvertisePort)
	fmt.Printf("  BDS 后端     : %s\n", c.BDS)
	fmt.Println("----------------------------------------------------------")
	fmt.Println("请确认 BDS 的 server.properties：")
	fmt.Println("  · server-port 填 " + strconv.Itoa(mustPort(c.BDS)) + "（只给本代理访问）")
	fmt.Println("  · server-udp-ports 留空（由代理统一复用，切勿填端口！）")
	fmt.Println("  · transport=nethernet")

	if savePath != "" {
		if askYesNo(w, "保存配置到 "+savePath+"（下次运行免设置）", true) {
			if err := saveConfig(savePath, c); err != nil {
				fmt.Println("保存失败:", err)
			} else {
				fmt.Println("已保存", savePath)
			}
		}
	}
	fmt.Println()
	fmt.Println("正在启动代理（按 Ctrl+C 停止）...")
	return c
}

// askDefault 显示默认值并读取一行；空输入返回默认值。
func askDefault(w *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	line, err := w.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// askPort 读取 1-65535 端口；空输入/等于默认值时 ok=false（沿用默认）。
func askPort(w *bufio.Reader, label string, def int) (int, bool) {
	for {
		s := askDefault(w, label, strconv.Itoa(def))
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 65535 {
			return n, n != def
		}
		fmt.Println("  × 请输入 1-65535 之间的数字")
	}
}

func askYesNo(w *bufio.Reader, label string, def bool) bool {
	yn := "n"
	if def {
		yn = "Y"
	}
	for {
		s := strings.ToLower(askDefault(w, label+" [Y/n]", yn))
		switch s {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Println("  × 请输入 y 或 n")
	}
}

func mustPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
