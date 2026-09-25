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

// 候选端口顺序：19132 为默认值；被占用（通常是 BDS 在用）时依次尝试后续。
var wizardPortCandidates = []int{19132, 19130, 19131, 19134, 19135}

func runWizard(savePath string) *config {
	computeLocalIPs() // 供"同机端口冲突"检测使用

	w := bufio.NewReader(os.Stdin)
	fmt.Println("==========================================================")
	fmt.Println("   Minecraft 基岩版联机助手 · 首次运行设置（共 5 步）")
	fmt.Println("==========================================================")
	fmt.Println()
	fmt.Println("  这个程序解决什么问题？")
	fmt.Println("  基岩版的新联机方式（NetherNet）每个玩家要独占一个端口，")
	fmt.Println("  端口不够时，第 2 个玩家就进不来了。")
	fmt.Println("  本程序把所有玩家合并到 2 个端口（1 个 TCP + 1 个 UDP），")
	fmt.Println("  玩家数量不再受端口限制。")
	fmt.Println()
	fmt.Println("  怎么填？")
	fmt.Println("  每一步直接按「回车」= 采用方括号里的推荐值。")
	fmt.Println("  拿不准就一路回车！")
	fmt.Println("----------------------------------------------------------")

	c := &config{}

	// ── 第 1 步：玩家连接端口（TCP）──
	fmt.Println()
	fmt.Println("【第 1 步，共 5 步】玩家连接用的端口（TCP）")
	fmt.Println()
	fmt.Println("  玩家在游戏里「添加服务器」时填的端口。")
	fmt.Println("  用面板开服 → 填面板分给你的 TCP 端口。")
	defListen := freeTCPPort(wizardPortCandidates...)
	if defListen == 0 {
		defListen = 19132
	}
	if defListen != 19132 {
		fmt.Println()
		fmt.Println("  ! 检测到 19132 已被其他程序占用（通常是 BDS 服务端在用）")
		fmt.Println("  ! 已自动换成一个空闲端口")
	}
	c.Listen = ":" + strconv.Itoa(defListen)
	if p, ok := askPort(w, "端口", defListen); ok {
		c.Listen = ":" + strconv.Itoa(p)
	}

	// ── 第 2 步：BDS 地址 ──
	fmt.Println()
	fmt.Println("【第 2 步，共 5 步】Minecraft 服务端（BDS）的地址")
	fmt.Println()
	fmt.Println("  程序需要知道 BDS 在哪，才能把玩家的数据转给它。")
	fmt.Println("  ▸ 代理和 BDS 在同一台电脑/服务器（最常见）→ 直接回车")
	fmt.Println("  ▸ BDS 在别的机器 → 填那台机器的地址，如 192.168.1.100:19132")
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
	fmt.Printf("  正在连接 %s ... ", bds)
	if conn, err := net.DialTimeout("tcp", bds, 1500*time.Millisecond); err == nil {
		conn.Close()
		fmt.Println("✓ 已连上")
	} else {
		fmt.Println("✗ 连不上（BDS 可能还没启动，不影响保存设置，之后启动也行）")
	}

	// 同机端口冲突检测：代理监听端口不能和 BDS 端口相同
	if bdsHost, _, err := net.SplitHostPort(bds); err == nil && hostIsLocal(bdsHost) {
		if bp := mustPort(bds); bp != 0 && mustPort(c.Listen) == bp {
			fmt.Println()
			fmt.Printf("  ! 注意：代理端口和 BDS 端口都是 %d，在同一台机器上会冲突！\n", bp)
			if alt := freeTCPPort(19130, 19131, 19134, 19135, bp+1); alt != 0 {
				if askYesNo(w, fmt.Sprintf("  把「玩家连接端口」换成空闲的 %d 吗", alt), true) {
					c.Listen = ":" + strconv.Itoa(alt)
				}
				// 仍冲突则强制换：留着必挂的配置不如现在解决
				if mustPort(c.Listen) == bp {
					c.Listen = ":" + strconv.Itoa(alt)
					fmt.Printf("  已自动把玩家连接端口改为 %d（同机时不能和 BDS 端口相同）\n", alt)
				}
			}
		}
	}

	// ── 第 3 步：游戏数据端口（UDP）──
	fmt.Println()
	fmt.Println("【第 3 步，共 5 步】游戏数据用的端口（UDP）")
	fmt.Println()
	fmt.Println("  所有玩家的游戏数据都从这一个 UDP 端口进出。")
	fmt.Println("  用面板开服 → 填面板分给你的 UDP 端口。")
	fmt.Println()
	fmt.Println("  小知识：TCP 和 UDP 是两种不同的端口，数字相同也不冲突")
	fmt.Println("  （比如 TCP 19130 + UDP 19133 完全没问题）。")
	c.Mux = ":19133"
	if p, ok := askPort(w, "端口", 19133); ok {
		c.Mux = ":" + strconv.Itoa(p)
	}

	// ── 第 4 步：公网 IP ──
	fmt.Println()
	fmt.Println("【第 4 步，共 5 步】服务器的对外 IP")
	fmt.Println()
	guessed := guessPublicIP()
	fmt.Printf("  玩家拿这个 IP 连你。程序自动检测到：%s\n", guessed)
	if ip := net.ParseIP(guessed); ip != nil && ip.IsPrivate() {
		fmt.Println()
		fmt.Println("  ! 检测到的是内网地址（192.168 / 10. / 172.16~31 开头）")
		fmt.Println("    → 局域网联机没问题；要让外网玩家进，")
		fmt.Println("      需改填公网 IP（面板/云服务器商家会提供）")
	}
	fmt.Println()
	ip := askDefault(w, "IP", guessed)
	for net.ParseIP(ip) == nil {
		fmt.Println("  × 这不是一个有效的 IP 地址，例如 203.0.113.10")
		ip = askDefault(w, "IP", guessed)
	}
	c.AdvertiseIP = ip

	// ── 第 5 步：外网 UDP 映射端口 ──
	fmt.Println()
	fmt.Println("【第 5 步，共 5 步】外网 UDP 映射端口")
	fmt.Println()
	fmt.Println("  只有这一种情况需要改：面板/路由器把「外部 UDP 端口」")
	fmt.Println("  映射成了和内部不同的数字（例如外部 20000 → 内部 19133），")
	fmt.Println("  这时填外部的那个数字。其他情况直接回车！")
	defAdv := mustPort(c.Mux)
	c.AdvertisePort = defAdv
	if p, ok := askPort(w, "端口", defAdv); ok {
		c.AdvertisePort = p
	}

	// ── 摘要 ──
	fmt.Println()
	fmt.Println("----------------------------------------------------------")
	fmt.Println("                设置完成！请记住以下信息")
	fmt.Println("----------------------------------------------------------")
	fmt.Println()
	fmt.Println("  ★ 玩家这样进服（游戏 → 服务器 → 添加服务器）：")
	fmt.Printf("        地址：%s    端口：%d\n", c.AdvertiseIP, mustPort(c.Listen))
	fmt.Println()
	fmt.Println("  ★ 防火墙 / 面板需要放行这 2 个端口：")
	fmt.Printf("        TCP %d（玩家连接）\n", mustPort(c.Listen))
	fmt.Printf("        UDP %d（游戏数据）\n", mustPort(c.Mux))
	fmt.Println()
	fmt.Println("  ★ 检查 BDS 文件夹里 server.properties 的这几行：")
	fmt.Println("        transport=nethernet")
	fmt.Printf("        server-port=%d        ← 保持这样，别改\n", mustPort(c.BDS))
	fmt.Println("        #server-udp-ports=      ← 默认带 # 号（注释）就对了，")
	fmt.Println("                                   千万别取消注释、别填端口！")

	if savePath != "" {
		fmt.Println()
		if askYesNo(w, "  保存设置到 "+savePath+"？（下次启动免设置）", true) {
			if err := saveConfig(savePath, c); err != nil {
				fmt.Println("  保存失败:", err)
			} else {
				fmt.Println("  已保存", savePath)
			}
		}
	}
	fmt.Println()
	fmt.Println("  正在启动...（窗口开着 = 代理在运行，关窗口 = 停止）")
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

// freeTCPPort 依次探测候选端口，返回第一个未被占用的；
// 全被占用时让系统分配一个随机空闲端口；彻底失败返回 0。
func freeTCPPort(candidates ...int) int {
	for _, p := range candidates {
		if p < 1 || p > 65535 {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// hostIsLocal 判断地址是否指向本机（用于"代理端口与 BDS 端口同机冲突"检测）。
func hostIsLocal(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return true
		}
		return localIPs[ip.String()]
	}
	return strings.EqualFold(host, "localhost")
}
