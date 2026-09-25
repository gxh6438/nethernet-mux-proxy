// nethernet-mux-proxy：BDS NetherNet 单端口复用前置代理。
//
// 架构（针对 NAT/端口受限的面板服）：
//
//	外部仅需 1 个 TCP 端口（信令）+ 1 个 UDP 端口（mux），玩家数无上限。
//	1) 信令前置：反代 BDS 的 HTTP 信令，把 answer 里的 a=candidate 地址
//	   改写为 mux 的公网地址（identity 断言只签指纹，改候选不破坏签名）。
//	2) UDP mux：单 UDP 端口接收所有玩家；首个包为 ICE STUN binding request，
//	   按 USERNAME 里的 ufrag 认领会话（必须通过 MESSAGE-INTEGRITY 验证，
//	   key = answer 的 a=ice-pwd，伪造者无法抢占）；BDS 侧回包按其源端口
//	   (每连接唯一) 区分会话转回。DTLS/SCTP/Xbox 身份验证全部端到端穿透，
//	   不解密。
//
// 使用方式：
//
//	./proxy            # 零参数：加载 ./proxy.json，不存在则进入交互式向导
//	./proxy -config c.json
//	./proxy -listen :19132 -bds 127.0.0.1:19132 -mux :19133 -advertise-ip 1.2.3.4
//	./proxy ... -save-config   # 把本次参数写入 proxy.json，下次零参数直接启动
//	./proxy -fix-bds           # 自动检查并修正同目录 server.properties（建议放在 BDS 目录运行）
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var localIPs = map[string]bool{"127.0.0.1": true, "::1": true}

func computeLocalIPs() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				localIPs[ip.String()] = true
			}
		}
	}
}

func isLocalAddr(a *net.UDPAddr) bool {
	if a == nil {
		return false
	}
	if a.IP.IsLoopback() {
		return true
	}
	return localIPs[a.IP.String()]
}

// options 运行参数（flag / 配置文件 / 向导三来源归一）。
type options struct {
	Listen           string // 对外 TCP 信令监听
	BDS              string // BDS 信令后端
	Mux              string // 对外 UDP mux 监听
	AdvertiseIP      string // IP 字面量或域名（启动时解析为 IP）
	AdvertisePort    int    // 通告公网 UDP 端口
	AdvertiseTCPPort int    // 通告公网 TCP 端口（仅提示玩家用）
	Idle             time.Duration
	MaxSessions      int
	MaxAddrs         int
	InsecureClaim    bool
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	platformInit() // Windows：UTF-8 代码页 + VT 转义

	opts := parseArgsAndConfig()

	computeLocalIPs()

	if opts.AdvertiseIP == "" {
		opts.AdvertiseIP = guessPublicIP()
		log.Printf("[main] 未指定公网 IP，使用自动检测 %s（NAT/面板部署请确认！）", opts.AdvertiseIP)
	}
	if opts.AdvertisePort == 0 {
		_, portStr, err := net.SplitHostPort(opts.Mux)
		if err != nil {
			fatal("配置里 mux 地址格式不对：%v\n  正确写法如 \":19133\"；删掉 proxy.json 重新运行本程序可进入设置向导", err)
		}
		opts.AdvertisePort, _ = strconv.Atoi(portStr)
	}
	if opts.AdvertiseTCPPort == 0 {
		opts.AdvertiseTCPPort, _ = strconv.Atoi(hostPortOnly(opts.Listen))
	}
	// SDP candidate 里只能写 IP 字面量：域名在此解析（面板/DDNS 场景填域名）
	opts.AdvertiseIP = resolveAdvertiseHost(opts.AdvertiseIP)

	table := newSessionTable(opts.Idle, opts.MaxSessions, opts.MaxAddrs, opts.InsecureClaim)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go runMux(opts.Mux, table)
	go runStats(table)

	log.Printf("[main] nethernet-mux-proxy 启动：信令 %s → %s | mux %s，通告 %s:%d",
		opts.Listen, opts.BDS, opts.Mux, opts.AdvertiseIP, opts.AdvertisePort)
	if opts.AdvertiseTCPPort != mustPort(opts.Listen) {
		log.Printf("[main] 检测到端口映射：外网 TCP %d → 内网 %s（面板/NAT 转发）",
			opts.AdvertiseTCPPort, hostPortOnly(opts.Listen))
	}
	if !opts.InsecureClaim {
		log.Printf("[main] STUN 认领验证已启用（MESSAGE-INTEGRITY）")
	} else {
		log.Printf("[main] 警告：-insecure-claim 已开启，STUN 认领不做完整性验证")
	}
	log.Printf("[main] 玩家连接地址：%s 端口 %d（游戏中「添加服务器」填这两项）",
		opts.AdvertiseIP, opts.AdvertiseTCPPort)

	if err := runSignaling(ctx, opts, table); err != nil && ctx.Err() == nil {
		fatal("信令服务出错退出：%v", err)
	}
	log.Printf("[main] 已退出")
}

func hostPortOnly(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func guessPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53") // 不会真正发包，只为路由选择源地址
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil {
			return addr.IP.String()
		}
	}
	return "127.0.0.1"
}

// resolveAdvertiseHost 把通告地址归一为 IP 字面量（SDP candidate 只能写 IP）：
// 本身是 IP 则原样返回；是域名则 DNS 解析（优先 IPv4）。
func resolveAdvertiseHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() {
			log.Printf("[main] 警告：通告 IP %s 是内网地址——仅局域网联机可用；公网部署请填写公网 IP 或域名", host)
		}
		return host
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		fatal("通告地址 %q 既不是 IP，域名也解析失败：%v\n  请检查 proxy.json 里的 advertise_ip（公网 IP 或域名均可）", host, err)
	}
	var v6 net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			log.Printf("[main] 通告域名 %s 已解析为 %s（重启本程序会重新解析）", host, v4)
			return v4.String()
		}
		if v6 == nil {
			v6 = ip
		}
	}
	if v6 != nil {
		log.Printf("[main] 通告域名 %s 只解析出 IPv6 %s（无 IPv4 记录）", host, v6)
		return v6.String()
	}
	fatal("通告域名 %q 没有解析出任何 IP 地址", host)
	return ""
}

func runStats(t *sessionTable) {
	for range time.Tick(60 * time.Second) {
		t.gc()
		t.logStats()
	}
}

// parseArgsAndConfig 三来源归一：命令行 flags > 配置文件 > 交互向导。
func parseArgsAndConfig() *options {
	fs := flag.NewFlagSet("", flag.ExitOnError)
	cfgPath := fs.String("config", "", "配置文件路径（JSON）")
	wizard := fs.Bool("wizard", false, "强制进入交互式设置向导")
	saveCfg := fs.Bool("save-config", false, "把本次启动参数（含默认值）保存到配置文件，下次零参数直接启动")
	fixBds := fs.Bool("fix-bds", false, "自动检查并修正同目录 server.properties（改前自动备份；建议把程序放在 BDS 目录运行）")
	listenTCP := fs.String("listen", "", "对外 TCP 监听地址（信令前置，玩家连接的端口）")
	bdsTCP := fs.String("bds", "", "BDS NetherNet 信令后端（BDS 的 server-port）")
	muxBind := fs.String("mux", "", "UDP mux 监听地址（所有玩家的游戏流量共用）")
	advIP := fs.String("advertise-ip", "", "通告给客户端的公网 IP 或域名（域名启动时解析；NAT/面板部署必填）")
	advPort := fs.Int("advertise-port", 0, "通告给客户端的公网 UDP 端口（默认同 mux 监听端口）")
	advTCP := fs.Int("advertise-tcp-port", 0, "通告给玩家的公网 TCP 端口（默认同 listen；仅提示用）")
	idle := fs.Duration("idle", 0, "会话空闲回收时间")
	maxSessions := fs.Int("max-sessions", 0, "最大并发会话数（默认 1024）")
	maxAddrs := fs.Int("max-addrs", 0, "每会话客户端地址数上限（默认 16）")
	insecure := fs.Bool("insecure-claim", false, "关闭 STUN MESSAGE-INTEGRITY 验证（不推荐）")
	_ = fs.Parse(os.Args[1:])

	gaveFlags := anyFlagGiven(fs)
	var cfg *config

	switch {
	case *wizard:
		cfg = runWizard("")
	case *cfgPath != "":
		c, err := loadConfig(*cfgPath)
		if err != nil {
			fatal("读取配置文件 %s 失败：%v\n  若改不明白，删除该文件后重新运行本程序会进入设置向导", *cfgPath, err)
		}
		cfg = c
	default:
		if c, err := loadConfig(defaultConfigPath); err == nil && c != nil {
			log.Printf("[main] 已加载配置 %s", defaultConfigPath)
			cfg = c
		} else if gaveFlags {
			cfg = &config{}
		} else {
			cfg = runWizard(defaultConfigPath) // 零基础路径：直接运行进入向导
		}
	}

	opts := &options{
		Listen:           orDefault(cfg.Listen, ":19132"),
		BDS:              orDefault(cfg.BDS, "127.0.0.1:19132"),
		Mux:              orDefault(cfg.Mux, ":19133"),
		AdvertiseIP:      cfg.AdvertiseIP,
		AdvertisePort:    cfg.AdvertisePort,
		AdvertiseTCPPort: cfg.AdvertiseTCPPort,
		Idle:             orDur(cfg.Idle, 5*time.Minute),
		MaxSessions:      orInt(cfg.MaxSessions, 1024),
		MaxAddrs:         orInt(cfg.MaxAddrs, 16),
		InsecureClaim:    cfg.InsecureClaim,
	}

	// 命令行 flags 覆盖配置文件
	if *listenTCP != "" {
		opts.Listen = *listenTCP
	}
	if *bdsTCP != "" {
		opts.BDS = *bdsTCP
	}
	if *muxBind != "" {
		opts.Mux = *muxBind
	}
	if *advIP != "" {
		opts.AdvertiseIP = *advIP
	}
	if *advPort != 0 {
		opts.AdvertisePort = *advPort
	}
	if *advTCP != 0 {
		opts.AdvertiseTCPPort = *advTCP
	}
	if *idle != 0 {
		opts.Idle = *idle
	}
	if *maxSessions != 0 {
		opts.MaxSessions = *maxSessions
	}
	if *maxAddrs != 0 {
		opts.MaxAddrs = *maxAddrs
	}
	if *insecure {
		opts.InsecureClaim = true
	}

	// -fix-bds：自动检查并修正同目录 server.properties（先于 -save-config，
	// 这样冲突修正后的新 BDS 端口也能一并保存进配置文件）。
	if *fixBds {
		if spPath := findServerProperties(); spPath == "" {
			log.Printf("[main] -fix-bds：当前目录没有 server.properties，跳过（把程序放到 BDS 目录里运行即可）")
		} else if data, err := os.ReadFile(spPath); err != nil {
			log.Printf("[main] -fix-bds：读取 %s 失败：%v", spPath, err)
		} else {
			listenP := mustPort(opts.Listen)
			alt := freeTCPPort(19131, 19130, 19134, 19135, listenP+1)
			bdsHost, _, _ := net.SplitHostPort(opts.BDS)
			fix := planServerPropertiesFix(string(data), listenP, alt, hostIsLocal(bdsHost))
			if len(fix.changes) == 0 {
				log.Printf("[main] -fix-bds：%s 检查通过，无需修改", spPath)
			} else {
				for _, ch := range fix.changes {
					log.Printf("[main] -fix-bds：%s", ch)
				}
				if err := saveServerPropertiesFixed(spPath, data, fix.content); err != nil {
					log.Printf("[main] -fix-bds：%v（未改动原文件）", err)
				} else {
					log.Printf("[main] -fix-bds：已修正 %s（原文件已备份），重启 BDS 后生效", spPath)
					if fix.newBDSPort != 0 {
						opts.BDS = bdsHost + ":" + strconv.Itoa(fix.newBDSPort)
						log.Printf("[main] -fix-bds：BDS 端口已变更，本进程将连接 %s；下次启动请同步修改 -bds（或加 -save-config 保存）", opts.BDS)
					}
				}
			}
		}
	}

	// -save-config：把本次有效配置（命令行覆盖 + 默认值归一后的结果）
	// 写入配置文件，下次零参数启动即用。
	if *saveCfg {
		path := *cfgPath
		if path == "" {
			path = defaultConfigPath
		}
		if err := saveConfig(path, optsToConfig(opts)); err != nil {
			log.Printf("[main] 保存配置到 %s 失败：%v", path, err)
		} else {
			log.Printf("[main] 已保存配置到 %s（下次零参数启动即用）", path)
		}
	}
	return opts
}

// optsToConfig 运行参数 → 配置文件结构（用于 -save-config 落盘）。
func optsToConfig(o *options) *config {
	return &config{
		Listen:           o.Listen,
		BDS:              o.BDS,
		Mux:              o.Mux,
		AdvertiseIP:      o.AdvertiseIP,
		AdvertisePort:    o.AdvertisePort,
		AdvertiseTCPPort: o.AdvertiseTCPPort,
		Idle:             o.Idle.String(),
		MaxSessions:      o.MaxSessions,
		MaxAddrs:         o.MaxAddrs,
		InsecureClaim:    o.InsecureClaim,
	}
}

func anyFlagGiven(fs *flag.FlagSet) bool {
	given := false
	fs.Visit(func(*flag.Flag) { given = true })
	return given
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDur(v string, def time.Duration) time.Duration {
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func orInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
