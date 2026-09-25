# NetherNet Mux Proxy

Minecraft 基岩版服务器（BDS）NetherNet **单端口复用前置代理**。

解决面板服/端口受限环境下的核心痛点：**NetherNet 每个玩家连接都要占用一个独立 UDP 端口，端口受限的面板服只能进一个玩家**。本代理部署后对外只需 **1 个 TCP 端口 + 1 个 UDP 端口**，玩家数量无上限，BDS 无需任何改动。

```
                        面板/公网只放行 2 个端口
                        ┌─────────────────────┐
 玩家 A ─┐               │  TCP :19132 (信令)  │      ┌──────────────┐
 玩家 B ─┼──────────────►│  UDP :19133 (mux)   │─────►│ 代理(本项目)  │
 玩家 C ─┘               │                     │      └──────┬───────┘
                         └─────────────────────┘             │ 本机回环
                                                    ┌────────▼────────┐
                                                    │ BDS (nethernet) │
                                                    │ 内部端口按玩家分配│
                                                    └─────────────────┘
```

- 适用版本：Minecraft BDS 1.26.50+（`transport=nethernet`）
- 语言：Go（纯标准库 + pion/stun），无 CGO，静态编译单文件
- 平台：Windows x64/ARM64、Linux x64/ARM64

---

## 目录

- [背景与原理](#背景与原理)
- [技术实现](#技术实现)
- [安全模型](#安全模型)
- [使用说明](#使用说明)
  - [下载与启动](#一下载与启动)
  - [向导各步填写](#二向导各步填写)
  - [BDS 侧设置](#三bds-侧设置重要)
  - [防火墙放行](#四防火墙面板放行)
  - [玩家进服](#五玩家怎么进服)
  - [命令行与配置文件](#六命令行与配置文件)
  - [Linux 常驻 systemd](#七-linux-常驻systemd-可选)
- [从源码构建](#从源码构建)
- [测试](#测试)
- [常见问题 FAQ](#常见问题-faq)
- [许可证](#许可证)

---

## 背景与原理

Minecraft 基岩版 1.26.50 起，联机传输层从 RakNet 切换到了 **NetherNet**（基于 WebRTC 的 P2P 传输）：

- 信令走 BDS 的 HTTP 端口（`server-port`，TCP），客户端 POST SDP offer，BDS 返回 answer；
- 游戏数据走 WebRTC DataChannel（DTLS/SCTP over UDP），**每个玩家连接由 BDS 分配独立的 UDP 端口**（`server-udp-ports`）。

在端口受限的面板服上，只放行了有限端口，NetherNet 的"每玩家一个 UDP 端口"模式直接崩坏：第一个玩家占掉唯一端口后，第二个玩家无法加入。

本代理在 BDS 前面做两层工作：

1. **信令前置（TCP）**：反向代理 BDS 的 HTTP 信令。转发 offer 原文，把 answer 中的 `a=candidate` 地址改写为代理的公网地址。SDP 的 `a=identity` 断言只覆盖 `a=fingerprint` 行，改候选地址不破坏 Xbox 身份签名。
2. **UDP 复用（单 UDP 端口）**：所有玩家的游戏流量共用一个 UDP 端口。
   - 玩家 → 代理：未知来源首包为 ICE STUN binding request，按 USERNAME 里的 ufrag 定位会话，**必须通过 MESSAGE-INTEGRITY 验证**（HMAC-SHA1，密钥 = answer 的 `a=ice-pwd`）后学习地址、放行转发；
   - 代理 → BDS：按会话转发到 BDS 为该玩家分配的内部 UDP 地址；
   - BDS → 代理：按回包的源端口（每连接唯一）解复用，转回该玩家最新活跃的地址。

DTLS/SCTP/Xbox 身份验证全部端到端穿透，代理不解密、不感知游戏内容。

## 技术实现

### 转发路径：写时复制（COW）快照，每包零锁

高 pps 的 UDP 转发路径不能碰互斥锁。会话表采用不可变快照（`session.go`）：

```
读路径（每包）:  atomic.Load(snapshot) → map 查表 → WriteTo   # 零锁
写路径（低频）:  mu.Lock → 修改权威集 → 全量重建 map → atomic.Store # 整体替换
```

注册/认领/回收均为每玩家连接 1~3 次的低频事件，全量重建成本可忽略，换来转发路径完全无锁竞争。

### STUN 认领：两级验证

- **第一级 `stunUsername`（零依赖快速预筛）**：手写解析 STUN 头与 USERNAME 属性（含属性对齐、越界防御），只对"未知来源首包"调用；
- **第二级 `stunVerify`（pion/stun）**：RFC 5389/8445 短期凭证 MESSAGE-INTEGRITY 完整验证。密钥为会话的 `a=ice-pwd`——该值只在信令应答中出现，不经过公网 UDP，伪造者无从获得。

### 回程跟随：最新活跃地址

真实客户端会从多个本地 socket 发 ICE 检查，回程必须跟随**最新活跃**的来源（`clientAddr atomic.Pointer`），否则回包会钉死在过期 socket 上导致 ICE 配对失败。

### 会话生命周期

- 空闲回收（默认 5 分钟，`-idle` 可调）；
- 最大并发会话上限（默认 1024）；
- 每会话可学习的客户端地址数上限（默认 16，防地址表被刷爆）。

### 信令前置的健壮性

- 逐跳头剥离（RFC 7230 §6.1）；
- SDP 请求体上限 1 MB（防超大 body 攻击）；
- 各级超时（ReadHeaderTimeout 防慢速头部攻击，后端超时覆盖 BDS 的 ICE 全量收集）；
- 仅透传 `/v1/join` 路径，减少暴露面；
- 优雅退出（SIGINT/SIGTERM → context 取消 → HTTP Shutdown）。

### Windows 控制台兼容

`platformInit()` 设置 UTF-8 代码页（65001）并启用 VT100 转义，保证中文提示与表格线在 cmd/PowerShell 下正常显示。`SetConsoleOutputCP` 未被 x/sys 封装，经 `kernel32.dll` 直接调用。

### 性能细节

- UDP 接收缓冲提升至 4 MB，降低高 pps 丢包；
- 单 socket 双向转发，无 per-player goroutine；
- 转发直接操作原 buffer，验证仅在副本上进行；
- 二进制 `-trimpath -ldflags "-s -w"` 静态编译，Linux 版约 6.5 MB。

## 安全模型

| 威胁 | 防御 |
|---|---|
| 知道 ufrag 即抢占他人会话（旧版抢占攻击） | MESSAGE-INTEGRITY 验证，无 ice-pwd 无法通过 HMAC |
| 猜测/爆破 ice-pwd | 每会话地址数上限 + 拒绝计数与日志告警 |
| 伪造非 STUN 垃圾包 | 非 STUN 直接丢弃，不学习地址 |
| 刷地址表撑爆内存 | 每会话 maxAddrs（默认 16）上限 |
| 会话泄漏 | 空闲 5 分钟自动 GC |
| 超大 SDP 攻击信令 | 请求体 1 MB 上限 |
| 慢速连接攻击 | ReadHeaderTimeout 10s |
| BDS 重启后端口复用串话 | 端口重叠检测并按最新会话处理，记录日志 |

仓库自带 `attacker` 工具可完整验证该模型（见[测试](#测试)）。

> **注意**：`-insecure-claim` 会关闭 MESSAGE-INTEGRITY 验证（兼容无 ice-pwd 的非常规后端），仅在你明确知道后果时使用。

---

## 使用说明

### 一、下载与启动

到 [Releases](../../releases) 下载对应平台的程序：

| 服务器系统 | 文件 |
|---|---|
| Windows x64（最常见） | `nethernet-mux-proxy-windows-amd64.exe` |
| Windows ARM | `nethernet-mux-proxy-windows-arm64.exe` |
| Linux x64 | `nethernet-mux-proxy-linux-amd64` |
| Linux ARM | `nethernet-mux-proxy-linux-arm64` |

**Windows**：把 `.exe` 放到一个文件夹（例如 `D:\proxy\`），双击运行。第一次运行自动进入设置向导，逐步提问，**直接按回车就用方括号里的默认值**。向导结束后自动启动，窗口不要关（关了代理就停了）。

**Linux**：

```bash
chmod +x nethernet-mux-proxy-linux-amd64
./nethernet-mux-proxy-linux-amd64
```

同样第一次进向导，自动生成 `proxy.json`，下次运行免设置。想重新跑向导：删掉 `proxy.json` 或加参数 `-wizard`。

### 二、向导各步填写

每一步直接按回车 = 采用方括号里的推荐值，拿不准就一路回车。

| 步骤 | 问题 | 填什么 |
|---|---|---|
| [1/5] | 玩家连接用的端口（TCP） | 玩家在游戏里「添加服务器」填的端口。**程序会自动避开已被占用的端口**（比如 BDS 正在用的 19132）。面板只给了特定 TCP 端口就填那个 |
| [2/5] | Minecraft 服务端（BDS）的地址 | 默认 `127.0.0.1:19132`（代理和 BDS 同机，最常见）。BDS 在别的机器填那台机器的地址，如 `192.168.1.100:19132`。向导自动检测连通性；**同机时代理端口与 BDS 端口撞车会自动提醒并换成空闲端口** |
| [3/5] | 游戏数据用的端口（UDP） | 所有玩家的游戏数据共用的 UDP 端口，默认 19133。面板只给了特定 UDP 端口就填那个（TCP 和 UDP 是两种端口，数字相同也不冲突） |
| [4/5] | 服务器的对外 IP 或域名 | 玩家拿这个地址连你。填**公网 IP 或域名**（面板给的 `play.xxx.cn` 也可以，程序启动时自动解析成 IP）。向导自动检测本机 IP；检测出 192.168 / 10. / 172.16~31 开头说明是内网地址（局域网联机没问题） |
| [5/5] | 外网映射端口（TCP + UDP） | 面板/路由器把外网端口映射成和内网不同数字时填**外网的**（如外网 29011 → 内网 19132 就填 29011）；外网内网一样的话直接回车 |

### 三、BDS 侧设置（重要！）

确认 `server.properties`：

```properties
transport=nethernet
server-port=19132
#server-udp-ports=
```

> **关于 `server-udp-ports`**：新装的 BDS 里这一行默认就是被注释掉的（行首有 `#` 号）——**保持原样即可，不需要取消注释**，更不要往里填端口。本代理会统一复用 UDP 端口，BDS 自己分配的内部端口不需要你操心。如果不小心取消注释并填了端口，改回 `#server-udp-ports=`（或清空值）即可。

> **关于 `server-port`**：这是 BDS 自己的端口（默认 19132），只给本代理访问，玩家不直连它。注意代理的「玩家连接端口」（向导第 1 步）不能和它相同——**同机部署时向导会自动检测并避开**；若忘了向导直接启动，程序也会打印具体的冲突解决办法而不是闪退。

### 四、防火墙/面板放行

必须放行两个端口（对应向导 [1/5] 和 [3/5]）：

- **TCP 19132** —— 玩家连接/信令
- **UDP 19133** —— 游戏数据

BDS 的端口**不需要**对外放行（代理在本机访问它）。

### 五、玩家怎么进服

Minecraft 基岩版 → 游戏 → 服务器 → 添加服务器：

- **服务器地址**：向导 [4/5] 填的公网 IP
- **端口**：向导 [1/5] 填的 TCP 端口（默认 19132）

### 六、命令行与配置文件

向导生成的 `proxy.json`（与程序同目录）可直接编辑，改完重启生效：

```json
{
  "listen": ":19132",
  "bds": "127.0.0.1:19131",
  "mux": ":19132",
  "advertise_ip": "play.example.com",
  "advertise_port": 29011,
  "advertise_tcp_port": 29011,
  "idle": "5m",
  "max_sessions": 1024,
  "max_addrs": 16,
  "insecure_claim": false
}
```

- `advertise_ip` 可以填**公网 IP 或域名**；域名会在启动时解析成 IP（SDP candidate 要求 IP 字面量），重启后重新解析
- `advertise_port` 是**外网 UDP 端口**（玩家游戏数据实际访问的），`advertise_tcp_port` 是**外网 TCP 端口**（玩家「添加服务器」填的，仅提示用）；外网内网端口相同时可省略

优先级：**命令行 flags > 配置文件 > 默认值**。零参数且无配置文件时进入向导。

```
-config PATH        指定配置文件路径（JSON）
-wizard             强制进入交互式设置向导
-listen ADDR        对外 TCP 监听（信令前置，玩家连接的端口）
-bds ADDR           BDS NetherNet 信令后端（BDS 的 server-port）
-mux ADDR           UDP mux 监听（所有玩家游戏流量共用）
-advertise-ip HOST  通告给客户端的公网 IP 或域名（域名启动时解析；NAT/面板部署必填）
-advertise-port N   通告的公网 UDP 端口（默认同 mux 监听端口）
-advertise-tcp-port N  通告给玩家的公网 TCP 端口（默认同 listen；仅提示用）
-idle DUR           会话空闲回收时间（默认 5m）
-max-sessions N     最大并发会话数（默认 1024）
-max-addrs N        每会话客户端地址数上限（默认 16）
-insecure-claim     关闭 STUN MESSAGE-INTEGRITY 验证（不推荐！）
```

运行中每 60 秒打印一次统计：

```
[stats] 会话=3 正向=74 反向=102 认领=2 拒绝=8 丢弃=0 未知BDS端口=0
```

### 七、Linux 常驻（systemd，可选）

`/etc/systemd/system/nethernet-mux-proxy.service`：

```ini
[Unit]
Description=NetherNet Mux Proxy
After=network.target

[Service]
ExecStart=/opt/proxy/nethernet-mux-proxy-linux-amd64
WorkingDirectory=/opt/proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now nethernet-mux-proxy
```

---

## 从源码构建

需要 Go 1.25+：

```bash
go build -o proxy .                    # 当前平台
go test ./...                          # 单元测试（含 -race）

# 全平台交叉编译（无需 CGO）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o proxy.exe .
CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o proxy .
```

项目结构：

```
.
├── main.go          # 入口：三来源配置归一、信号处理、公网 IP 检测
├── wizard.go        # 零基础交互式设置向导（自动避开占用端口/同机冲突检测）
├── fatal.go         # 友好报错：端口占用等原因与解决办法，Windows 不闪退
├── config.go        # JSON 配置读写
├── signaling.go     # 信令前置：HTTP 反代 + SDP answer 候选改写
├── mux.go           # UDP mux：单端口双向转发决策
├── session.go       # 会话表：COW 快照、认领、GC、限额
├── stun.go          # STUN USERNAME 预筛 + MESSAGE-INTEGRITY 验证
├── console_*.go     # 平台适配（Windows UTF-8/VT100）
├── stun_test.go     # 单元测试（协议解析、安全性、限额、配置）
├── fakebds/         # 测试用"假 BDS"（pion WebRTC，可模拟单端口限制）
├── testclient/      # 测试用模拟基岩客户端（伪造 NAT + Xbox 身份）
└── attacker/        # 安全模型攻击模拟器
```

## 测试

```bash
# 单元测试（含数据竞争检测）
go test -race ./...

# 端到端回归：假 BDS + 代理 + 双客户端并发（单 UDP 端口承载）
go build -o testbin/fakebds ./fakebds && go build -o testbin/testclient ./testclient && go build -o testbin/proxy .
./testbin/fakebds &
./testbin/proxy -listen 127.0.0.1:19132 -bds 127.0.0.1:25000 -mux :19133 -advertise-ip 127.0.0.1 &
./testbin/testclient & ./testbin/testclient &      # 双客户端应全部 connected + 收到回显

# 攻击模拟：伪造包被拒 / 合法包放行
go build -o testbin/attacker ./attacker
./testbin/attacker
```

`attacker` 模拟三类攻击 + 一个对照组：

- **A1** 知道受害者 ufrag + 猜测密码构造伪造 MESSAGE-INTEGRITY → **被拒**（无响应）
- **A2** 知道 ufrag 但不带 MESSAGE-INTEGRITY → **被拒**
- **A3** 非 STUN 垃圾字节 → **丢弃**
- **C** 自己的 ufrag + 信令应答中的 ice-pwd（合法检查）→ 收到 Binding Success（证明静默是安全拒绝而非网络故障）

## 常见问题 FAQ

**玩家卡在"连接中"进不来？**
最常见原因是 UDP 端口没放行。确认防火墙/面板放行了向导 [3/5] 的 UDP 端口。

**启动报"端口没法监听 / address already in use"？**
最常见是 BDS 的 server-port 和代理端口撞了（默认都是 19132）。程序会打印具体原因和解决办法（Windows 下不会闪退，会停住等你按回车）。最简单的处理：删掉 proxy.json 重新运行，向导会自动挑一个空闲端口。

**通告地址可以填域名吗（比如面板给的 play.xxx.cn）？**
可以。域名会在启动时解析成 IP 写进 SDP candidate（candidate 只接受 IP 字面量），重启后重新解析。外网端口和内网不同时，记得同时设置 `advertise_port`（外网 UDP）和 `advertise_tcp_port`（外网 TCP）。

**Linux 怎么后台一键启动？**
```bash
nohup ./nethernet-mux-proxy-linux-amd64 > proxy.log 2>&1 &
```
停止：`pkill -x nethernet-mux-proxy`；看日志：`tail -f proxy.log`。

**日志出现"拒绝...MESSAGE-INTEGRITY 验证失败"？**
正常，这是代理在拦截伪造/重放的包，不是故障。

**能和 BDS 不在同一台机器吗？**
可以，[2/5] 填 BDS 所在机器的地址即可。但代理与 BDS 之间的 UDP 端口需可达（内网/同机房最佳）。

**玩家数据会被解密吗？**
不会。DTLS/SCTP/Xbox 身份验证全部端到端穿透，代理只做四层转发，看不到也不存储游戏内容。

**BDS 重启后玩家连不上？**
BDS 重启会复用内部端口，代理会自动按最新会话处理并记录警告日志；玩家重连一次即可。

**支持旧版 RakNet 协议吗？**
不支持。本代理只针对 NetherNet（`transport=nethernet`），RakNet 本来就不存在端口受限问题。

## 许可证

[MIT](LICENSE)
