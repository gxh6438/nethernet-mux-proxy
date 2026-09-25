package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const defaultConfigPath = "proxy.json"

// config 配置文件结构（JSON，向导可自动生成）。
// Listen/Mux 为空时按 "0.0.0.0:端口" 处理；字段均可省略走默认值。
type config struct {
	Listen           string `json:"listen"`             // 对外 TCP 信令监听，如 ":19132"
	BDS              string `json:"bds"`                // BDS 信令后端，如 "127.0.0.1:19132"
	Mux              string `json:"mux"`                // 对外 UDP mux 监听，如 ":19133"
	AdvertiseIP      string `json:"advertise_ip"`       // 通告公网地址：IP 或域名（域名启动时解析）
	AdvertisePort    int    `json:"advertise_port"`     // 通告公网 UDP 端口（0 = 同 mux）
	AdvertiseTCPPort int    `json:"advertise_tcp_port"` // 通告公网 TCP 端口（0 = 同 listen；仅提示玩家用）
	Idle             string `json:"idle"`               // 会话空闲回收，如 "5m"
	MaxSessions      int    `json:"max_sessions"`       // 最大并发会话（0 = 1024）
	MaxAddrs         int    `json:"max_addrs"`          // 每会话地址上限（0 = 16）
	InsecureClaim    bool   `json:"insecure_claim"`     // 关闭 STUN MIC 验证（不推荐）
}

// loadConfig 读取配置；文件不存在时返回 (nil, nil)。
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	c := &config{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func saveConfig(path string, c *config) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
