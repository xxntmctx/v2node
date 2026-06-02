package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Modified
type Conf struct {
	LogConfig    LogConfig     `mapstructure:"Log"`
	NodeConfigs  []NodeConfig  `mapstructure:"Nodes"`
	PprofPort    int           `mapstructure:"PprofPort"`
	GOGC         int           `mapstructure:"Gogc"`
	MemLimit     int64         `mapstructure:"MemLimit"`
	PolicyConfig PolicyConfig  `mapstructure:"Policy"`
	Monitor      MonitorConfig `mapstructure:"Monitor"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type NodeConfig struct {
	APIHost          string `mapstructure:"ApiHost"`
	NodeID           int    `mapstructure:"NodeID"`
	NodeType         string `mapstructure:"NodeType"`
	Key              string `mapstructure:"ApiKey"`
	Timeout          int    `mapstructure:"Timeout"`
	CustomConfigPath string `mapstructure:"CustomConfigPath"`
}

// Added
type PolicyConfig struct {
	Handshake      uint32 `mapstructure:"Handshake"`
	ConnectionIdle uint32 `mapstructure:"ConnectionIdle"`
	UplinkOnly     uint32 `mapstructure:"UplinkOnly"`
	DownlinkOnly   uint32 `mapstructure:"DownlinkOnly"`
	BufferSize     int32  `mapstructure:"BufferSize"`
}

// Added
type MonitorConfig struct {
	Enable       bool  `mapstructure:"Enable"`
	Interval     int   `mapstructure:"Interval"`
	LogThreshold int   `mapstructure:"LogThreshold"`
}

// Modified
func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
		GOGC:     100,
		MemLimit: 0,
		PolicyConfig: PolicyConfig{
			Handshake:      4,
			ConnectionIdle: 300,
			UplinkOnly:     2,
			DownlinkOnly:   4,
			BufferSize:     16,
		},
		Monitor: MonitorConfig{
			Enable:       true,
			Interval:     30,
			LogThreshold: 100,
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	return nil
}
