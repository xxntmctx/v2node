package core

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// LocalXrayConfig is a subset of the full xray config format.
// Users can define any of these sections in their local custom.json file.
// Sections not specified are simply ignored and the defaults are used.
type LocalXrayConfig struct {
	// Outbounds defines additional outbound proxies or rules.
	// Format is standard xray OutboundDetourConfig JSON format.
	// Example: [{"protocol":"socks","tag":"us_out","settings":{...}}]
	Outbounds []json.RawMessage `json:"outbounds"`

	// Routing defines additional routing rules to be merged with panel routes.
	// Panel routes always take the highest priority.
	// Routes here come after panel routes but before the built-in defaults.
	Routing *LocalRoutingConfig `json:"routing"`

	// DNS defines additional DNS servers to prepend to the built-in localhost DNS.
	// Format: standard xray DNS server config JSON objects.
	DNS *LocalDNSConfig `json:"dns"`
}

// LocalRoutingConfig mirrors the xray routing config, but only the rules array is used.
type LocalRoutingConfig struct {
	// Rules contains xray-compatible routing rule objects.
	// You can use inboundTag to match a specific node's traffic.
	// Node inboundTag format: "[https://your-panel.com]-vless:1"
	// Example rule:
	//   {"type":"field","inboundTag":["[https://x.y.z]-vless:1"],"domain":["geosite:netflix"],"outboundTag":"jp_proxy"}
	Rules []json.RawMessage `json:"rules"`
}

// LocalDNSConfig holds additional DNS servers to prepend.
type LocalDNSConfig struct {
	// Servers is a list of DNS server entries.
	// Each entry can be a plain string (e.g., "8.8.8.8") or a full xray
	// NameServerConfig object (e.g., {"address":"8.8.8.8","domains":["geosite:cn"]}).
	Servers []json.RawMessage `json:"servers"`
}

// defaultLocalConfigPath is the default path to look for the local custom config.
const defaultLocalConfigPath = "/etc/v2node/custom.json"

// LoadLocalConfig reads a local xray-format config file and returns the parsed config.
// If path is empty, it tries defaultLocalConfigPath.
// If the file does not exist, it returns nil (no error — this is an optional feature).
// If the file exists but cannot be parsed, an error is returned.
func LoadLocalConfig(path string) (*LocalXrayConfig, error) {
	if path == "" {
		path = defaultLocalConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist — that's OK, it's optional
			return nil, nil
		}
		return nil, fmt.Errorf("read local config file %s: %w", path, err)
	}

	cfg := &LocalXrayConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse local config file %s: %w", path, err)
	}

	routeCount := 0
	outboundCount := len(cfg.Outbounds)
	if cfg.Routing != nil {
		routeCount = len(cfg.Routing.Rules)
	}
	log.Infof("Local custom config loaded from %s: %d outbounds, %d route rules",
		path, outboundCount, routeCount)

	return cfg, nil
}
