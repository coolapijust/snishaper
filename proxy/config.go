package proxy

import (
	"encoding/json"
	"fmt"
	"time"
)

type ConfigFile struct {
	Version string       `json:"version"`
	Type    string       `json:"type"`
	Rules   []ConfigRule `json:"rules"`
}

type ConfigRule struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Domains  []string `json:"domains"`
	Upstream string   `json:"upstream,omitempty"`
	SniFake  string   `json:"sni_fake,omitempty"`
}

func (rm *RuleManager) ExportConfig() (string, error) {
	var mitmRules, transRules []ConfigRule

	rm.mu.RLock()
	for _, sg := range rm.siteGroups {
		rule := ConfigRule{
			Name:     sg.Name,
			Enabled:  sg.Enabled,
			Domains:  sg.Domains,
			Upstream: sg.Upstream,
			SniFake:  sg.SniFake,
		}

		if sg.Mode == "mitm" {
			mitmRules = append(mitmRules, rule)
		} else {
			transRules = append(transRules, rule)
		}
	}
	rm.mu.RUnlock()

	result := make(map[string]interface{})
	result["exported"] = time.Now().Format("2006-01-02 15:04:05")

	if len(mitmRules) > 0 {
		mitmConfig := ConfigFile{
			Version: "1.0",
			Type:    "mitm",
			Rules:   mitmRules,
		}
		mitmJSON, _ := json.MarshalIndent(mitmConfig, "", "  ")
		result["mitm"] = string(mitmJSON)
	}

	if len(transRules) > 0 {
		transConfig := ConfigFile{
			Version: "1.0",
			Type:    "transparent",
			Rules:   transRules,
		}
		transJSON, _ := json.MarshalIndent(transConfig, "", "  ")
		result["transparent"] = string(transJSON)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (rm *RuleManager) ImportConfig(content string) error {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	for _, key := range []string{"mitm", "transparent"} {
		if jsonStr, ok := data[key].(string); ok {
			var config ConfigFile
			if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
				continue
			}

			for _, rule := range config.Rules {
				sg := SiteGroup{
					ID:       generateID(),
					Name:     rule.Name,
					Domains:  rule.Domains,
					Mode:     config.Type,
					Upstream: rule.Upstream,
					SniFake:  rule.SniFake,
					Enabled:  rule.Enabled,
				}
				rm.siteGroups = append(rm.siteGroups, sg)
			}
		}
	}

	if len(rm.siteGroups) == 0 {
		return fmt.Errorf("no valid rules found")
	}

	return nil
}
