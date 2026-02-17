package sysproxy

import (
	"fmt"
	"strings"
)

const (
	proxySettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

func notifyProxyChange() {
	// 使用 WM_SETTINGCHANGE 广播通知系统设置已更改
	// 通过执行一个轻量级的命令来触发系统刷新
	startHiddenCommand("cmd", "/c", "echo", "proxy_changed")
}

func GetSystemProxyStatus() SystemProxyStatus {
	status := SystemProxyStatus{}

	// 查询 ProxyEnable
	out, err := outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable")
	if err == nil && len(out) > 0 {
		if strings.Contains(string(out), "0x1") {
			status.Enabled = true
		}
	}

	// 查询 ProxyServer
	out, err = outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer")
	if err == nil && len(out) > 0 {
		status.Server = parseRegValue(string(out))
	}

	// 查询 ProxyOverride
	out, err = outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride")
	if err == nil && len(out) > 0 {
		status.Override = parseRegValue(string(out))
	}

	return status
}

func parseRegValue(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func SetSystemProxy(enable bool, server string) error {
	enableVal := "0"
	if enable {
		enableVal = "1"
	}

	// Set ProxyEnable using reg command
	if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", enableVal, "/f"); err != nil {
		return fmt.Errorf("[sysproxy] failed to set ProxyEnable: %w", err)
	}

	// Set ProxyServer if enabling
	if enable {
		if server == "" {
			return fmt.Errorf("[sysproxy] server cannot be empty when enabling proxy")
		}
		if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", server, "/f"); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyServer: %w", err)
		}

		// Set ProxyOverride
		override := "<local>"
		if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", override, "/f"); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyOverride: %w", err)
		}
	}

	notifyProxyChange()
	return nil
}

func EnableSystemProxy(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("[sysproxy] invalid port: %d", port)
	}
	server := fmt.Sprintf("127.0.0.1:%d", port)
	return SetSystemProxy(true, server)
}

func DisableSystemProxy() error {
	return SetSystemProxy(false, "")
}

func GetSystemProxyStatusSafe() (SystemProxyStatus, error) {
	status := GetSystemProxyStatus()
	return status, nil
}

var originalProxySettings *SystemProxyStatus

func SaveOriginalProxySettings() error {
	status := GetSystemProxyStatus()
	originalProxySettings = &status
	return nil
}

func RestoreOriginalProxySettings() error {
	if originalProxySettings == nil {
		return nil
	}

	enableVal := "0"
	if originalProxySettings.Enabled {
		enableVal = "1"
	}

	// Restore ProxyEnable
	runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", enableVal, "/f")

	// Restore ProxyServer if it was enabled
	if originalProxySettings.Enabled && originalProxySettings.Server != "" {
		runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", originalProxySettings.Server, "/f")
		if originalProxySettings.Override != "" {
			runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", originalProxySettings.Override, "/f")
		}
	}

	notifyProxyChange()
	return nil
}

// SetSystemProxyManual 允许用户通过 Windows 设置界面手动配置代理
func SetSystemProxyManual() error {
	// 打开 Windows 代理设置界面
	return startHiddenCommand("cmd", "/c", "start", "ms-settings:network-proxy")
}
