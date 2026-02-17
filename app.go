package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"snishaper/cert"
	"snishaper/proxy"
	"snishaper/sysproxy"
)

type App struct {
	ctx          context.Context
	proxyServer *proxy.ProxyServer
	certManager *cert.CertManager
	ruleManager *proxy.RuleManager
	certPath    string
	logPath     string
	logFile     *os.File
}

func NewApp() *App {
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	configPath := filepath.Join(execDir, "config.json")

	return &App{
		proxyServer: proxy.NewProxyServer("127.0.0.1:8080"),
		ruleManager: proxy.NewRuleManager(configPath),
		certPath:    filepath.Join(execDir, "cert"),
		logPath:     filepath.Join(execDir, "snishaper.log"),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.setupFileLogger()
	runtime.LogInfo(ctx, "[startup] SniShaper starting...")

	var err error
	a.certManager, err = cert.InitCertManager(a.certPath)
	if err != nil {
		runtime.LogError(ctx, "[startup] Failed to init cert manager: "+err.Error())
	} else {
		runtime.LogInfo(ctx, "[startup] Cert path: "+a.certPath)
	}

	if err := a.ruleManager.LoadConfig(); err != nil {
		runtime.LogError(ctx, "[startup] Failed to load config: "+err.Error())
	}

	a.proxyServer.SetRuleManager(a.ruleManager)
	a.proxyServer.SetCertGenerator(a.certManager)

	if err := sysproxy.SaveOriginalProxySettings(); err != nil {
		runtime.LogWarning(ctx, "[startup] Failed to save original proxy settings: "+err.Error())
	}

	runtime.LogInfo(ctx, "[startup] SniShaper started successfully")
}

func (a *App) shutdown(ctx context.Context) {
	runtime.LogInfo(ctx, "[shutdown] SniShaper shutting down...")

	if a.proxyServer.IsRunning() {
		runtime.LogInfo(ctx, "[shutdown] Stopping proxy server...")
		if err := a.proxyServer.Stop(); err != nil {
			runtime.LogError(ctx, "[shutdown] Failed to stop proxy: "+err.Error())
		}
	}

	runtime.LogInfo(ctx, "[shutdown] Restoring original system proxy settings...")
	if err := sysproxy.RestoreOriginalProxySettings(); err != nil {
		runtime.LogError(ctx, "[shutdown] Failed to restore proxy settings: "+err.Error())
	}

	runtime.LogInfo(ctx, "[shutdown] SniShaper shutdown complete")
	if a.logFile != nil {
		_ = a.logFile.Close()
		a.logFile = nil
	}
}

func (a *App) setupFileLogger() {
	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[startup] Failed to open log file %s: %v", a.logPath, err)
		return
	}
	a.logFile = f
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.Printf("[startup] Logging to %s", a.logPath)
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) StartProxy() error {
	runtime.LogInfo(a.ctx, "Starting proxy server...")
	return a.proxyServer.Start()
}

func (a *App) StopProxy() error {
	runtime.LogInfo(a.ctx, "Stopping proxy server...")
	return a.proxyServer.Stop()
}

func (a *App) IsProxyRunning() bool {
	return a.proxyServer.IsRunning()
}

func (a *App) GetStats() (int64, int64, int64) {
	return a.proxyServer.GetStats()
}

func (a *App) GetListenPort() int {
	addr := a.proxyServer.GetListenAddr()
	var port int
	fmt.Sscanf(addr, "127.0.0.1:%d", &port)
	return port
}

func (a *App) SetListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	return a.proxyServer.SetListenAddr(addr)
}

func (a *App) SetProxyMode(mode string) error {
	runtime.LogInfo(a.ctx, "[mode] Set proxy mode: "+mode)
	return a.proxyServer.SetMode(mode)
}

func (a *App) GetProxyMode() string {
	return a.proxyServer.GetMode()
}

func (a *App) GetCACertPath() string {
	if a.certManager != nil {
		return a.certManager.GetCACertPath()
	}
	return ""
}

type CAInstallStatus struct {
	Installed   bool
	Platform    string
	CertPath    string
	InstallHelp string
}

func (a *App) GetCAInstallStatus() CAInstallStatus {
	if a.certManager == nil {
		return CAInstallStatus{
			CertPath:    "",
			Platform:    "windows",
			InstallHelp: "证书管理器未初始化",
		}
	}
	status := a.certManager.GetCAInstallStatus()
	return CAInstallStatus{
		Installed:   status.Installed,
		Platform:    status.Platform,
		CertPath:    status.CertPath,
		InstallHelp: status.InstallHelp,
	}
}

func (a *App) OpenCAFile() error {
	if a.certManager == nil {
		return fmt.Errorf("cert manager not initialized")
	}
	return a.certManager.OpenCAFile()
}

func (a *App) GetCACertPEM() string {
	if a.certManager != nil {
		return a.certManager.GetCACertPEM()
	}
	return ""
}

func (a *App) RegenerateCert() error {
	if a.certManager == nil {
		return fmt.Errorf("cert manager not initialized")
	}
	return a.certManager.RegenerateCA()
}

func (a *App) ExportCert() string {
	if a.certManager == nil {
		return ""
	}
	data, err := a.certManager.ExportCert()
	if err != nil {
		runtime.LogError(a.ctx, "Export cert error: "+err.Error())
		return ""
	}
	return string(data)
}

func (a *App) GetSiteGroups() []proxy.SiteGroup {
	return a.ruleManager.GetSiteGroups()
}

func (a *App) AddSiteGroup(sg proxy.SiteGroup) error {
	return a.ruleManager.AddSiteGroup(sg)
}

func (a *App) UpdateSiteGroup(sg proxy.SiteGroup) error {
	return a.ruleManager.UpdateSiteGroup(sg)
}

func (a *App) DeleteSiteGroup(id string) error {
	return a.ruleManager.DeleteSiteGroup(id)
}

func (a *App) GetUpstreams() []proxy.Upstream {
	return a.ruleManager.GetUpstreams()
}

func (a *App) AddUpstream(u proxy.Upstream) error {
	return a.ruleManager.AddUpstream(u)
}

func (a *App) UpdateUpstream(u proxy.Upstream) error {
	return a.ruleManager.UpdateUpstream(u)
}

func (a *App) DeleteUpstream(id string) error {
	return a.ruleManager.DeleteUpstream(id)
}

func (a *App) ExportConfig() (string, error) {
	return a.ruleManager.ExportConfig()
}

func (a *App) ImportConfig(content string) error {
	return a.ruleManager.ImportConfig(content)
}

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

func (a *App) GetSystemProxyStatus() SystemProxyStatus {
	status := sysproxy.GetSystemProxyStatus()
	return SystemProxyStatus{
		Enabled:  status.Enabled,
		Server:   status.Server,
		Override: status.Override,
	}
}

func (a *App) EnableSystemProxy() error {
	runtime.LogInfo(a.ctx, "[sysproxy] Enabling system proxy...")
	addr := a.proxyServer.GetListenAddr()
	var port int
	fmt.Sscanf(addr, "127.0.0.1:%d", &port)
	if port == 0 {
		port = 8080
	}
	runtime.LogInfo(a.ctx, fmt.Sprintf("[sysproxy] Using port %d", port))
	return sysproxy.EnableSystemProxy(port)
}

func (a *App) DisableSystemProxy() error {
	runtime.LogInfo(a.ctx, "[sysproxy] Disabling system proxy...")
	return sysproxy.DisableSystemProxy()
}
