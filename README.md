# SniShaper

SniShaper 是一个基于 Go + Wails 的桌面代理工具，面向 DPI 相关网络场景，支持两种流量处理模式：

- `transparent`：透明透传（TCP 隧道）
- `mitm`：中间人模式（本地 CA 解密 + 上游 SNI 控制）

项目核心目标是：通过可视化界面管理规则、上游与系统代理，实现可控的分流与代理链路。

## 核心功能

- 支持 HTTP 代理与 `CONNECT` 隧道。
- 支持双模式运行：`transparent` / `mitm`。
- 支持按域名规则匹配，区分不同模式规则。
- 支持上游地址配置与 `sni_fake`（MITM 场景）。
- 内置 CA 证书生成、安装状态检测（Windows）。
- 支持一键开关系统代理（Windows）。
- 提供桌面端 GUI 管理界面（Wails + 前端页面）。

## 项目结构

- `main.go`：Wails 程序入口。
- `app.go`：前后端绑定、生命周期、系统能力封装。
- `proxy/`：代理核心实现（请求处理、CONNECT、规则匹配、MITM/透传逻辑）。
- `cert/`：CA 与证书管理。
- `sysproxy/`：Windows 系统代理读写与恢复。
- `frontend/`：前端界面源码。
- `rules/`：内置规则文件。

## 运行环境

- Go `1.26+`
- Node.js + npm
- Wails CLI v2
- Windows（当前系统代理模块为 Windows 实现）

## 开发与调试

安装前端依赖：

```powershell
cd frontend
npm install
cd ..
```

开发模式运行：

```powershell
wails dev
```

## 构建

构建桌面应用：

```powershell
wails build
```

仅做后端编译校验：

```powershell
go test ./...
go build ./...
```

## 配置与日志

- 默认监听地址：`127.0.0.1:8080`
- 配置文件路径：可执行文件同目录下 `config.json`
- 证书目录路径：可执行文件同目录下 `cert/`
- 后端运行日志：可执行文件同目录下 `snishaper.log`

## 两种模式说明

### transparent 模式

- 仅做隧道透传，不解密 TLS。
- 适合“可透传”链路（例如特定上游场景）。
- 性能开销小，链路简单。

### mitm 模式

- 客户端与代理建立 TLS，代理与上游再建立 TLS。
- 可按规则使用 `sni_fake` 控制上游握手 SNI。
- 需要系统/浏览器信任当前 CA 证书。

## 常见问题

### 1. transparent 能通，mitm 不通

重点检查：

- 当前运行实例使用的 `cert/ca.crt` 是否与系统信任库中的证书一致。
- 是否确实切换到 `mitm` 模式（前端模式已同步到后端）。
- `snishaper.log` 中 MITM 失败阶段（客户端握手 / 上游握手）。

### 2. 证书已安装但仍提示不信任

- 重新导出并安装当前 `cert/ca.crt`。
- 清理历史旧 CA（同名旧证书可能干扰判断）。
- 重启浏览器后再测试。

### 3. 模式切换后行为无变化

- 确认规则中对应模式的规则已启用。
- 查看日志中的 `runtime-mode` 与 `rule-mode` 是否一致。

## 免责声明

本项目仅用于网络技术研究与授权测试，请在符合法律法规和服务条款的前提下使用。
