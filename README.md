```markdown
# SniShaper

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)]()

**通过零成本穿透或中间人重写突破SNI 阻断的桌面代理工具。、**

> 🔍 **什么是 SNI 阻断？**  
> 防火墙通过检查 TLS 握手时的域名信息（SNI）来阻断连接。SniShaper 通过修改 SNI、模拟浏览器指纹（uTLS）和利用境内 Anycast 节点，让流量看起来像在访问 Cloudflare 服务或是一个不存在的域名，实则访问目标网站。

---

## ✨ 核心特性

- **🎯 双模式智能代理**
  - `transparent`：透明透传（TCP 隧道，不解密，性能最优）
  - `mitm`：中间人模式（本地 CA 解密，完全控制 TLS 指纹与 SNI）

- **🧠 可视化规则引擎**  
  按域名精准分流，国内网站直连，仅被封锁的域名走代理。支持 `website` 分组管理、多上游候选、动态变量替换。

- **🔒 深度协议控制**
  - **SNI 策略**：`fake`（伪造）/ `original`（原域名）/ `upstream`（IP 作为 SNI）
  - **uTLS 指纹**：模拟 Chrome 浏览器指纹，防止被动检测
  - **ALPN 控制**：强制 HTTP/1.1 解决 `ERR_HTTP2_PROTOCOL_ERROR`

- **🚀 零基础设施成本**  
  直接连接谷歌中国 Anycast IP 或 目标ip直连，利用其国际骨干网出口，无需 VPS/机场订阅。

---

## 🚀 快速开始

### 1. 下载运行
```bash
# Windows
双击 snishaper.exe

```
默认监听 `127.0.0.1:8080`，管理界面自动打开。

### 2. 安装证书（MITM 模式必需）
```bash
# 程序会自动生成 cert/ca.crt
# 双击安装到"受信任的根证书颁发机构"，重启浏览器
```
> ⚠️ **注意**：证书仅用于本地解密，私钥不会离开你的设备。

### 3. 配置规则
编辑 `config.json`（与程序同目录）：

```json
{
  "sites": [
    {
      "website": "Google 透传",
      "domains": ["*.google.com", "*.youtube.com"],
      "mode": "mitm",
      "upstream": "142.250.185.78:443,142.250.80.46:443",
      "sni_policy": "fake",
      "sni_fake": "www.apple.com",
      "utls_policy": "on"
    },
    {
      "website": "GitHub",
      "domains": ["github.com", "*.github.com"],
      "mode": "mitm",
      "upstream": "20.205.243.166:443",
      "sni_policy": "fake",
      "sni_fake": "www.microsoft.com",
      "utls_policy": "on"
    }
  ]
}
```
也可以用gui规则界面直接修改。
### 4. 启用代理
点击界面"启动代理" → "系统代理：开"，即可访问。

---

## 📋 配置详解

### 核心字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `mode` | `transparent` / `mitm` | 透明透传（不解密）或中间人（解密可控） |
| `upstream` | string | 上游地址，支持多 IP（逗号分隔）如 `ip1:443,ip2:443` |
| `sni_policy` | enum | `fake`: 使用 `sni_fake` 字段伪造；`original`: 原域名；`upstream`: 使用 IP 作为 SNI |
| `sni_fake` | string | 伪造的 SNI，如 `www.microsoft.com`。留空时自动将域名 token 化（`google.com` → `google-com`） |
| `alpn_policy` | enum | `h2_h1`（默认）或 `h1_only`（解决 HTTP/2 兼容问题） |
| `utls_policy` | enum | `on`（模拟 Chrome）/ `off`（Go 默认）/ `auto`（推荐） |



## 🏗️ 工作原理

```
浏览器 → SniShaper(本地 127.0.0.1:8080) → 规则引擎匹配 → [透明/MITM] → 上游
```

**Transparent 模式**  
仅建立 TCP 隧道，利用浏览器 CONNECT。适用于境内有 CDN 节点的目标（如谷歌中国 IP），**无需证书**，性能最优。

**MITM 模式**  
本地终止 TLS（使用动态签发的子证书），重新与上游建立连接时可完全控制：
- 伪造 SNI（声称访问 `apple.com`，实则连接 `google.com`）
- 模拟浏览器 TLS 指纹（uTLS）
- 调整 ALPN（强制 HTTP/1.1 规避协议错误）

---

## ⚠️ 常见问题

**Q: 为什么提示证书错误？**  
A: MITM 模式需要安装 `cert/ca.crt` 到系统根证书，并**完全重启浏览器**（包括后台进程）。

**Q: 国内连接会受影响吗？**  
A: **不会**。只有匹配 `config.json` 规则的域名会进入代理，银行/微信等国内应用默认直连，无证书问题。

**Q: 出现 `ERR_HTTP2_PROTOCOL_ERROR`？**  
A: 将该站点 `alpn_policy` 改为 `h1_only`。

**Q: 需要购买服务器吗？**  
A: **不需要**。`upstream` 填写的是境内 CDN IP（如谷歌中国 `142.250.x.x` 或 Cloudflare 国内节点），流量通过其国际出口转发。

**Q: 支持路由器部署吗？**  
A: 目前为桌面端设计（Wails 框架），核心逻辑可移植到 OpenWrt，并且有相关计划。

---

## 🔒 安全提示

- **本地计算**：所有流量处理在本地完成，无远程服务器参与
- **证书安全**：妥善保管 `cert/` 目录，切勿分享 CA 私钥
- **精准规则**：建议精确配置域名范围，避免不必要的 MITM 解密

---

