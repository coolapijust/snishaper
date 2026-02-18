# SniShaper

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)]()

通过透传或本地中间人重写绕过 SNI 阻断的桌面代理工具。

## 核心特性

- 双模式代理
  - `transparent`：透明透传（TCP 隧道，不解密 TLS）
  - `mitm`：中间人模式（本地 CA 解密，控制上游 TLS）
- 可视化规则引擎
  - 支持 `website` 分组
  - 支持多上游候选（逗号分隔）
  - 支持动态上游表达式（如 `$1.gvt1.com:443`）
- MITM 协议控制
  - `sni_policy`：`fake | original | upstream | none`
  - `sni_fake`：可显式指定；`fake` 且留空时自动 token 化（`google.com -> google-com`）
  - `alpn_policy`：`h2_h1 | h1_only`
  - `utls_policy`：`on | off | auto`
- 配置导入导出 + 客户诊断工具（`customer-diagnose.exe`）

## 工作原理

```text
浏览器 -> SniShaper(127.0.0.1:8080) -> 规则命中 -> [transparent/mitm] -> 上游
```

- `transparent`：只做隧道转发，开销低。
- `mitm`：本地终止 TLS 后重建上游 TLS，可控制 SNI/ALPN/uTLS。

## 快速开始

### 1. 启动

运行 `snishaper.exe`，默认监听 `127.0.0.1:8080`。

### 2. 安装证书（MITM 必需）

安装 `cert/ca.crt` 到系统受信任根证书，然后完全重启浏览器。

### 3. 配置规则

编辑与 `snishaper.exe` 同目录的 `config.json`：

```json
{
  "site_groups": [
    {
      "name": "Google",
      "website": "google",
      "domains": ["google.com", "*.google.com"],
      "mode": "mitm",
      "upstream": "8.137.102.117:443",
      "sni_policy": "fake",
      "sni_fake": "g.cn",
      "utls_policy": "on",
      "enabled": true
    }
  ]
}
```

也可直接在 GUI 规则页面新增/编辑。

### 4. 启用代理

在界面点击“启动代理”并打开“系统代理”。

## 配置字段

| 字段 | 说明 |
|---|---|
| `domains` | 域名匹配列表 |
| `website` | 网站分组名（用于 GUI 聚合） |
| `mode` | `transparent` 或 `mitm` |
| `upstream` | 上游地址（单个或逗号分隔多个） |
| `sni_policy` | `fake` / `original` / `upstream` / `none` |
| `sni_fake` | 伪造 SNI |
| `alpn_policy` | `h2_h1` 或 `h1_only` |
| `utls_policy` | `on` / `off` / `auto` |
| `enabled` | 是否启用该规则 |

## 客户诊断工具

可执行文件：`customer-diagnose.exe`

使用方式：

1. 放在和 `snishaper.exe`、`config.json` 同目录。
2. 双击运行，等待报告生成。
3. 收集以下文件反馈：
   - `diag_report_*.txt`
   - `diag_report_*.json`

报告会标出失败阶段（`proxy_connect` / `upstream_tls` 等），用于快速定位“规则问题”还是“链路问题”。

## 常见问题

- 证书错误：MITM 模式必须安装并信任 CA，且浏览器需完全重启。
- `ERR_HTTP2_PROTOCOL_ERROR`：对该站点设置 `alpn_policy=h1_only`。
- 命中规则但不通：优先检查 `upstream` 可达性、`sni_policy` 与 `sni_fake` 是否匹配目标站点。

## 文件说明

- `config.json`：运行时主配置（优先读取可执行文件同目录）
- `cert/`：CA 与签发证书目录
- `snishaper.log`：运行日志
- `customer-diagnose.exe`：客户侧诊断工具
