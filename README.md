# SniShaper

SniShaper is a desktop proxy tool (Go + Wails) for DPI bypass experiments with two traffic handling modes:

- `transparent`: pure TCP tunnel forwarding.
- `mitm`: TLS interception with local CA + upstream SNI control.

The project is designed for rule-based domain routing and upstream mapping, with a local GUI for runtime control.

## Features

- HTTP proxy with `CONNECT` support.
- Dual mode traffic handling: transparent / MITM.
- Rule-based domain matching (`mitm` and `transparent` rules).
- Upstream mapping and fake-SNI support for MITM scenarios.
- Built-in CA generation and certificate status checks (Windows).
- System proxy enable/disable integration (Windows).
- Wails desktop UI.

## Project Structure

- `main.go`: Wails app bootstrap.
- `app.go`: app bindings and lifecycle hooks.
- `proxy/`: proxy server core and rule manager.
- `cert/`: CA and certificate management.
- `sysproxy/`: Windows system proxy operations.
- `frontend/`: Wails frontend (Vite).
- `rules/`: built-in default rule files.

## Requirements

- Go `1.26+` (per `go.mod`).
- Node.js + npm (for frontend build).
- Wails CLI v2.
- Windows (current system proxy integration implementation).

## Development

Install frontend dependencies:

```powershell
cd frontend
npm install
cd ..
```

Run in development mode:

```powershell
wails dev
```

## Build

Build desktop app:

```powershell
wails build
```

If you only need compile checks:

```powershell
go test ./...
go build ./...
```

## Runtime Notes

- Proxy default listen address: `127.0.0.1:8080`.
- Config file is loaded from executable directory: `config.json`.
- Certificate directory is loaded from executable directory: `cert/`.
- Runtime backend log file: `snishaper.log` (same directory as executable).

## MITM Mode Notes

- MITM requires the current generated CA certificate to be installed and trusted by the system/browser.
- Leaf certs are dynamically generated per-host and cached in memory.
- Upstream SNI uses `sni_fake` when configured.

## Disclaimer

This project is for network research and controlled testing only. Use only where you have authorization and comply with applicable laws and service terms.
