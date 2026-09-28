# Lumen v32

## Data plane

- Added managed Xray-core lifecycle with download, executable persistence,
  JSON validation before replacement, loopback-only inbounds and clean
  shutdown.
- Added the complete Railway-compatible SideRail matrix:
  - VLESS: WebSocket, HTTPUpgrade, XHTTP
  - VMess: WebSocket, HTTPUpgrade, XHTTP
  - Trojan: WebSocket, HTTPUpgrade, XHTTP
- Added a dependency-free Node edge that preserves raw HTTP Upgrade streams
  and XHTTP session suffixes before forwarding to Xray.
- Kept the existing deployment-gated VLESS Raw TCP listener.

## Existing Lumen behavior retained

- Per-config quota, expiry, speed and concurrent-IP controls.
- Direct or exact HTTP/HTTPS/SOCKS5 outbound selection, fail-closed.
- Two-location subscription groups and explicit location routing.
- Dashboard, public subscription pages, Telegram store, managed proxy
  repository, updater and Railway persistence.

## Added SideRail capabilities

- Clash/Mihomo and sing-box subscription formats.
- Xray health/status and restart endpoints.
- Domain/IP block rules.
- Backup export/import.
- Daily, weekly and monthly traffic resets.
- Subscription usage headers and update interval.

## Railway limitations

Railway's public HTTPS edge carries HTTP-based transports. gRPC, KCP,
WireGuard, Hysteria and arbitrary public raw TCP are not advertised because
they cannot be made functional through that edge. Raw TCP remains available
only through a separately configured Railway TCP Proxy with application-owned
TLS and explicit SNI mappings.