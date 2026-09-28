"""Managed Xray data-plane for Lumen v32.

The public Railway HTTPS edge terminates TLS.  Lumen validates the public
per-user path, then bridges the HTTP based transport to a loopback-only Xray
inbound.  Xray remains responsible for VLESS/VMess/Trojan authentication and
for the actual outbound connection.

The design follows SideRail's data-plane model while keeping Lumen's existing
state, subscriptions, quotas, exit proxies, Telegram bot and dashboard.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

logger = logging.getLogger("Lumen.xray")

SUPPORTED_PROTOCOLS = ("vless", "vmess", "trojan")
SUPPORTED_TRANSPORTS = ("ws", "httpupgrade", "xhttp")
XRAY_VERSION = os.environ.get("XRAY_VERSION", "v26.9.9")
XRAY_API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))
XRAY_INBOUND_BASE_PORT = int(os.environ.get("XRAY_INBOUND_BASE_PORT", "21000"))


@dataclass(frozen=True)
class RuntimeRoute:
    """One externally addressable Lumen route and one loopback Xray inbound."""

    key: str
    user_id: str
    password: str
    protocol: str
    transport: str
    port: int = 0
    location_id: str = ""
    outbound_url: str = ""

    @property
    def tag(self) -> str:
        digest = hashlib.sha256(self.key.encode()).hexdigest()[:16]
        return f"lumen-{self.protocol}-{self.transport}-{digest}"

    @property
    def email(self) -> str:
        suffix = f":{self.location_id}" if self.location_id else ""
        return f"{self.user_id}{suffix}"


def split_transport_id(value: object) -> tuple[str, str]:
    raw = str(value or "").strip().lower()
    try:
        protocol, transport = raw.split("-", 1)
    except ValueError as exc:
        raise ValueError(f"invalid protocol/transport identifier: {raw}") from exc
    if protocol not in SUPPORTED_PROTOCOLS or transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"unsupported Xray route: {raw}")
    return protocol, transport


def _stream_settings(transport: str) -> dict:
    base: dict = {"network": transport}
    if transport == "ws":
        base["wsSettings"] = {"path": "/lumen", "host": ""}
    elif transport == "httpupgrade":
        base["httpupgradeSettings"] = {"path": "/lumen", "host": ""}
    elif transport == "xhttp":
        base["xhttpSettings"] = {"path": "/lumen", "host": "", "mode": "auto"}
    return base


def _protocol_settings(route: RuntimeRoute) -> dict:
    if route.protocol == "vless":
        return {
            "clients": [{"id": route.user_id, "email": route.email, "flow": ""}],
            "decryption": "none",
        }
    if route.protocol == "vmess":
        return {"clients": [{"id": route.user_id, "email": route.email}]}
    return {
        "clients": [{"password": route.password, "email": route.email}],
        "fallbacks": [],
    }


def _proxy_outbound(url: str, tag: str) -> dict:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5"} or not parsed.hostname or not parsed.port:
        raise ValueError("Xray exit proxy must be http, https, or socks5")
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    server: dict = {"address": parsed.hostname, "port": parsed.port}
    if user or password:
        server["users"] = [{"user": user, "pass": password}]
    outbound: dict = {
        "tag": tag,
        "protocol": "socks" if scheme == "socks5" else "http",
        "settings": {"servers": [server]},
    }
    # An https:// repository entry means TLS to the proxy.  Plain HTTP CONNECT
    # remains the default for http:// entries.
    if scheme == "https":
        outbound["streamSettings"] = {
            "security": "tls",
            "tlsSettings": {"allowInsecure": True},
        }
    return outbound


def build_xray_config(routes: list[RuntimeRoute], routing_rules: list[dict] | None = None) -> dict:
    """Build a complete, loopback-only Xray configuration."""
    assigned: list[RuntimeRoute] = []
    for offset, route in enumerate(sorted(routes, key=lambda item: item.key)):
        assigned.append(
            RuntimeRoute(**{**route.__dict__, "port": XRAY_INBOUND_BASE_PORT + offset})
        )

    inbounds = [
        {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": XRAY_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        }
    ]
    outbounds: list[dict] = [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    ]
    rules: list[dict] = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]

    proxy_tags: dict[str, str] = {}
    for route in assigned:
        inbounds.append(
            {
                "tag": route.tag,
                "listen": "127.0.0.1",
                "port": route.port,
                "protocol": route.protocol,
                "settings": _protocol_settings(route),
                "streamSettings": _stream_settings(route.transport),
                "sniffing": {"enabled": False, "destOverride": []},
            }
        )
        outbound_tag = "direct"
        if route.outbound_url:
            outbound_tag = proxy_tags.get(route.outbound_url, "")
            if not outbound_tag:
                outbound_tag = "proxy-" + hashlib.sha256(
                    route.outbound_url.encode()
                ).hexdigest()[:16]
                outbounds.append(_proxy_outbound(route.outbound_url, outbound_tag))
                proxy_tags[route.outbound_url] = outbound_tag
        rules.append(
            {
                "type": "field",
                "inboundTag": [route.tag],
                "outboundTag": outbound_tag,
            }
        )

    for rule in routing_rules or []:
        values = rule.get("values")
        if not isinstance(values, list) or not values:
            continue
        item = {"type": "field", "outboundTag": "blocked"}
        item["ip" if rule.get("kind") == "ip" else "domain"] = [
            str(value).strip() for value in values if str(value).strip()
        ]
        if item.get("ip") or item.get("domain"):
            rules.insert(1, item)

    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


class XrayManager:
    def __init__(self) -> None:
        data_dir = Path(os.environ.get("DATA_DIR", "/data"))
        self.directory = Path(os.environ.get("XRAY_DIR", data_dir / "xray"))
        self.binary = self.directory / ("xray.exe" if os.name == "nt" else "xray")
        self.config_file = self.directory / "config.json"
        self.process: asyncio.subprocess.Process | None = None
        self.routes: dict[str, RuntimeRoute] = {}
        self.error = ""
        self.started_at = 0.0
        self._lock = asyncio.Lock()

    def _asset_name(self) -> str:
        machine = platform.machine().lower()
        if os.name == "nt":
            return "Xray-windows-64.zip"
        if platform.system().lower() == "darwin":
            return "Xray-macos-arm64-v8a.zip" if "arm" in machine else "Xray-macos-64.zip"
        return "Xray-linux-arm64-v8a.zip" if machine in {"arm64", "aarch64"} else "Xray-linux-64.zip"

    def _download_binary(self) -> bool:
        self.directory.mkdir(parents=True, exist_ok=True)
        url = (
            "https://github.com/XTLS/Xray-core/releases/download/"
            f"{XRAY_VERSION}/{self._asset_name()}"
        )
        archive = Path(tempfile.gettempdir()) / f"lumen-xray-{os.getpid()}.zip"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Lumen/32"})
            with urllib.request.urlopen(request, timeout=90) as response, archive.open("wb") as out:
                shutil.copyfileobj(response, out)
            with zipfile.ZipFile(archive) as bundle:
                for name in bundle.namelist():
                    if Path(name).name.lower() == self.binary.name.lower():
                        with bundle.open(name) as source, self.binary.open("wb") as target:
                            shutil.copyfileobj(source, target)
                        break
            if self.binary.exists() and os.name != "nt":
                self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
            return self.binary.exists()
        except Exception as exc:
            self.error = f"Xray download failed: {exc}"
            logger.error(self.error)
            return False
        finally:
            archive.unlink(missing_ok=True)

    async def ensure_binary(self) -> bool:
        configured = os.environ.get("XRAY_BINARY", "").strip()
        if configured:
            self.binary = Path(configured)
        if self.binary.exists() and os.access(self.binary, os.X_OK):
            return True
        return await asyncio.to_thread(self._download_binary)

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.returncode is None

    def endpoint(self, key: str) -> tuple[str, int, str] | None:
        route = self.routes.get(key)
        if route is None or not self.running:
            return None
        return "127.0.0.1", route.port, route.transport

    async def stop(self) -> None:
        process, self.process = self.process, None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    async def reload(
        self, routes: list[RuntimeRoute], routing_rules: list[dict] | None = None
    ) -> bool:
        async with self._lock:
            if not await self.ensure_binary():
                if os.environ.get("XRAY_REQUIRED", "").lower() in {"1", "true", "yes"}:
                    raise RuntimeError(self.error or "Xray binary unavailable")
                return False
            assigned = [
                RuntimeRoute(
                    **{**route.__dict__, "port": XRAY_INBOUND_BASE_PORT + offset}
                )
                for offset, route in enumerate(sorted(routes, key=lambda item: item.key))
            ]
            config = build_xray_config(assigned, routing_rules)
            self.directory.mkdir(parents=True, exist_ok=True)
            # Xray selects the parser from the filename extension. Keep .json
            # on the candidate file or `run -test` treats it as an unknown
            # format and exits without a useful stderr message.
            temp = self.config_file.with_name("config.tmp.json")
            temp.write_text(json.dumps(config, indent=2), encoding="utf-8")
            test = await asyncio.create_subprocess_exec(
                str(self.binary),
                "run",
                "-test",
                "-config",
                str(temp),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await test.communicate()
            if test.returncode:
                detail = (stderr + stdout).decode(errors="replace")[-2000:]
                self.error = "Xray config validation failed: " + detail
                temp.unlink(missing_ok=True)
                logger.error(self.error)
                return False
            temp.replace(self.config_file)
            await self.stop()
            self.process = await asyncio.create_subprocess_exec(
                str(self.binary),
                "run",
                "-config",
                str(self.config_file),
                stdout=asyncio.subprocess.DEVNULL,
                # Runtime warnings can otherwise fill an unread PIPE and stall
                # the data-plane. Configuration errors were already captured
                # by the mandatory `run -test` above.
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(0.15)
            if self.process.returncode is not None:
                self.error = f"Xray failed to start (exit {self.process.returncode})"
                self.process = None
                logger.error(self.error)
                return False
            self.routes = {route.key: route for route in assigned}
            self.error = ""
            self.started_at = asyncio.get_running_loop().time()
            logger.info("Xray %s started with %d routes", XRAY_VERSION, len(assigned))
            return True

    def status(self) -> dict:
        uptime = 0
        if self.running and self.started_at:
            try:
                uptime = int(asyncio.get_running_loop().time() - self.started_at)
            except RuntimeError:
                uptime = 0
        return {
            "running": self.running,
            "version": XRAY_VERSION,
            "routes": len(self.routes),
            "uptime": uptime,
            "error": self.error,
        }


XRAY = XrayManager()