"""Clash/Mihomo and sing-box serializers for Lumen v32 subscriptions."""
from __future__ import annotations

import json

from config_address import link_hosts
from transports import TRANSPORTS


def _record(uid: str, link: dict, host: str, remark: str, location_id: str = "") -> dict:
    adapter = TRANSPORTS.get(link.get("protocol", "vless-ws"))
    address, sni = link_hosts(link.get("address"), link.get("sni"), host)
    path = f"/xray/{adapter.transport}/{uid}"
    if location_id:
        path += f"?loc={location_id}"
    return {
        "uid": uid,
        "password": str(link.get("xray_password") or uid),
        "protocol": adapter.protocol,
        "transport": adapter.transport,
        "address": address,
        "port": int(link.get("port") or 443),
        "sni": sni,
        "host": host,
        "path": path,
        "remark": remark,
        "fingerprint": link.get("fingerprint") or "chrome",
        "alpn": [
            value.strip()
            for value in str(link.get("alpn") or "").split(",")
            if value.strip()
        ],
        "mode": (link.get("transport_settings") or {}).get("mode", "auto"),
    }


def clash_config(items: list[tuple[str, dict, str, str]], host: str) -> str:
    """Build a compact Mihomo-compatible YAML document.

    Item shape is ``(uuid, link, remark, location_id)``.
    """
    proxies: list[dict] = []
    for uid, link, remark, location_id in items:
        r = _record(uid, link, host, remark, location_id)
        proxy: dict = {
            "name": r["remark"],
            "type": r["protocol"],
            "server": r["address"],
            "port": r["port"],
            "udp": True,
            "tls": True,
            "servername": r["sni"],
            "client-fingerprint": r["fingerprint"],
            "network": r["transport"],
        }
        if r["protocol"] in {"vless", "vmess"}:
            proxy["uuid"] = r["uid"]
        if r["protocol"] == "vless":
            proxy["flow"] = ""
        elif r["protocol"] == "vmess":
            proxy.update({"alterId": 0, "cipher": "auto"})
        else:
            proxy["password"] = r["password"]
        if r["alpn"]:
            proxy["alpn"] = r["alpn"]
        if r["transport"] in {"ws", "httpupgrade"}:
            proxy[f"{r['transport']}-opts"] = {
                "path": r["path"],
                "headers": {"Host": r["host"]},
            }
        else:
            proxy["xhttp-opts"] = {
                "path": r["path"],
                "host": r["host"],
                "mode": r["mode"],
            }
        proxies.append(proxy)

    names = [proxy["name"] for proxy in proxies]
    lines = ["proxies:"]
    for proxy in proxies:
        parts = []
        for key, value in proxy.items():
            parts.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
        lines.append("  - { " + ", ".join(parts) + " }")
    lines += [
        "proxy-groups:",
        "  - name: Lumen",
        "    type: select",
        "    proxies: " + json.dumps(names, ensure_ascii=False),
        "rules:",
        "  - MATCH,Lumen",
    ]
    return "\n".join(lines)


def singbox_config(items: list[tuple[str, dict, str, str]], host: str) -> str:
    outbounds: list[dict] = []
    tags: list[str] = []
    for index, (uid, link, remark, location_id) in enumerate(items):
        r = _record(uid, link, host, remark, location_id)
        tag = f"{remark}-{index + 1}" if remark in tags else remark
        tags.append(tag)
        outbound: dict = {
            "type": r["protocol"],
            "tag": tag,
            "server": r["address"],
            "server_port": r["port"],
            "tls": {
                "enabled": True,
                "server_name": r["sni"],
                "utls": {"enabled": True, "fingerprint": r["fingerprint"]},
            },
            "transport": {
                "type": "http" if r["transport"] == "xhttp" else r["transport"],
                "path": r["path"],
                "headers": {"Host": r["host"]},
            },
        }
        if r["alpn"]:
            outbound["tls"]["alpn"] = r["alpn"]
        if r["protocol"] in {"vless", "vmess"}:
            outbound["uuid"] = r["uid"]
        if r["protocol"] == "vmess":
            outbound.update({"alter_id": 0, "security": "auto"})
        if r["protocol"] == "trojan":
            outbound["password"] = r["password"]
        outbounds.append(outbound)
    payload = {
        "outbounds": [
            {"type": "selector", "tag": "Lumen", "outbounds": [*tags, "direct"]},
            *outbounds,
            {"type": "direct", "tag": "direct"},
        ]
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)