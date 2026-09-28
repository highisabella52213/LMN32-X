#!/usr/bin/env python3
"""Lumen v32 protocol registry and Xray configuration contract."""
import asyncio
import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="lumen-v32-transport-")
os.environ["SECRET_KEY"] = "contract-secret"

from transports import TRANSPORTS, TransportValidationError
from xray_core import RuntimeRoute, build_xray_config
import main


async def no_reload():
    return True


main.reload_xray_runtime = no_reload


async def run():
    matrix = [
        f"{protocol}-{transport}"
        for protocol in ("vless", "vmess", "trojan")
        for transport in ("ws", "httpupgrade", "xhttp")
    ]
    capabilities = {row["id"]: row for row in TRANSPORTS.capabilities()}
    assert all(capabilities[item]["available"] for item in matrix)
    assert capabilities["vless-tcp"]["available"] in {True, False}
    try:
        TRANSPORTS.validate("vless-grpc")
    except TransportValidationError:
        pass
    else:
        raise AssertionError("unsupported gRPC was accepted")

    routes = []
    for protocol_id in matrix:
        protocol, transport = protocol_id.split("-", 1)
        uid, link = await main.make_link(
            label=protocol_id,
            remark=protocol_id,
            protocol=protocol_id,
            address="relay.example",
            sni="relay.example",
        )
        uri = main.vless_link_for_link(link, uid, "relay.example")
        assert uri.startswith(protocol + "://"), (protocol_id, uri)
        if protocol == "vmess":
            payload = json.loads(base64.b64decode(uri[8:]))
            assert payload["net"] == transport
            assert payload["path"].startswith(f"/xray/{transport}/{uid}")
        else:
            query = parse_qs(urlsplit(uri).query)
            assert query["type"] == [transport]
            assert query["path"][0].startswith(f"/xray/{transport}/{uid}")
        routes.append(
            RuntimeRoute(
                key=uid + ":",
                user_id=uid,
                password=link["xray_password"],
                protocol=protocol,
                transport=transport,
            )
        )

    config = build_xray_config(routes)
    inbounds = config["inbounds"][1:]
    assert len(inbounds) == 9
    assert {item["protocol"] for item in inbounds} == {"vless", "vmess", "trojan"}
    assert {item["streamSettings"]["network"] for item in inbounds} == {
        "ws",
        "httpupgrade",
        "xhttp",
    }
    assert all(item["listen"] == "127.0.0.1" for item in inbounds)
    print("Lumen v32 transport matrix: 9/9 contract OK")


asyncio.run(run())