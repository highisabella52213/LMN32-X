"""Protocol/transport capability registry for Lumen v32.

Railway's public HTTPS edge can carry SideRail's HTTP based transports:
WebSocket, HTTPUpgrade and XHTTP. Each is backed by managed Xray. The legacy
native Raw TCP transport remains deployment-gated behind a Railway TCP Proxy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import raw_tcp
from xray_core import SUPPORTED_PROTOCOLS, SUPPORTED_TRANSPORTS


class TransportValidationError(ValueError):
    pass


class TransportUnavailableError(TransportValidationError):
    pass


def _safe_location_id(value: object) -> str:
    return "".join(c for c in str(value or "") if c.isalnum() or c in "-_")[:24]


@dataclass(frozen=True)
class TransportAdapter:
    id: str
    protocol: str
    transport: str
    label: str
    short_label: str
    description: str
    available: bool = True
    unavailable_reason: str = ""
    default_alpn: str = "http/1.1"

    def availability(self) -> tuple[bool, str]:
        return self.available, self.unavailable_reason

    def require_available(self) -> None:
        available, detail = self.availability()
        if not available:
            raise TransportUnavailableError(
                f"{self.label}: NOT SUPPORTED BY CURRENT RUNTIME. {detail}"
            )

    def validate_settings(self, value: object) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TransportValidationError("transport_settings must be an object")
        allowed = {"mode"} if self.transport == "xhttp" else set()
        unknown = set(value) - allowed
        if unknown:
            raise TransportValidationError(
                f"unsupported {self.transport} settings: {', '.join(sorted(unknown))}"
            )
        result: dict[str, Any] = {}
        if self.transport == "xhttp":
            mode = str(value.get("mode") or "auto").strip().lower()
            if mode not in {"auto", "packet-up", "stream-up", "stream-one"}:
                raise TransportValidationError("invalid XHTTP mode")
            result["mode"] = mode
        return result

    def validate_security(self, value: object) -> str:
        security = str(value if value is not None else "tls").strip().lower()
        if security != "tls":
            raise TransportValidationError(
                f"{self.label} requires security=tls behind Railway"
            )
        return security

    def uri_parameters(
        self,
        *,
        user_id: str,
        transport_host: str,
        location_id: object = None,
        settings: object = None,
    ) -> dict[str, str]:
        self.require_available()
        normalized = self.validate_settings(settings)
        location = _safe_location_id(location_id)
        path = f"/xray/{self.transport}/{user_id}"
        if location:
            path += f"?loc={location}"
        result = {"type": self.transport, "host": transport_host, "path": path}
        if self.transport == "xhttp":
            result["mode"] = normalized.get("mode", "auto")
        if self.transport in {"ws", "httpupgrade"}:
            result["headerType"] = "none"
        return result

    def capability(self) -> dict[str, object]:
        available, detail = self.availability()
        properties = (
            {
                "mode": {
                    "type": "string",
                    "enum": ["auto", "packet-up", "stream-up", "stream-one"],
                    "default": "auto",
                }
            }
            if self.transport == "xhttp"
            else {}
        )
        return {
            "id": self.id,
            "protocol": self.protocol,
            "transport": self.transport,
            "label": self.label,
            "short_label": self.short_label,
            "description": self.description,
            "available": available,
            "status": "VERIFIED — XRAY RUNTIME" if available else "NOT SUPPORTED",
            "detail": "" if available else detail,
            "settings_schema": {
                "type": "object",
                "additional_properties": False,
                "properties": properties,
            },
        }


@dataclass(frozen=True)
class RawTCPAdapter(TransportAdapter):
    def availability(self) -> tuple[bool, str]:
        return raw_tcp.availability()

    def validate_settings(self, value: object) -> dict[str, Any]:
        if value is None or value == {}:
            return {}
        raise TransportValidationError("Raw TCP settings are deployment-managed")

    def uri_parameters(self, **_: object) -> dict[str, str]:
        self.require_available()
        return {"type": raw_tcp.deployment().uri_network}

    def endpoint(
        self,
        *,
        address: object,
        port: object,
        sni: object,
        fallback_host: str,
        location_id: object = None,
    ) -> tuple[str, int, str]:
        if any(str(value or "").strip() for value in (address, sni)):
            raise TransportValidationError("Raw TCP address and SNI are deployment-managed")
        if port not in (None, "", 443):
            raise TransportValidationError("Raw TCP port is assigned by Railway")
        return raw_tcp.deployment().endpoint_for_location(location_id)


class TransportRegistry:
    def __init__(self, adapters: tuple[TransportAdapter, ...]) -> None:
        self._ordered = adapters
        self._adapters = {adapter.id: adapter for adapter in adapters}

    def get(self, transport_id: object) -> TransportAdapter:
        value = str(transport_id or "").strip().lower()
        adapter = self._adapters.get(value)
        if adapter is None:
            raise TransportValidationError(f"Unknown transport: {value or '(empty)'}")
        return adapter

    def validate(self, transport_id: object, settings: object = None) -> tuple[str, dict]:
        adapter = self.get(transport_id)
        adapter.require_available()
        return adapter.id, adapter.validate_settings(settings)

    def is_available(self, transport_id: object) -> bool:
        try:
            return self.get(transport_id).availability()[0]
        except TransportValidationError:
            return False

    def validate_security(self, transport_id: object, value: object = None) -> str:
        adapter = self.get(transport_id)
        adapter.require_available()
        return adapter.validate_security(value)

    def protocol(self, transport_id: object) -> str:
        return self.get(transport_id).protocol

    def transport(self, transport_id: object) -> str:
        return self.get(transport_id).transport

    def uri_parameters(
        self,
        transport_id: object,
        *,
        user_id: str,
        transport_host: str,
        location_id: object = None,
        settings: object = None,
    ) -> dict[str, str]:
        return self.get(transport_id).uri_parameters(
            user_id=user_id,
            transport_host=transport_host,
            location_id=location_id,
            settings=settings,
        )

    # Compatibility alias for the previous VLESS-only implementation.
    def vless_parameters(
        self,
        transport_id: object,
        *,
        uuid: str,
        transport_host: str,
        location_id: object = None,
        settings: object = None,
    ) -> dict[str, str]:
        return self.uri_parameters(
            transport_id,
            user_id=uuid,
            transport_host=transport_host,
            location_id=location_id,
            settings=settings,
        )

    def capabilities(self) -> list[dict[str, object]]:
        return [adapter.capability() for adapter in self._ordered]

    def endpoint(self, transport_id: object, **kwargs: object):
        adapter = self.get(transport_id)
        endpoint = getattr(adapter, "endpoint", None)
        if endpoint is None:
            return None
        adapter.require_available()
        return endpoint(**kwargs)


_adapters: list[TransportAdapter] = []
for _protocol in SUPPORTED_PROTOCOLS:
    for _transport in SUPPORTED_TRANSPORTS:
        _adapters.append(
            TransportAdapter(
                id=f"{_protocol}-{_transport}",
                protocol=_protocol,
                transport=_transport,
                label=f"{_protocol.upper()} / {'HTTPUpgrade' if _transport == 'httpupgrade' else _transport.upper()}",
                short_label=f"{_protocol.upper()} / {_transport.upper()}",
                description=f"Xray {_protocol.upper()} over {_transport}.",
            )
        )
_adapters.append(
    RawTCPAdapter(
        id="vless-tcp",
        protocol="vless",
        transport="tcp",
        label="VLESS / Raw TCP",
        short_label="VLESS / TCP",
        description="Native TLS Raw TCP through a separately configured Railway TCP Proxy.",
        available=False,
        unavailable_reason="Railway TCP Proxy and TLS deployment are not configured.",
        default_alpn="",
    )
)

TRANSPORTS = TransportRegistry(tuple(_adapters))