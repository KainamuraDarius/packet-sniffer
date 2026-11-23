"""Data structures shared across the sniffer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketInfo:
    """A protocol-agnostic summary of a single captured packet.

    Keeping this separate from Scapy's own packet objects means the display
    and statistics code never has to know about Scapy internals, and it can be
    tested with plain hand-built instances.
    """

    timestamp: float
    length: int
    protocol: str
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    ttl: int | None = None
    tcp_flags: str | None = None
    info: str = ""
    layers: tuple[str, ...] = field(default_factory=tuple)
    payload: bytes = b""

    @property
    def source(self) -> str:
        """Best available source address, with port when one exists."""
        return _endpoint(self.src_ip or self.src_mac, self.src_port)

    @property
    def destination(self) -> str:
        """Best available destination address, with port when one exists."""
        return _endpoint(self.dst_ip or self.dst_mac, self.dst_port)


def _endpoint(address: str | None, port: int | None) -> str:
    if address is None:
        return "?"
    if port is None:
        return address
    # IPv6 addresses contain colons, so bracket them as in URLs.
    if ":" in address and "." not in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"
