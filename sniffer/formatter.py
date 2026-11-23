"""Human-readable rendering of packets and capture statistics."""

from __future__ import annotations

import string
from datetime import datetime

from sniffer.models import PacketInfo
from sniffer.stats import CaptureStats

_PRINTABLE = set(string.printable) - set("\t\n\r\x0b\x0c")


def format_packet(index: int, packet: PacketInfo, *, show_payload: bool = False,
                  payload_bytes: int = 64) -> str:
    """Return a one-line summary, optionally followed by a payload hex dump."""
    time_str = datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]
    line = (
        f"{index:>5}  {time_str}  {packet.protocol:<8} "
        f"{packet.source:>28} -> {packet.destination:<28} "
        f"{packet.length:>5}B  {packet.info}"
    )
    if show_payload and packet.payload:
        line += "\n" + hexdump(packet.payload[:payload_bytes], indent=7)
        if len(packet.payload) > payload_bytes:
            line += f"\n{' ' * 7}... {len(packet.payload) - payload_bytes} more bytes"
    return line


def format_layers(packet: PacketInfo) -> str:
    """Show the encapsulation stack, e.g. ``Ethernet > IP > TCP > Raw``."""
    return " > ".join(packet.layers)


def hexdump(data: bytes, *, width: int = 16, indent: int = 0) -> str:
    """Classic offset / hex / ASCII dump, like ``xxd`` or Wireshark."""
    pad = " " * indent
    rows = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text_part = "".join(chr(b) if chr(b) in _PRINTABLE else "." for b in chunk)
        rows.append(f"{pad}{offset:04x}  {hex_part:<{width * 3}} {text_part}")
    return "\n".join(rows)


def header() -> str:
    return (
        f"{'No.':>5}  {'Time':<12}  {'Proto':<8} {'Source':>28}    "
        f"{'Destination':<28} {'Len':>6}  Info\n" + "-" * 120
    )


def format_stats(stats: CaptureStats, *, top: int = 5) -> str:
    """Summarise a capture: totals, protocol mix and busiest conversations."""
    lines = [
        "",
        "=" * 60,
        "Capture summary",
        "=" * 60,
        f"Packets captured : {stats.total_packets}",
        f"Bytes captured   : {stats.total_bytes}",
        f"Duration         : {stats.duration:.2f}s",
        "",
        "Protocols:",
    ]
    for proto, count in stats.protocols.most_common():
        share = 100 * count / stats.total_packets
        lines.append(f"  {proto:<12} {count:>6}  ({share:5.1f}%)")

    if stats.conversations:
        lines += ["", f"Top {top} conversations (by packets):"]
        for (a, b), count in stats.conversations.most_common(top):
            lines.append(f"  {a:>20} <-> {b:<20} {count:>6}")
    return "\n".join(lines)
