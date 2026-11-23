"""Aggregate statistics that show how traffic flows over a capture."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sniffer.models import PacketInfo


@dataclass
class CaptureStats:
    total_packets: int = 0
    total_bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    protocols: Counter[str] = field(default_factory=Counter)
    # Conversations are direction-independent: A->B and B->A count together.
    conversations: Counter[tuple[str, str]] = field(default_factory=Counter)

    def update(self, packet: PacketInfo) -> None:
        self.total_packets += 1
        self.total_bytes += packet.length
        self.protocols[packet.protocol] += 1

        if self.first_seen is None:
            self.first_seen = packet.timestamp
        self.last_seen = packet.timestamp

        if packet.src_ip and packet.dst_ip:
            pair = sorted((packet.src_ip, packet.dst_ip))
            self.conversations[(pair[0], pair[1])] += 1

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen
