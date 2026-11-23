"""Thin wrappers around Scapy's live capture and pcap reading."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.utils import PcapWriter

logger = logging.getLogger(__name__)

PacketHandler = Callable[[Packet], None]


class CaptureError(RuntimeError):
    """Raised when a capture cannot be started (permissions, bad filter...)."""


def capture_live(
    handler: PacketHandler,
    *,
    interface: str | None = None,
    bpf_filter: str | None = None,
    count: int = 0,
    timeout: float | None = None,
    save_to: Path | None = None,
) -> None:
    """Capture packets from a network interface and pass each to ``handler``.

    Requires root or the CAP_NET_RAW capability. ``count=0`` means unlimited;
    the capture then runs until ``timeout`` expires or the user presses Ctrl+C.
    """
    writer = PcapWriter(str(save_to), append=False, sync=True) if save_to else None

    def on_packet(packet: Packet) -> None:
        if writer is not None:
            writer.write(packet)
        handler(packet)

    logger.info("Starting capture on %s (filter=%r)", interface or "default interface",
                bpf_filter)
    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            count=count,
            timeout=timeout,
            prn=on_packet,
            store=False,  # don't keep every packet in memory
        )
    except PermissionError as exc:
        raise CaptureError(
            "Permission denied: live capture needs root. Try: sudo .venv/bin/python -m sniffer"
        ) from exc
    except OSError as exc:
        raise CaptureError(f"Could not start capture: {exc}") from exc
    except Scapy_Exception as exc:  # e.g. an invalid BPF filter expression
        raise CaptureError(f"Capture failed (filter={bpf_filter!r}): {exc}") from exc
    finally:
        if writer is not None:
            writer.close()
            logger.info("Saved packets to %s", save_to)


def read_pcap(
    path: Path,
    handler: PacketHandler,
    *,
    bpf_filter: str | None = None,
    count: int = 0,
) -> None:
    """Replay a saved .pcap file through ``handler``. Needs no special privileges."""
    if not path.is_file():
        raise CaptureError(f"No such capture file: {path}")
    logger.info("Reading packets from %s", path)
    try:
        sniff(offline=str(path), filter=bpf_filter, count=count, prn=handler, store=False)
    except (OSError, Scapy_Exception) as exc:
        raise CaptureError(f"Could not read {path}: {exc}") from exc
