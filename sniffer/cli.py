"""Command-line entry point: ``python -m sniffer --help``."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from scapy.packet import Packet

from sniffer import __version__
from sniffer.capture import CaptureError, capture_live, read_pcap
from sniffer.formatter import format_layers, format_packet, format_stats, header
from sniffer.parser import parse_packet
from sniffer.stats import CaptureStats
from sniffer.tls import TlsReassembler

logger = logging.getLogger("sniffer")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Capture and analyse network packets.",
        epilog=(
            "examples:\n"
            "  sudo .venv/bin/python -m sniffer -c 20\n"
            "  sudo .venv/bin/python -m sniffer -f 'tcp port 80' --payload\n"
            "  .venv/bin/python -m sniffer -r capture.pcap --layers"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", "--interface",
                        help="interface to listen on (default: Scapy's choice)")
    source.add_argument("-r", "--read", type=Path, metavar="FILE",
                        help="read packets from a .pcap file instead of the network")

    parser.add_argument("-f", "--filter", metavar="BPF",
                        help="BPF filter, e.g. 'tcp', 'udp port 53', 'host 8.8.8.8'")
    parser.add_argument("-c", "--count", type=_non_negative_int, default=0,
                        help="stop after N packets (default: 0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=float, help="stop after N seconds")
    parser.add_argument("-w", "--write", type=Path, metavar="FILE",
                        help="also save captured packets to a .pcap file")
    parser.add_argument("-p", "--payload", action="store_true",
                        help="show a hex dump of each packet's payload")
    parser.add_argument("--payload-bytes", type=_non_negative_int, default=64,
                        help="max payload bytes to dump (default: 64)")
    parser.add_argument("-l", "--layers", action="store_true",
                        help="show each packet's layer stack (Ether > IP > TCP ...)")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return number


def main(argv: list[str] | None = None) -> int:
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args(argv)
    if args.read and (args.write or args.timeout):
        arg_parser.error("--write and --timeout only apply to live capture, not --read")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    stats = CaptureStats()
    tls = TlsReassembler()  # joins TLS handshakes split across TCP segments
    counter = 0

    def handle(raw: Packet) -> None:
        nonlocal counter
        counter += 1
        try:
            info = parse_packet(raw, tls)
        except Exception:  # one malformed packet should never stop the capture
            logger.debug("Failed to parse packet #%d", counter, exc_info=True)
            return
        stats.update(info)
        print(format_packet(counter, info, show_payload=args.payload,
                            payload_bytes=args.payload_bytes))
        if args.layers:
            print(f"{' ' * 7}layers: {format_layers(info)}")

    print(header())
    try:
        if args.read:
            read_pcap(args.read, handle, bpf_filter=args.filter, count=args.count)
        else:
            capture_live(handle, interface=args.interface, bpf_filter=args.filter,
                         count=args.count, timeout=args.timeout, save_to=args.write)
    except CaptureError as exc:
        logger.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    if stats.total_packets:
        print(format_stats(stats))
    else:
        print("No packets captured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
