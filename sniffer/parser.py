"""Turn raw Scapy packets into :class:`PacketInfo` summaries.

Packets are layered like an onion: Ethernet (link) wraps IP (network), which
wraps TCP/UDP/ICMP (transport), which wraps the application payload. This
module walks those layers from the outside in and records what it finds.
"""

from __future__ import annotations

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from sniffer.models import PacketInfo
from sniffer.tls import TlsReassembler, describe_quic, describe_tls

# Common well-known ports, used to label application-layer protocols.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    3306: "MySQL",
    5353: "mDNS",
    8080: "HTTP-ALT",
}

ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
}


def parse_packet(packet: Packet, tls: TlsReassembler | None = None) -> PacketInfo:
    """Extract the useful fields from a Scapy packet.

    Never raises on unusual packets: anything unrecognised is reported with
    whatever fields could be read and the protocol name of its top layer.

    Pass the same ``tls`` reassembler for every packet of a capture to decode
    TLS handshakes that TCP split across several segments.
    """
    fields: dict = {
        "timestamp": float(packet.time),
        "length": len(packet),
        "layers": _layer_names(packet),
        "protocol": packet.lastlayer().name,
    }

    if packet.haslayer(Ether):
        fields["src_mac"] = packet[Ether].src
        fields["dst_mac"] = packet[Ether].dst

    if packet.haslayer(ARP):
        fields.update(_parse_arp(packet[ARP]))
        return PacketInfo(**fields)

    if packet.haslayer(IP):
        ip = packet[IP]
        fields.update(src_ip=ip.src, dst_ip=ip.dst, ttl=ip.ttl)
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        fields.update(src_ip=ip6.src, dst_ip=ip6.dst, ttl=ip6.hlim)

    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    fields["payload"] = payload

    if packet.haslayer(TCP):
        fields.update(_parse_tcp(packet[TCP]))
        if payload:
            _add_tls_info(fields, packet[TCP], payload, tls)
    elif packet.haslayer(UDP):
        fields.update(_parse_udp(packet[UDP], payload))
    elif packet.haslayer(ICMP):
        fields.update(_parse_icmp(packet[ICMP]))

    if packet.haslayer(DNS):
        fields["protocol"] = "DNS"
        fields["info"] = _describe_dns(packet[DNS])

    return PacketInfo(**fields)


def _layer_names(packet: Packet) -> tuple[str, ...]:
    names = []
    layer = packet
    while layer:
        names.append(layer.name)
        layer = layer.payload
    return tuple(names)


def _parse_arp(arp: ARP) -> dict:
    operation = "who-has" if arp.op == 1 else "is-at"
    if arp.op == 1:
        info = f"Who has {arp.pdst}? Tell {arp.psrc}"
    else:
        info = f"{arp.psrc} is at {arp.hwsrc}"
    return {
        "protocol": "ARP",
        "src_ip": arp.psrc,
        "dst_ip": arp.pdst,
        "info": f"[{operation}] {info}",
    }


def _parse_tcp(tcp: TCP) -> dict:
    flags = str(tcp.flags)
    return {
        "protocol": _app_protocol(tcp.sport, tcp.dport, default="TCP"),
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "tcp_flags": flags,
        "info": f"[{flags}] seq={tcp.seq} ack={tcp.ack} win={tcp.window}",
    }


def _add_tls_info(fields: dict, tcp: TCP, payload: bytes,
                  tls: TlsReassembler | None) -> None:
    """If the TCP payload carries TLS, replace seq/ack details with what it says."""
    description = None
    if tls is not None:
        flow = (fields.get("src_ip") or "?", tcp.sport, fields.get("dst_ip") or "?", tcp.dport)
        joined = tls.feed(flow, tcp.seq, payload)
        if joined is not None:
            if joined.complete:
                description = (f"{describe_tls(joined.data)} "
                               f"(reassembled from {joined.segments} segments)")
            else:
                description = f"TLS (segment {joined.segments} of a split record)"
    if description is None:
        description = describe_tls(payload)
    if description is None:
        return
    fields["info"] = f"[{fields['tcp_flags']}] {description}"
    if fields["protocol"] == "TCP":  # TLS on a port we don't have a name for
        fields["protocol"] = "TLS"


def _parse_udp(udp: UDP, payload: bytes = b"") -> dict:
    fields = {
        "protocol": _app_protocol(udp.sport, udp.dport, default="UDP"),
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "info": f"len={udp.len}",
    }
    # HTTPS over UDP port 443 is QUIC, the transport underneath HTTP/3.
    if 443 in (udp.sport, udp.dport):
        fields["protocol"] = "QUIC"
        description = describe_quic(payload)
        if description:
            fields["info"] = f"{description} len={udp.len}"
    return fields


def _parse_icmp(icmp: ICMP) -> dict:
    label = ICMP_TYPES.get(icmp.type, f"type={icmp.type}")
    return {"protocol": "ICMP", "info": f"{label} code={icmp.code}"}


def _describe_dns(dns: DNS) -> str:
    if dns.qd:
        query = dns.qd[0].qname.decode(errors="replace")
    elif dns.an:  # mDNS announcements carry answers without a question
        query = dns.an[0].rrname.decode(errors="replace")
    else:
        query = "?"
    kind = "response" if dns.qr else "query"
    answers = f" answers={dns.ancount}" if dns.qr else ""
    return f"DNS {kind} {query}{answers}"


def _app_protocol(sport: int, dport: int, default: str) -> str:
    """Guess the application protocol from the lower well-known port."""
    for port in sorted((sport, dport)):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return default
