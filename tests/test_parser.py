"""Tests use hand-built Scapy packets, so they need no network or root access."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from sniffer.formatter import format_packet, hexdump
from sniffer.parser import parse_packet
from sniffer.stats import CaptureStats


def test_tcp_http_packet():
    pkt = Ether() / IP(src="10.0.0.1", dst="93.184.216.34", ttl=64) / \
        TCP(sport=51000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n")
    info = parse_packet(pkt)

    assert info.protocol == "HTTP"
    assert info.src_ip == "10.0.0.1"
    assert info.dst_ip == "93.184.216.34"
    assert (info.src_port, info.dst_port) == (51000, 80)
    assert info.ttl == 64
    assert info.tcp_flags == "PA"
    assert info.payload.startswith(b"GET /")
    assert info.layers == ("Ethernet", "IP", "TCP", "Raw")
    assert info.source == "10.0.0.1:51000"


def test_unknown_tcp_port_falls_back_to_tcp():
    info = parse_packet(IP() / TCP(sport=40000, dport=40001))
    assert info.protocol == "TCP"


def test_dns_query():
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5555, dport=53) / \
        DNS(rd=1, qd=DNSQR(qname="example.com"))
    info = parse_packet(pkt)
    assert info.protocol == "DNS"
    assert "example.com" in info.info
    assert "query" in info.info


def test_icmp_echo_request():
    info = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8))
    assert info.protocol == "ICMP"
    assert "Echo Request" in info.info
    assert info.src_port is None


def test_arp_request():
    pkt = Ether() / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1")
    info = parse_packet(pkt)
    assert info.protocol == "ARP"
    assert "Who has 192.168.1.1" in info.info


def test_ipv6_endpoint_is_bracketed():
    info = parse_packet(IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=1234, dport=4321))
    assert info.source == "[fe80::1]:1234"


def test_stats_counts_conversations_in_both_directions():
    stats = CaptureStats()
    stats.update(parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP()))
    stats.update(parse_packet(IP(src="2.2.2.2", dst="1.1.1.1") / TCP()))
    assert stats.total_packets == 2
    assert stats.conversations[("1.1.1.1", "2.2.2.2")] == 2


def test_hexdump_shows_ascii():
    dump = hexdump(b"Hi\x00")
    assert "48 69 00" in dump
    assert dump.endswith("Hi.")


def test_format_packet_includes_payload_when_requested():
    info = parse_packet(IP() / UDP(sport=9999, dport=9998) / Raw(b"hello"))
    assert "hello" in format_packet(1, info, show_payload=True)
    assert "hello" not in format_packet(1, info, show_payload=False)
