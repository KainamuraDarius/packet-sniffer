"""Tests for TLS/QUIC decoding, using hand-built handshake bytes."""

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from sniffer.parser import parse_packet
from sniffer.tls import (
    HELLO_RETRY_REQUEST_RANDOM,
    TlsReassembler,
    describe_quic,
    describe_tls,
)


def _vec(data: bytes, length_bytes: int) -> bytes:
    return len(data).to_bytes(length_bytes, "big") + data


def _ext(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + _vec(data, 2)


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + _vec(body, 2)


def client_hello(server_name: str, padding: int = 0) -> bytes:
    """A minimal ClientHello record, optionally padded to force a split."""
    sni = _vec(b"\x00" + _vec(server_name.encode(), 2), 2)
    extensions = _ext(21, b"\x00" * padding) + _ext(0, sni)  # padding, then SNI
    body = (b"\x03\x03" + b"\x11" * 32 + _vec(b"", 1) + _vec(b"\x13\x01", 2)
            + _vec(b"\x00", 1) + _vec(extensions, 2))
    return _record(22, _handshake(1, body))


def server_hello(random: bytes = b"\x22" * 32, tls13: bool = True) -> bytes:
    extensions = _ext(43, b"\x03\x04") if tls13 else b""
    body = b"\x03\x03" + random + _vec(b"", 1) + b"\x13\x01" + b"\x00" + _vec(extensions, 2)
    return _record(22, _handshake(2, body))


def test_client_hello_sni():
    assert describe_tls(client_hello("example.com")) == "TLS ClientHello SNI=example.com"


def test_server_hello_reports_tls13_from_supported_versions():
    assert describe_tls(server_hello()) == "TLS ServerHello TLS 1.3"
    assert describe_tls(server_hello(tls13=False)) == "TLS ServerHello TLS 1.2"


def test_hello_retry_request():
    assert describe_tls(server_hello(HELLO_RETRY_REQUEST_RANDOM)) == "TLS HelloRetryRequest"


def test_application_data_and_multiple_records():
    data = _record(20, b"\x01") + _record(23, b"\xaa" * 40)
    assert describe_tls(data) == "TLS ChangeCipherSpec, ApplicationData (40B encrypted)"


def test_encrypted_handshake_is_not_misread():
    # After ChangeCipherSpec the handshake bytes are ciphertext.
    data = _record(22, b"\x00" * 8 + b"\x5b" * 32)
    assert describe_tls(data) == "TLS Handshake (encrypted)"


def test_non_tls_payload():
    assert describe_tls(b"GET / HTTP/1.1\r\n") is None


def test_split_client_hello_is_reassembled():
    record = client_hello("split.example", padding=1500)
    first, second = record[:1400], record[1400:]
    tls = TlsReassembler()
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443, seq=100,
                                                    flags="A") / Raw(first)
    pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443, seq=1500,
                                                    flags="PA") / Raw(second)

    info1 = parse_packet(pkt1, tls)
    info2 = parse_packet(pkt2, tls)

    assert "ClientHello (split across segments" in info1.info
    assert "SNI=split.example (reassembled from 2 segments)" in info2.info
    # Without a reassembler the second segment is just opaque bytes.
    assert "TLS" not in parse_packet(pkt2).info


def test_reassembler_ignores_out_of_order_segment():
    tls = TlsReassembler()
    record = client_hello("x.example", padding=1500)
    assert tls.feed(("a", 1, "b", 2), 0, record[:1000]) is None
    assert tls.feed(("a", 1, "b", 2), 5000, record[1000:]) is None


def test_tls_on_unknown_port_is_labelled_tls():
    pkt = IP() / TCP(sport=40000, dport=8443, flags="PA") / Raw(client_hello("a.b"))
    assert parse_packet(pkt).protocol == "TLS"


def test_quic_headers():
    assert describe_quic(b"\xc3\x00\x00\x00\x01rest") == "QUIC Initial (v1)"
    assert describe_quic(b"\xe3\x00\x00\x00\x01rest") == "QUIC Handshake (v1)"
    assert describe_quic(b"\x45abc") == "QUIC 1-RTT (short header, encrypted)"
    assert describe_quic(b"") is None


def test_udp_443_is_labelled_quic():
    pkt = IP() / UDP(sport=50000, dport=443) / Raw(b"\xc3\x00\x00\x00\x01" + b"\x00" * 20)
    info = parse_packet(pkt)
    assert info.protocol == "QUIC"
    assert info.info.startswith("QUIC Initial (v1)")


def test_mdns_answer_without_question_shows_name():
    wire = bytes(IP() / UDP(sport=5353, dport=5353) / DNS(qr=1, qd=[], an=DNSRR(rrname="tv.local")))
    info = parse_packet(IP(wire)).info
    assert info == "DNS response tv.local. answers=1"
