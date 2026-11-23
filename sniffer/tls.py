"""Decode the parts of TLS and QUIC traffic that are *not* encrypted.

HTTPS hides the page contents, but every connection still starts with a
plaintext handshake. From it we can learn which kind of message each packet
carries and, from the ClientHello, which server name (SNI) the client asked
for. After the handshake every record is "ApplicationData": encrypted bytes.

TLS record layout (RFC 8446, section 5.1)::

    +--------------+-----------------+---------------+-------------------+
    | content type | legacy version  | length        | fragment ...      |
    | 1 byte       | 2 bytes (0x0303)| 2 bytes       | `length` bytes    |
    +--------------+-----------------+---------------+-------------------+
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

RECORD_HEADER_LEN = 5

CONTENT_TYPES: dict[int, str] = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
}

HANDSHAKE_TYPES: dict[int, str] = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# SHA-256 of "HelloRetryRequest" (RFC 8446, section 4.1.3).
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_VERSIONS = 43


# --------------------------------------------------------------------------- TLS


def looks_like_tls(data: bytes) -> bool:
    """True if ``data`` starts with a plausible TLS record header."""
    return (
        len(data) >= RECORD_HEADER_LEN
        and data[0] in CONTENT_TYPES
        and data[1] == 0x03
        and data[2] <= 0x04
    )


def describe_tls(data: bytes) -> str | None:
    """Summarise the TLS records at the start of a TCP payload.

    Returns ``None`` if the payload does not start with a TLS record (for
    example, the middle of a large record that began in an earlier segment).
    """
    if not looks_like_tls(data):
        return None

    parts: list[str] = []
    offset = 0
    while offset + RECORD_HEADER_LEN <= len(data):
        content_type = data[offset]
        if content_type not in CONTENT_TYPES:
            break
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        body = data[offset + RECORD_HEADER_LEN:offset + RECORD_HEADER_LEN + length]
        parts.append(_describe_record(content_type, body, length))
        offset += RECORD_HEADER_LEN + length
    return "TLS " + ", ".join(_collapse(parts))


def _describe_record(content_type: int, body: bytes, length: int) -> str:
    if content_type == 22:
        return _describe_handshake(body, length)
    if content_type == 23:
        return f"ApplicationData ({length}B encrypted)"
    return CONTENT_TYPES[content_type]


def _describe_handshake(body: bytes, record_length: int) -> str:
    """Name the handshake message(s) inside one Handshake record."""
    names: list[str] = []
    offset = 0
    while offset + 4 <= len(body):
        msg_type = body[offset]
        msg_length = int.from_bytes(body[offset + 1:offset + 4], "big")
        # After ChangeCipherSpec, handshake messages are encrypted and their
        # first bytes are random-looking: an unknown type or impossible length.
        if msg_type not in HANDSHAKE_TYPES or offset + 4 + msg_length > record_length:
            return "Handshake (encrypted)" if not names else ", ".join(names)
        message = body[offset + 4:offset + 4 + msg_length]
        names.append(_describe_handshake_message(msg_type, message, msg_length))
        offset += 4 + msg_length
    return ", ".join(names) if names else "Handshake"


def _describe_handshake_message(msg_type: int, message: bytes, msg_length: int) -> str:
    name = HANDSHAKE_TYPES[msg_type]
    if msg_type == 1:
        sni = client_hello_sni(message)
        if sni:
            return f"ClientHello SNI={sni}"
        if len(message) < msg_length:
            return "ClientHello (split across segments, SNI not in this one)"
    elif msg_type == 2:
        # A HelloRetryRequest is a ServerHello with this fixed "random" value:
        # the server wants the client to send its ClientHello again.
        if message[2:34] == HELLO_RETRY_REQUEST_RANDOM:
            return "HelloRetryRequest"
        version = server_hello_version(message)
        if version:
            return f"ServerHello {version}"
    return name


def _collapse(parts: list[str]) -> list[str]:
    """Turn repeated neighbours into ``name x3`` to keep the line short."""
    out: list[tuple[str, int]] = []
    for part in parts:
        if out and out[-1][0] == part:
            out[-1] = (part, out[-1][1] + 1)
        else:
            out.append((part, 1))
    return [p if n == 1 else f"{p} x{n}" for p, n in out]


class _Truncated(ValueError):
    """The message ended before the field we were reading."""


class _Reader:
    """Sequential reader over bytes that raises instead of reading past the end."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise _Truncated
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def vector(self, length_bytes: int) -> bytes:
        return self.take(self.uint(length_bytes))


def _extensions(reader: _Reader):
    """Yield ``(type, data)`` for each extension; stops quietly if truncated."""
    try:
        reader.uint(2)  # total extensions length
        while True:
            ext_type = reader.uint(2)
            yield ext_type, reader.vector(2)
    except _Truncated:
        return


def client_hello_sni(message: bytes) -> str | None:
    """Return the Server Name Indication from a ClientHello body, if present."""
    reader = _Reader(message)
    try:
        reader.take(2 + 32)  # legacy_version, random
        reader.vector(1)     # session id
        reader.vector(2)     # cipher suites
        reader.vector(1)     # compression methods
    except _Truncated:
        return None
    for ext_type, ext_data in _extensions(reader):
        if ext_type != _EXT_SERVER_NAME:
            continue
        names = _Reader(ext_data)
        try:
            names.uint(2)  # server_name_list length
            if names.uint(1) == 0:  # name_type 0 = host_name
                return names.vector(2).decode("ascii", errors="replace")
        except _Truncated:
            return None
    return None


def server_hello_version(message: bytes) -> str | None:
    """Return the negotiated TLS version from a ServerHello body.

    TLS 1.3 servers still write 0x0303 (TLS 1.2) in the legacy field for
    compatibility; the real version is in the ``supported_versions`` extension.
    """
    reader = _Reader(message)
    try:
        version = reader.uint(2)
        reader.take(32)    # random
        reader.vector(1)   # session id
        reader.take(2 + 1)  # chosen cipher suite, compression method
    except _Truncated:
        return None
    for ext_type, ext_data in _extensions(reader):
        if ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) == 2:
            version = int.from_bytes(ext_data, "big")
    return TLS_VERSIONS.get(version)


# ---------------------------------------------------------------- reassembly

FlowKey = tuple[str, int, str, int]


@dataclass
class _Pending:
    data: bytearray
    needed: int
    next_seq: int
    segments: int = 1


@dataclass(frozen=True)
class Reassembled:
    """Result of feeding a segment that continues a split TLS record."""

    data: bytes
    segments: int
    complete: bool


class TlsReassembler:
    """Join a TLS handshake record that TCP split across several segments.

    A ClientHello is often bigger than one packet (~1460 bytes of payload), so
    the server name can land in the *second* segment. TCP numbers every byte
    with a sequence number, so a segment whose ``seq`` equals the previous
    segment's ``seq + len`` is the next piece of the same stream.

    Only handshake records are buffered, and memory is bounded.
    """

    def __init__(self, *, max_flows: int = 256, max_bytes: int = 64 * 1024) -> None:
        self.max_flows = max_flows
        self.max_bytes = max_bytes
        self._pending: OrderedDict[FlowKey, _Pending] = OrderedDict()

    def feed(self, flow: FlowKey, seq: int, payload: bytes) -> Reassembled | None:
        """Process one TCP payload.

        Returns a :class:`Reassembled` when ``payload`` continues a record that
        started earlier in this flow, otherwise ``None``.
        """
        pending = self._pending.pop(flow, None)
        if pending is not None and seq == pending.next_seq:
            pending.data += payload
            pending.segments += 1
            pending.next_seq = (seq + len(payload)) & 0xFFFFFFFF
            done = len(pending.data) >= pending.needed or len(pending.data) >= self.max_bytes
            if not done:
                self._store(flow, pending)
            return Reassembled(bytes(pending.data), pending.segments, complete=done)

        # Start buffering if this segment opens a handshake record it can't hold.
        if looks_like_tls(payload) and payload[0] == 22:
            needed = RECORD_HEADER_LEN + int.from_bytes(payload[3:5], "big")
            if needed > len(payload):
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
                self._store(flow, _Pending(bytearray(payload), needed, next_seq))
        return None

    def _store(self, flow: FlowKey, pending: _Pending) -> None:
        self._pending[flow] = pending
        while len(self._pending) > self.max_flows:
            self._pending.popitem(last=False)  # forget the oldest flow


# ---------------------------------------------------------------------- QUIC

# QUIC v1 (RFC 9000) and v2 (RFC 9369) number the long-header types differently.
_QUIC_V1_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
_QUIC_V2_TYPES = {1: "Initial", 2: "0-RTT", 3: "Handshake", 0: "Retry"}
_QUIC_V2 = 0x6B3343CF


def describe_quic(data: bytes) -> str | None:
    """Describe a QUIC packet (HTTP/3 runs over QUIC on UDP port 443).

    The first byte tells the two header forms apart: a *long* header (top bit
    set) is used while the connection is being set up, a *short* header for
    the encrypted data that follows.
    """
    if not data:
        return None
    first = data[0]
    if first & 0x80:
        if len(data) < 5:
            return "QUIC long header"
        version = int.from_bytes(data[1:5], "big")
        if version == 0:
            return "QUIC Version Negotiation"
        packet_type = (first & 0x30) >> 4
        if version == 1:
            return f"QUIC {_QUIC_V1_TYPES[packet_type]} (v1)"
        if version == _QUIC_V2:
            return f"QUIC {_QUIC_V2_TYPES[packet_type]} (v2)"
        return f"QUIC long header (version 0x{version:08x})"
    if first & 0x40:
        return "QUIC 1-RTT (short header, encrypted)"
    return None
