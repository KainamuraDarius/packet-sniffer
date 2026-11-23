# Packet Sniffer

A small command-line tool that captures network packets with
[Scapy](https://scapy.net/) and shows what's inside them: source and
destination addresses, protocols, TCP flags, DNS queries, TLS handshakes,
QUIC packets and payloads.

> **Use it only on networks you own or have permission to monitor.**
> Capturing other people's traffic without consent is illegal in many places.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

Live capture needs root (raw sockets), so run the venv's Python with `sudo`:

```bash
sudo .venv/bin/python -m sniffer -c 20                       # 20 packets, any protocol
sudo .venv/bin/python -m sniffer -f "udp port 53" -p         # DNS only, with payload hex dump
sudo .venv/bin/python -m sniffer -i wlan0 -t 30 -w out.pcap  # 30 s on wlan0, saved to a file
.venv/bin/python -m sniffer -r out.pcap --layers             # replay a file (no root needed)
```

Run `python -m sniffer --help` for every option. Press **Ctrl+C** to stop;
a summary of protocols and the busiest conversations is printed at the end.

Example output:

```
  No.  Time          Proto    Source                     Destination              Len  Info
    1  14:02:11.204  DNS      192.168.1.5:53211  -> 8.8.8.8:53                  71B  DNS query example.com.
    2  14:02:11.231  DNS      8.8.8.8:53         -> 192.168.1.5:53211           87B  DNS response example.com. answers=1
    3  14:02:11.240  HTTPS    192.168.1.5:40122  -> 93.184.216.34:443           74B  [S] seq=... ack=0 win=64240
```

## How it works

Every packet is a stack of layers, each wrapping the next:

| Layer (OSI)      | Example protocols | What this tool reads          |
|------------------|-------------------|-------------------------------|
| 2 – Data link    | Ethernet, ARP     | MAC addresses, ARP requests   |
| 3 – Network      | IPv4, IPv6, ICMP  | IP addresses, TTL, ping types |
| 4 – Transport    | TCP, UDP          | Ports, TCP flags, seq/ack     |
| 7 – Application  | DNS, HTTP, …      | DNS names, raw payload bytes  |

Use `--layers` to see each packet's stack (e.g. `Ethernet > IP > TCP > Raw`).
Watching a TCP connection open shows the three-way handshake: `S`, then `SA`,
then `A`. Most web traffic today is HTTPS, so its payload is encrypted and
appears as unreadable bytes. Plain HTTP or DNS shows readable text.

### HTTPS: what TLS still reveals

The TLS handshake that starts every HTTPS connection is not encrypted, so the
tool decodes it:

```
  5  HTTPS  192.168.1.5:48984 -> 93.184.216.34:443  1454B  [A] TLS ClientHello (split across segments, SNI not in this one)
  6  HTTPS  192.168.1.5:48984 -> 93.184.216.34:443   749B  [PA] TLS ClientHello SNI=example.com (reassembled from 2 segments)
  7  HTTPS  93.184.216.34:443 -> 192.168.1.5:48984   387B  [PA] TLS ServerHello TLS 1.2, NewSessionTicket, ChangeCipherSpec, Handshake (encrypted)
  9  HTTPS  192.168.1.5:48984 -> 93.184.216.34:443   165B  [PA] TLS ApplicationData (94B encrypted)
```

- **ClientHello / ServerHello**: the client and server agree on a TLS version
  and keys. TLS 1.3 servers write `TLS 1.2` in the old version field for
  compatibility; the tool reads the real one from the `supported_versions`
  extension.
- **SNI** (Server Name Indication): the website name the client asks for, sent
  in plain text. When a ClientHello is larger than one TCP segment, the tool
  joins the pieces using TCP sequence numbers before reading it.
- **ApplicationData**: the encrypted content. Only its size is visible.

UDP traffic on port 443 is labelled **QUIC**, the protocol under HTTP/3. Its
first byte shows whether it is a *long header* (connection setup: `Initial`,
`Handshake`) or a *short header* (encrypted data, `1-RTT`).

## Project layout

```
sniffer/
  cli.py        command-line arguments and main loop
  capture.py    live capture and .pcap reading (Scapy wrappers)
  parser.py     Scapy packet -> PacketInfo (layer-by-layer decoding)
  tls.py        TLS handshake / QUIC header decoding and TCP reassembly
  models.py     PacketInfo dataclass
  formatter.py  table rows, hex dumps and the summary
  stats.py      protocol and conversation counters
tests/          unit tests using hand-built packets (no root needed)
```

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
```
