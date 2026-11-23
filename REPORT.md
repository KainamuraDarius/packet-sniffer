# Network Packet Sniffer — Project Report

Name: KAINAMURA DARIUS
Course CYBER SECURITY


## 1. Objective

The goal of this project was to build a Python program that captures network
packets and displays what they contain, and to use it to understand how data
flows through a network and how common protocols work. The requirements were:

- Capture live network traffic.
- Analyse captured packets to understand their structure and content.
- Learn how data flows through the network and the basics of protocols.
- Use a library such as `scapy` or `socket` for capturing.
- Display source/destination IPs, protocols and payloads.

## 2. Tools and technologies

| Tool | Purpose |
|---|---|
| Python 3.13 | Programming language |
| Scapy 2.8 | Capturing packets from the network interface and splitting them into layers |
| Debian Linux | Operating system (live capture uses raw sockets, which need root) |
| pytest / ruff | Automated tests and code-style checks |

## 3. Design

The program is a command-line tool split into small modules, each with one job:

| Module | Responsibility |
|---|---|
| `cli.py` | Reads command-line options and runs the capture loop |
| `capture.py` | Live capture with Scapy's `sniff()`, and reading/writing `.pcap` files |
| `parser.py` | Turns each Scapy packet into a simple `PacketInfo` record, layer by layer |
| `tls.py` | Decodes the unencrypted parts of TLS handshakes and QUIC headers |
| `formatter.py` | Prints the packet table, hex dumps and the end-of-capture summary |
| `stats.py` | Counts protocols and conversations |
| `models.py` | The `PacketInfo` data structure |

**How a packet is processed:**

1. Scapy reads a raw frame from the network card (or from a `.pcap` file).
2. `parser.py` walks the layers from the outside in: **Ethernet** (MAC
   addresses) → **IP** (IP addresses, TTL) → **TCP/UDP/ICMP** (ports, flags) →
   **application data** (DNS names, TLS messages, raw payload).
3. The result is printed as one table row, and optionally a hex dump of the
   payload and the full layer stack.
4. When the capture stops, a summary shows packet and byte totals, the mix of
   protocols, and the busiest conversations.

**Main features:**

- Live capture on any interface, with BPF filters (e.g. `udp port 53`), and a
  packet limit (`-c`) or time limit (`-t`).
- Save to and replay from `.pcap` files, which can also be opened in Wireshark.
- Shows source/destination IP and port, protocol, length, TCP flags,
  sequence/acknowledgement numbers, DNS queries and answers, ICMP types and ARP
  requests.
- Hex/ASCII payload dumps (`-p`) and layer stacks (`--layers`).
- TLS handshake decoding: ClientHello with the server name (SNI), ServerHello
  with the negotiated TLS version, and encrypted ApplicationData sizes.
  ClientHellos split across two TCP segments are joined using TCP sequence
  numbers.
- QUIC (HTTP/3) is recognised on UDP port 443, with its header type.
- Errors such as a missing root permission or a bad filter are reported
  clearly, and one malformed packet never stops the capture.

## 4. How to run

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

sudo .venv/bin/python -m sniffer -c 20                  # capture 20 packets
sudo .venv/bin/python -m sniffer -f "udp port 53" -p    # DNS only, with payloads
sudo .venv/bin/python -m sniffer -t 30 -w out.pcap      # 30 seconds, saved to a file
.venv/bin/python -m sniffer -r out.pcap --layers -p     # replay a saved file
.venv/bin/pytest                                        # run the tests
```

## 5. Results: what the capture showed

I captured 30 seconds of traffic on my own computer (694 packets, about
163 KB) while running `ping 8.8.8.8` in another terminal.

> [Insert screenshot: live capture running]

| Protocol | Packets | Share |
|---|---|---|
| HTTPS (TLS over TCP) | 441 | 63.5% |
| QUIC (HTTP/3 over UDP) | 147 | 21.2% |
| ICMP | 60 | 8.6% |
| DNS | 30 | 4.3% |
| Other UDP | 10 | 1.4% |
| ARP | 4 | 0.6% |
| Other TCP | 2 | 0.3% |

> capture summary


### 5.1 The layered structure of a packet

The `--layers` option shows that every packet is built from layers, each one
wrapping the next, as in the OSI/TCP-IP model:

- `Ethernet > IP > ICMP > Raw`: a ping
- `Ethernet > IP > UDP > DNS`: a DNS lookup
- `Ethernet > IP > TCP > Raw`: HTTPS data
- `Ethernet > ARP > Padding`: ARP has no IP layer at all. The padding is added
  because Ethernet frames must be at least 60 bytes long.

> [Insert screenshot: layer stacks]

### 5.2 How a web connection is made, step by step

Following one HTTPS connection in the capture showed the whole sequence:

1. **DNS:** my computer asked the router (`10.200.5.1`) for the IP address of
   the server name and got an answer back. Names were usually asked twice at
   once, most likely once for the IPv4 address (A record) and once for IPv6
   (AAAA).
2. **TCP three-way handshake:** `[S]` (SYN) from my computer, `[SA]` (SYN-ACK)
   from the server, `[A]` (ACK) from my computer. Only after this can data be
   sent.
3. **TLS handshake:** a *ClientHello*, then a *ServerHello*, then
   *ChangeCipherSpec*. The ClientHello in this example was too big for one TCP
   segment, so the program joined two segments to read it.
4. **Encrypted data:** every following record was *ApplicationData*, where only
   the size is visible.
5. **Closing:** another connection showed the four-step teardown: `[FA]` (FIN)
   from one side, ACK, `[FA]` from the other side, and a final ACK.

> [Insert screenshot: handshake / TLS packets]

### 5.3 What encryption hides, and what it doesn't

The content of HTTPS traffic was unreadable: hex dumps of ApplicationData are
random-looking bytes. But some information is still visible to anyone on the
network:

- **Who** is talking to whom (IP addresses and ports), **when**, and **how
  much** data is sent.
- The **website name**, through the SNI field of the ClientHello, which is
  sent before encryption starts.
- The **TLS version**: both TLS 1.2 and TLS 1.3 connections appeared. TLS 1.3
  servers still write "TLS 1.2" in the old version field for compatibility, so
  the program reads the real version from the `supported_versions` extension.

A plaintext example of why encryption matters: a Smart TV on the network was
broadcasting its name and details on UDP port 6537 to every device on the
network, readable by anyone.

### 5.4 ICMP (ping)

Each *Echo Request* to `8.8.8.8` was answered by an *Echo Reply* carrying
exactly the same payload: the server "echoes" the data back. The payload starts
with a timestamp, followed by filler bytes counting upward (`10 11 12 … 37`).
Over 30 pings, the round-trip time was 20 ms at best, 91 ms on average and
223 ms at worst.

> [Insert screenshot: ping packets with payload]

### 5.5 Other observations

- **TCP keepalives:** five idle connections to the same server sent a tiny
  packet about once a second, with a sequence number one less than the last
  acknowledged byte. This checks the connection is still alive without sending
  data.
- **QUIC:** about a fifth of the traffic was QUIC (HTTP/3), which runs over
  UDP instead of TCP. It has its own handshake (`Initial`, `Handshake`
  packets), after which packets use a short, encrypted header (`1-RTT`).
- **ARP:** the router asked "Who has 192.168.1.x? Tell 192.168.1.1" to find
  the MAC address for an IP address on the local network.
- **mDNS:** devices announced themselves to the multicast address
  `224.0.0.251` (for example, Chromecast-type devices looking for
  `_googlecast._tcp.local`).

## 6. Testing

The project has 21 automated tests (`tests/`). They use hand-built packets, so
they don't need root or a network connection. They cover TCP, UDP, DNS, ICMP,
ARP, IPv6, statistics, hex dumps, TLS ClientHello/ServerHello parsing, split
ClientHello reassembly, and QUIC headers. All tests pass, and `ruff` reports no
style issues.

> [Insert screenshot: pytest passing]

## 7. Challenges and limitations

- **Root access:** capturing live traffic needs raw sockets, which only root
  can open. The program detects this and explains how to run it with `sudo`.
  Replaying a saved `.pcap` file needs no special permissions.
- **Encryption:** most traffic is HTTPS or QUIC, so the payload can't be read.
  Only the handshake metadata is decoded.
- **Labelling by port:** protocols like HTTP and HTTPS are guessed from the
  port number, so traffic on unusual ports may be labelled wrongly.
- **Limited reassembly:** only TLS handshake records split across segments are
  joined. Full TCP stream reassembly (as in Wireshark) was out of scope.
- **QUIC:** the server name inside a QUIC Initial packet is also protected, so
  it isn't shown.

## 8. Ethics

Packet sniffing can expose private information such as visited websites, device
names and unencrypted data. I only captured traffic on my own computer and
network. Capturing other people's traffic without permission is illegal in many
countries. For this reason I have not included raw capture files in the
submission.

## 9. Conclusion

The project met all of its requirements: it captures live traffic with Scapy,
shows IP addresses, ports, protocols and payloads, and decodes packets layer by
layer. Using it on real traffic made the theory concrete. I could see the DNS
lookup, TCP handshake, TLS handshake, encrypted data and connection teardown
happen in order, and see how much information is still visible even when the
content itself is encrypted.

## References

- Scapy documentation: https://scapy.readthedocs.io/
- RFC 793 / RFC 9293: Transmission Control Protocol
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 1035: Domain Names — Implementation and Specification
