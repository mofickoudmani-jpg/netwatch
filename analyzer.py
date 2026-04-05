"""
NetWatch — Network Traffic Analysis Engine
Analyzes PCAP files for suspicious traffic patterns, threats, and anomalies.
"""

import struct
import socket
import io
from dataclasses import dataclass, field
from collections import defaultdict
from typing import List, Dict, Optional, Tuple
import ipaddress


# ── Known suspicious / interesting ports ─────────────────────────────────────
PORT_NAMES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPC", 119: "NNTP", 135: "RPC/DCOM", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE/VPN", 514: "Syslog", 587: "SMTP",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6667: "IRC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 119, 143, 389, 514}
DANGEROUS_PORTS = {4444, 1080, 6667, 31337, 12345, 9001, 9050}
SENSITIVE_PORTS = {3389, 5900, 1433, 3306, 5432, 27017, 6379}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class Packet:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    length: int = 0
    flags: int = 0          # TCP flags
    payload: bytes = b""
    timestamp: float = 0.0


@dataclass
class Alert:
    severity: str           # critical / high / medium / low / info
    category: str           # Port Scan / Cleartext Creds / etc.
    description: str
    source: str = ""
    destination: str = ""
    count: int = 1
    evidence: str = ""


@dataclass
class AnalysisResult:
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    top_destinations: List[Tuple[str, int]] = field(default_factory=list)
    port_activity: Dict[int, int] = field(default_factory=dict)
    alerts: List[Alert] = field(default_factory=list)
    connections: List[dict] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"
    summary: str = ""
    timeline: List[dict] = field(default_factory=list)


# ── PCAP Parser (no external dependencies) ────────────────────────────────────

PCAP_GLOBAL_HEADER = 24
PCAP_PACKET_HEADER = 16

def parse_pcap(data: bytes) -> List[Packet]:
    """Parse a PCAP file and return a list of Packet objects."""
    packets = []
    if len(data) < PCAP_GLOBAL_HEADER:
        return packets

    # Read global header
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        return packets  # Not a valid PCAP

    _, _, _, _, _, _, link_type = struct.unpack_from(endian + 'IHHiIII', data, 0)

    offset = PCAP_GLOBAL_HEADER
    while offset + PCAP_PACKET_HEADER <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += PCAP_PACKET_HEADER

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset: offset + incl_len]
        offset += incl_len
        timestamp = ts_sec + ts_usec / 1_000_000

        pkt = _parse_packet(pkt_data, link_type, timestamp, orig_len)
        if pkt:
            packets.append(pkt)

    return packets


def _parse_packet(data: bytes, link_type: int, timestamp: float, orig_len: int) -> Optional[Packet]:
    """Parse a single packet frame."""
    try:
        pkt = Packet(timestamp=timestamp, length=orig_len)

        # Strip link layer
        if link_type == 1:      # Ethernet
            if len(data) < 14:
                return None
            ethertype = struct.unpack_from(">H", data, 12)[0]
            if ethertype == 0x0800:         # IPv4
                ip_data = data[14:]
            elif ethertype == 0x86DD:       # IPv6
                ip_data = data[14:]
                pkt.protocol = "IPv6"
                return _parse_ipv6(ip_data, pkt)
            elif ethertype == 0x0806:       # ARP
                pkt.protocol = "ARP"
                pkt = _parse_arp(data[14:], pkt)
                return pkt
            else:
                return None
        elif link_type == 0:    # Loopback (BSD)
            if len(data) < 4:
                return None
            ip_data = data[4:]
        elif link_type == 101:  # Raw IP
            ip_data = data
        else:
            return None

        return _parse_ipv4(ip_data, pkt)

    except Exception:
        return None


def _parse_ipv4(data: bytes, pkt: Packet) -> Optional[Packet]:
    if len(data) < 20:
        return None
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    pkt.src_ip = src
    pkt.dst_ip = dst
    transport = data[ihl:]

    if proto == 6:      # TCP
        pkt.protocol = "TCP"
        return _parse_tcp(transport, pkt)
    elif proto == 17:   # UDP
        pkt.protocol = "UDP"
        return _parse_udp(transport, pkt)
    elif proto == 1:    # ICMP
        pkt.protocol = "ICMP"
        return pkt
    else:
        pkt.protocol = f"IP/{proto}"
        return pkt


def _parse_ipv6(data: bytes, pkt: Packet) -> Optional[Packet]:
    if len(data) < 40:
        return None
    next_hdr = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    pkt.src_ip = src
    pkt.dst_ip = dst
    transport = data[40:]
    if next_hdr == 6:
        pkt.protocol = "TCP"
        return _parse_tcp(transport, pkt)
    elif next_hdr == 17:
        pkt.protocol = "UDP"
        return _parse_udp(transport, pkt)
    else:
        pkt.protocol = "IPv6"
        return pkt


def _parse_tcp(data: bytes, pkt: Packet) -> Optional[Packet]:
    if len(data) < 20:
        return pkt
    pkt.src_port = struct.unpack_from(">H", data, 0)[0]
    pkt.dst_port = struct.unpack_from(">H", data, 2)[0]
    data_offset = ((data[12] >> 4) & 0xF) * 4
    pkt.flags = data[13]
    pkt.payload = data[data_offset:] if len(data) > data_offset else b""
    return pkt


def _parse_udp(data: bytes, pkt: Packet) -> Optional[Packet]:
    if len(data) < 8:
        return pkt
    pkt.src_port = struct.unpack_from(">H", data, 0)[0]
    pkt.dst_port = struct.unpack_from(">H", data, 2)[0]
    pkt.payload = data[8:]
    return pkt


def _parse_arp(data: bytes, pkt: Packet) -> Packet:
    if len(data) >= 28:
        try:
            pkt.src_ip = socket.inet_ntoa(data[14:18])
            pkt.dst_ip = socket.inet_ntoa(data[24:28])
        except Exception:
            pass
    return pkt


# ── Analysis Engine ───────────────────────────────────────────────────────────

def analyze_packets(packets: List[Packet]) -> AnalysisResult:
    result = AnalysisResult()
    if not packets:
        result.summary = "No packets found in file."
        return result

    result.total_packets = len(packets)
    result.total_bytes = sum(p.length for p in packets)

    timestamps = [p.timestamp for p in packets if p.timestamp > 0]
    if len(timestamps) >= 2:
        result.duration_seconds = round(max(timestamps) - min(timestamps), 2)

    # ── Protocol breakdown ────────────────────────────────────────────────────
    proto_counts = defaultdict(int)
    for p in packets:
        proto_counts[p.protocol or "Unknown"] += 1
    result.protocols = dict(sorted(proto_counts.items(), key=lambda x: -x[1]))

    # ── Top talkers ───────────────────────────────────────────────────────────
    src_bytes = defaultdict(int)
    dst_bytes = defaultdict(int)
    for p in packets:
        if p.src_ip:
            src_bytes[p.src_ip] += p.length
        if p.dst_ip:
            dst_bytes[p.dst_ip] += p.length
    result.top_talkers = sorted(src_bytes.items(), key=lambda x: -x[1])[:10]
    result.top_destinations = sorted(dst_bytes.items(), key=lambda x: -x[1])[:10]

    # ── Port activity ─────────────────────────────────────────────────────────
    port_counts = defaultdict(int)
    for p in packets:
        if p.dst_port:
            port_counts[p.dst_port] += 1
    result.port_activity = dict(sorted(port_counts.items(), key=lambda x: -x[1])[:20])

    # ── Unique connections ────────────────────────────────────────────────────
    conn_map = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for p in packets:
        if p.src_ip and p.dst_ip:
            key = (p.src_ip, p.dst_ip, p.protocol, p.dst_port)
            conn_map[key]["packets"] += 1
            conn_map[key]["bytes"] += p.length
    result.connections = [
        {
            "src": k[0], "dst": k[1], "protocol": k[2],
            "port": k[3], "port_name": PORT_NAMES.get(k[3], ""),
            "packets": v["packets"], "bytes": v["bytes"],
        }
        for k, v in sorted(conn_map.items(), key=lambda x: -x[1]["bytes"])[:50]
    ]

    # ── Run all detections ────────────────────────────────────────────────────
    alerts = []
    alerts += _detect_port_scan(packets)
    alerts += _detect_cleartext(packets)
    alerts += _detect_dangerous_ports(packets)
    alerts += _detect_dns_anomalies(packets)
    alerts += _detect_arp_spoofing(packets)
    alerts += _detect_icmp_flood(packets)
    alerts += _detect_large_transfers(packets)
    alerts += _detect_sensitive_ports(packets)
    alerts += _detect_external_connections(packets)

    result.alerts = sorted(alerts, key=lambda a: _severity_order(a.severity))

    # ── Risk score ────────────────────────────────────────────────────────────
    score = 0
    for a in alerts:
        score += {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}[a.severity]
    result.risk_score = min(100, score)
    result.risk_level, result.summary = _score_to_level(result.risk_score, result.total_packets, len(alerts))

    return result


# ── Detection Functions ───────────────────────────────────────────────────────

def _detect_port_scan(packets: List[Packet]) -> List[Alert]:
    alerts = []
    # SYN packets (flag bit 0x02 set, ACK bit 0x10 not set)
    syn_targets = defaultdict(set)  # src_ip -> set of dst_ports
    for p in packets:
        if p.protocol == "TCP" and (p.flags & 0x02) and not (p.flags & 0x10):
            if p.src_ip and p.dst_port:
                syn_targets[p.src_ip].add(p.dst_port)

    for src, ports in syn_targets.items():
        if len(ports) >= 15:
            alerts.append(Alert(
                severity="critical",
                category="Port Scan Detected",
                description=f"{src} sent SYN packets to {len(ports)} different ports — classic TCP SYN scan pattern. Likely reconnaissance activity.",
                source=src,
                count=len(ports),
                evidence=f"Ports targeted: {', '.join(str(p) for p in sorted(ports)[:10])}{'...' if len(ports) > 10 else ''}",
            ))
        elif len(ports) >= 5:
            alerts.append(Alert(
                severity="high",
                category="Possible Port Scan",
                description=f"{src} probed {len(ports)} ports — may indicate scanning activity.",
                source=src,
                count=len(ports),
                evidence=f"Ports: {', '.join(str(p) for p in sorted(ports))}",
            ))
    return alerts


def _detect_cleartext(packets: List[Packet]) -> List[Alert]:
    alerts = []
    found = defaultdict(int)  # (src, dst, port) -> count

    cred_keywords = [
        b"USER ", b"PASS ", b"Authorization: Basic",
        b"password=", b"passwd=", b"pwd=",
        b"username=", b"user=", b"login=",
    ]

    for p in packets:
        if p.dst_port in CLEARTEXT_PORTS and p.payload:
            for kw in cred_keywords:
                if kw.lower() in p.payload.lower():
                    key = (p.src_ip, p.dst_ip, p.dst_port)
                    found[key] += 1
                    break

    for (src, dst, port), count in found.items():
        proto = PORT_NAMES.get(port, str(port))
        alerts.append(Alert(
            severity="high",
            category="Cleartext Credentials",
            description=f"Credential-like data detected in unencrypted {proto} traffic between {src} → {dst}. Credentials transmitted in plaintext can be intercepted by anyone on the network.",
            source=src,
            destination=dst,
            count=count,
            evidence=f"Protocol: {proto} (port {port}) — use encrypted alternatives (SSH, HTTPS, SFTP)",
        ))
    return alerts


def _detect_dangerous_ports(packets: List[Packet]) -> List[Alert]:
    alerts = []
    seen = defaultdict(set)
    for p in packets:
        if p.dst_port in DANGEROUS_PORTS:
            seen[p.dst_port].add(p.src_ip)

    descriptions = {
        4444: "Metasploit default listener port — common in exploitation frameworks",
        1080: "SOCKS proxy port — often used for traffic tunneling and anonymization",
        6667: "IRC port — historically used by botnets for C2 communication",
        31337: "Elite/leet port — classic backdoor and hacking tool default",
        12345: "Known Trojan/backdoor port",
        9001: "Tor relay port — indicates possible Tor network usage",
        9050: "Tor SOCKS proxy — traffic anonymization through Tor network",
    }

    for port, sources in seen.items():
        alerts.append(Alert(
            severity="critical",
            category="Dangerous Port Activity",
            description=f"Traffic detected on port {port} ({PORT_NAMES.get(port, 'Unknown')}). {descriptions.get(port, 'Known suspicious port.')}",
            source=", ".join(list(sources)[:3]),
            count=len(sources),
            evidence=f"Port {port} — {len(sources)} source IP(s) involved",
        ))
    return alerts


def _detect_dns_anomalies(packets: List[Packet]) -> List[Alert]:
    alerts = []
    dns_sources = defaultdict(int)

    for p in packets:
        if p.protocol == "UDP" and (p.dst_port == 53 or p.src_port == 53):
            if p.src_ip:
                dns_sources[p.src_ip] += 1

    for src, count in dns_sources.items():
        if count > 200:
            alerts.append(Alert(
                severity="high",
                category="DNS Query Flood",
                description=f"{src} generated {count} DNS queries — may indicate DNS tunneling (data exfiltration via DNS), DGA malware (domain generation algorithm), or a misconfigured host.",
                source=src,
                count=count,
                evidence=f"{count} DNS packets from single source",
            ))
        elif count > 80:
            alerts.append(Alert(
                severity="medium",
                category="High DNS Volume",
                description=f"{src} generated {count} DNS queries — elevated but not necessarily malicious. Monitor for patterns.",
                source=src,
                count=count,
                evidence=f"{count} DNS packets",
            ))
    return alerts


def _detect_arp_spoofing(packets: List[Packet]) -> List[Alert]:
    alerts = []
    # Map IP → set of MACs seen (we don't have MAC in our simple parser,
    # so we detect duplicate ARP responses for same IP from different sources)
    arp_ips = defaultdict(set)
    for p in packets:
        if p.protocol == "ARP" and p.src_ip:
            arp_ips[p.dst_ip].add(p.src_ip)

    for ip, sources in arp_ips.items():
        if len(sources) > 1 and ip not in ("0.0.0.0", "255.255.255.255"):
            alerts.append(Alert(
                severity="critical",
                category="ARP Spoofing Detected",
                description=f"Multiple hosts claiming to own IP {ip}: {', '.join(sources)}. ARP spoofing is used for man-in-the-middle attacks — attackers can intercept all traffic destined for the victim IP.",
                source=", ".join(sources),
                destination=ip,
                count=len(sources),
                evidence=f"{len(sources)} different sources for IP {ip}",
            ))
    return alerts


def _detect_icmp_flood(packets: List[Packet]) -> List[Alert]:
    alerts = []
    icmp_counts = defaultdict(int)
    for p in packets:
        if p.protocol == "ICMP" and p.src_ip:
            icmp_counts[p.src_ip] += 1

    for src, count in icmp_counts.items():
        if count > 100:
            alerts.append(Alert(
                severity="high",
                category="ICMP Flood",
                description=f"{src} sent {count} ICMP packets — potential ping flood DoS attack or network reconnaissance using ping sweeps.",
                source=src,
                count=count,
                evidence=f"{count} ICMP packets from {src}",
            ))
    return alerts


def _detect_large_transfers(packets: List[Packet]) -> List[Alert]:
    alerts = []
    transfer_bytes = defaultdict(int)
    for p in packets:
        if p.src_ip and p.dst_ip:
            key = (p.src_ip, p.dst_ip)
            transfer_bytes[key] += p.length

    threshold = 50 * 1024 * 1024  # 50 MB
    warn_threshold = 10 * 1024 * 1024  # 10 MB

    for (src, dst), total in transfer_bytes.items():
        if not _is_private(src) or not _is_private(dst):
            if total > threshold:
                alerts.append(Alert(
                    severity="high",
                    category="Large Data Transfer",
                    description=f"Large transfer of {_fmt_bytes(total)} between {src} → {dst}. Cross-boundary large transfers may indicate data exfiltration.",
                    source=src,
                    destination=dst,
                    evidence=f"{_fmt_bytes(total)} transferred",
                ))
            elif total > warn_threshold:
                alerts.append(Alert(
                    severity="medium",
                    category="Notable Data Transfer",
                    description=f"Transfer of {_fmt_bytes(total)} between {src} → {dst}. Monitor for data exfiltration.",
                    source=src,
                    destination=dst,
                    evidence=f"{_fmt_bytes(total)} transferred",
                ))
    return alerts


def _detect_sensitive_ports(packets: List[Packet]) -> List[Alert]:
    alerts = []
    sensitive_seen = defaultdict(set)
    for p in packets:
        if p.dst_port in SENSITIVE_PORTS and p.src_ip:
            sensitive_seen[p.dst_port].add(p.src_ip)

    for port, sources in sensitive_seen.items():
        name = PORT_NAMES.get(port, str(port))
        alerts.append(Alert(
            severity="medium",
            category="Sensitive Service Access",
            description=f"Access to {name} (port {port}) detected from {len(sources)} source(s). Ensure this service is intentionally exposed and access is authorized.",
            source=", ".join(list(sources)[:3]),
            count=len(sources),
            evidence=f"Port {port} ({name}) — verify access control",
        ))
    return alerts


def _detect_external_connections(packets: List[Packet]) -> List[Alert]:
    alerts = []
    external_conns = defaultdict(set)
    for p in packets:
        if p.src_ip and p.dst_ip:
            if _is_private(p.src_ip) and not _is_private(p.dst_ip):
                external_conns[p.src_ip].add(p.dst_ip)

    for src, dsts in external_conns.items():
        if len(dsts) > 20:
            alerts.append(Alert(
                severity="medium",
                category="High External Connection Count",
                description=f"Internal host {src} connected to {len(dsts)} different external IPs — could indicate beaconing, malware C2 communication, or port scanning.",
                source=src,
                count=len(dsts),
                evidence=f"{len(dsts)} unique external destinations",
            ))
    return alerts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except Exception:
        return False


def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b/1_073_741_824:.1f} GB"
    if b >= 1_048_576:
        return f"{b/1_048_576:.1f} MB"
    if b >= 1024:
        return f"{b/1024:.1f} KB"
    return f"{b} B"


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def _score_to_level(score: int, total_packets: int, alert_count: int) -> Tuple[str, str]:
    if score == 0:
        return "Clean", f"No threats detected across {total_packets:,} packets. Traffic appears normal."
    elif score <= 15:
        return "Low", f"Minor anomalies detected in {total_packets:,} packets. {alert_count} low-priority alert(s)."
    elif score <= 40:
        return "Medium", f"Suspicious activity found in {total_packets:,} packets. {alert_count} alert(s) require investigation."
    elif score <= 70:
        return "High", f"Significant threats detected across {total_packets:,} packets. {alert_count} alert(s) — immediate review recommended."
    else:
        return "Critical", f"Multiple critical threats in {total_packets:,} packets. {alert_count} alert(s) — treat as active incident."


def generate_sample_pcap() -> bytes:
    """Generate a synthetic PCAP file with interesting traffic for demo purposes."""
    import random
    import time

    packets_raw = []
    base_time = int(time.time()) - 300

    def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, flags, payload=b"", t=0):
        # Ethernet header (14 bytes)
        eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
        # IP header (20 bytes)
        total_len = 20 + 20 + len(payload)
        ip = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0, total_len, random.randint(1000, 60000),
                         0, 64, 6, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        # TCP header (20 bytes)
        tcp = struct.pack(">HHIIBBHHH",
                          src_port, dst_port, random.randint(0, 0xFFFFFF), 0,
                          0x50, flags, 8192, 0, 0)
        return eth + ip + tcp + payload, t

    def make_eth_ip_udp(src_ip, dst_ip, src_port, dst_port, payload=b"", t=0):
        eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
        total_len = 20 + 8 + len(payload)
        ip = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0, total_len, random.randint(1000, 60000),
                         0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        udp = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0)
        return eth + ip + udp + payload, t

    def make_eth_ip_icmp(src_ip, dst_ip, t=0):
        eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
        ip = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0, 28, random.randint(1000, 60000),
                         0, 64, 1, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        icmp = struct.pack(">BBHH", 8, 0, 0, 0)
        return eth + ip + icmp, t

    def make_arp(src_ip, dst_ip, t=0):
        eth = b"\xff\xff\xff\xff\xff\xff" + b"\xaa\xbb\xcc\xdd\xee\x01" + b"\x08\x06"
        arp = struct.pack(">HHBBH",
                          1, 0x0800, 6, 4, 1)
        arp += b"\xaa\xbb\xcc\xdd\xee\x01"
        arp += socket.inet_aton(src_ip)
        arp += b"\x00\x00\x00\x00\x00\x00"
        arp += socket.inet_aton(dst_ip)
        return eth + arp, t

    t = base_time

    # Normal HTTPS traffic
    for i in range(60):
        pkt, _ = make_eth_ip_tcp("192.168.1.10", "142.250.80.46", random.randint(40000, 60000), 443, 0x18, b"", t + i)
        packets_raw.append((pkt, t + i))

    # Normal DNS
    for i in range(30):
        pkt, _ = make_eth_ip_udp("192.168.1.10", "8.8.8.8", random.randint(40000, 60000), 53, b"\x00\x01", t + i * 2)
        packets_raw.append((pkt, t + i * 2))

    # PORT SCAN — attacker scanning victim
    for port in [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080, 8443, 27017]:
        pkt, _ = make_eth_ip_tcp("192.168.1.99", "192.168.1.50", random.randint(40000, 60000), port, 0x02, b"", t + 50)
        packets_raw.append((pkt, t + 50))

    # CLEARTEXT FTP credentials
    for _ in range(5):
        pkt, _ = make_eth_ip_tcp("192.168.1.20", "192.168.1.5", random.randint(40000, 60000), 21, 0x18,
                                  b"USER admin\r\nPASS password123\r\n", t + 80)
        packets_raw.append((pkt, t + 80))

    # CLEARTEXT HTTP with credentials
    for _ in range(3):
        pkt, _ = make_eth_ip_tcp("192.168.1.20", "10.0.0.1", random.randint(40000, 60000), 80, 0x18,
                                  b"POST /login HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\nusername=admin&password=secret\r\n",
                                  t + 85)
        packets_raw.append((pkt, t + 85))

    # DANGEROUS PORT — Metasploit
    for i in range(8):
        pkt, _ = make_eth_ip_tcp("192.168.1.99", "192.168.1.50", random.randint(40000, 60000), 4444, 0x02, b"", t + 100 + i)
        packets_raw.append((pkt, t + 100 + i))

    # ICMP flood
    for i in range(120):
        pkt, _ = make_eth_ip_icmp("192.168.1.99", "192.168.1.1", t + 120 + i * 0.1)
        packets_raw.append((pkt, t + 120 + i * 0.1))

    # ARP spoofing — two IPs claiming same address
    pkt1, _ = make_arp("192.168.1.99", "192.168.1.10", t + 150)
    packets_raw.append((pkt1, t + 150))
    # Modify source IP for second ARP
    pkt2_data = list(make_arp("192.168.1.88", "192.168.1.10", t + 151)[0])
    pkt2 = bytes(pkt2_data)
    packets_raw.append((pkt2, t + 151))

    # DNS flood
    for i in range(250):
        pkt, _ = make_eth_ip_udp("192.168.1.77", "8.8.8.8", random.randint(40000, 60000), 53, b"\x00\x01", t + 160 + i * 0.3)
        packets_raw.append((pkt, t + 160 + i * 0.3))

    # RDP access
    for i in range(10):
        pkt, _ = make_eth_ip_tcp("192.168.1.30", "192.168.1.100", random.randint(40000, 60000), 3389, 0x18, b"", t + 200 + i)
        packets_raw.append((pkt, t + 200 + i))

    # Build PCAP
    # Global header
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray(header)

    for raw_pkt, ts in sorted(packets_raw, key=lambda x: x[1]):
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = len(raw_pkt)
        body += struct.pack("<IIII", ts_sec, ts_usec, incl_len, incl_len)
        body += raw_pkt

    return bytes(body)
