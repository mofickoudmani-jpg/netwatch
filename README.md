# 🔍 NetWatch — Network Traffic Analysis Engine

> A cybersecurity portfolio project by **Mofic Koudmani**  
> B.A.S. Cybersecurity & Ethical Hacking | Broward College | 2026

---

## Overview

NetWatch is a Python-based network traffic analyzer that parses PCAP capture files and detects malicious activity, suspicious patterns, and security anomalies — with zero external dependencies beyond Flask.

Built to demonstrate practical cybersecurity skills including packet analysis, threat detection, and network forensics — the same skills used daily by SOC analysts and network security engineers.

---

## Features

### Threat Detection
- ✅ **Port Scan Detection** — Identifies TCP SYN scans via flag analysis
- ✅ **Cleartext Credential Detection** — Flags FTP, HTTP, Telnet, and IMAP traffic carrying credentials
- ✅ **Dangerous Port Activity** — Detects Metasploit (4444), IRC C2 (6667), SOCKS (1080), Tor (9050)
- ✅ **ARP Spoofing Detection** — Identifies multiple hosts claiming the same IP (MITM indicator)
- ✅ **ICMP Flood Detection** — Flags potential ping flood DoS attacks
- ✅ **DNS Anomaly Detection** — Detects DNS floods and potential DNS tunneling
- ✅ **Large Data Transfer Alerts** — Flags potential data exfiltration events
- ✅ **Sensitive Service Access** — Monitors RDP, VNC, database, and admin service connections
- ✅ **External Connection Analysis** — Identifies internal hosts with high external connection counts

### Traffic Analysis
- ✅ Protocol breakdown with visual distribution
- ✅ Top talkers by traffic volume
- ✅ Destination port analysis with service identification
- ✅ Connection table with packet and byte counts
- ✅ Risk scoring (0–100) with severity levels
- ✅ Built-in sample PCAP generator for demos

### Technical
- ✅ Pure Python PCAP parser — no external libraries required (no Scapy, no dpkt)
- ✅ Supports libpcap format (Wireshark, tcpdump output)
- ✅ Handles IPv4, IPv6, TCP, UDP, ICMP, ARP
- ✅ Dark-themed responsive web interface

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Packet Parsing | Custom pure-Python PCAP parser |
| Analysis Engine | Heuristic threat detection engine |
| Frontend | HTML5, CSS3, Vanilla JS |
| Protocols | IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS |

---

## Installation & Running

```bash
cd netwatch
pip install -r requirements.txt
python app.py
```

Open: **http://localhost:5001**

---

## Usage

### Option A — Use the Sample PCAP
1. Click **⬇ Download Sample PCAP**
2. Upload the downloaded file
3. Click **⚡ Analyze Traffic**

The sample contains: port scan, ARP spoofing, cleartext FTP credentials, Metasploit traffic, ICMP flood, and DNS flood.

### Option B — Capture Your Own Traffic
```bash
# Using tcpdump (Linux/Mac)
sudo tcpdump -i eth0 -w capture.pcap

# Or use Wireshark on Windows
# File → Save As → Wireshark/tcpdump (.pcap)
```

---

## Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0 | ✅ Clean | Normal traffic |
| 1–15 | 🟡 Low | Monitor |
| 16–40 | 🟠 Medium | Investigate |
| 41–70 | 🔴 High | Immediate review |
| 71–100 | ☠️ Critical | Active incident response |

---

## Project Structure

```
netwatch/
├── app.py          # Flask server & API routes
├── analyzer.py     # PCAP parser + threat detection engine
├── requirements.txt
├── templates/
│   └── index.html  # Frontend UI
└── README.md
```

---

## About the Developer

**Mofic Koudmani** | mofic123@hotmail.com | (954) 249-5068  
B.A.S. Cybersecurity & Ethical Hacking — Broward College (Expected Aug 2026)  
Microsoft AZ-900 Certified | CompTIA Security+ (In Progress)  
Tools: Kali Linux, Wireshark, Metasploit, Nessus  

**GitHub:** [github.com/mofickoudmani-jpg](https://github.com/mofickoudmani-jpg)
