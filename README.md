Async SOCKS5 Proxy Manager

High-performance asynchronous SOCKS5 proxy manager and multi-hop circuit router built with Python asyncio.

This tool allows you to aggregate large proxy pools, health-check them, rotate circuits, and expose a local SOCKS5 proxy that routes traffic through multi-hop proxy chains.

Designed for research, network engineering, testing, and distributed traffic routing.

Features
Core Capabilities

Full SOCKS5 server implementation

Supports IPv4 / IPv6 / Domain names

Multi-hop proxy circuits

Per-hop authentication support (RFC1929)

Reliability

Automatic proxy health checks

Failure scoring system

Automatic proxy eviction + cooldown

Latency based proxy ranking

Performance

Fully async I/O (asyncio)

Concurrent health sweeps

Configurable connection timeouts

Idle timeout detection

Operational Features

Proxy score persistence across restarts

Circuit auto-rotation

Structured logging

Rotating log files

Environment variable configuration

Safety

Hard client limit (MAX_CLIENTS)

Idle connection cleanup

Graceful shutdown handling

Robust timeout controls

Architecture
Client Application
       │
       ▼
Local SOCKS5 Proxy
(proxy_manager.py)
       │
       ▼
Multi-Hop Circuit

Client
   │
   ▼
Proxy A
   │
   ▼
Proxy B
   │
   ▼
Proxy C
   │
   ▼
Destination Server

The tool dynamically selects healthy proxies and builds circuits like:

Client → Local SOCKS5 → Proxy1 → Proxy2 → Proxy3 → Target
Requirements
Python
Python >= 3.10

Tested with

Python 3.10
Python 3.11
Python 3.12
Install dependencies

No external dependencies required.

Uses only Python standard library

asyncio
socket
ipaddress
logging
json
struct
dataclasses
Installation

Clone repository

git clone https://github.com/YOUR_USERNAME/proxy-manager.git

cd proxy-manager

Run:

python3 proxy_manager.py
Usage
1️⃣ Add proxies

Create file

proxy.txt

Example:

1.2.3.4:1080
5.6.7.8:1080
user:pass@10.0.0.5:1080
[2001:db8::1]:1080

Formats supported:

IP:PORT
USER:PASS@IP:PORT
DOMAIN:PORT
2️⃣ Start the proxy manager
python3 proxy_manager.py

Server will listen on:

127.0.0.1:1080
3️⃣ Use the proxy

Configure applications to use:

SOCKS5
127.0.0.1
1080

Examples:

Curl
curl --socks5 127.0.0.1:1080 https://example.com
Proxychains
proxychains curl https://example.com
Browser

Configure SOCKS5 proxy:

127.0.0.1:1080
Configuration

Everything can be configured via environment variables.

Example:

export LOCAL_HOST=127.0.0.1
export LOCAL_PORT=1080
export CIRCUIT_SIZE=3
export MAX_CLIENTS=256
Important settings
Variable	Description
LOCAL_HOST	Local bind address
LOCAL_PORT	SOCKS5 listening port
PROXY_FILE	Proxy list file
SCORE_FILE	Proxy score database
MAX_CLIENTS	Maximum concurrent clients
HEALTH_INTERVAL	Proxy health check interval
ROTATE_INTERVAL	Circuit rotation interval
CIRCUIT_SIZE	Number of hops in circuit
MAX_FAILURES	Proxy failure threshold
Proxy Sources (Open Source)

You can collect proxies from open data sources.

GitHub
https://github.com/TheSpeedX/PROXY-List
https://github.com/clarketm/proxy-list
https://github.com/monosans/proxy-list
https://github.com/ShiftyTR/Proxy-List
https://github.com/mmpx12/proxy-list
APIs
https://proxylist.geonode.com/api/proxy-list
https://pubproxy.com/api/proxy
https://proxyscrape.com/api
Open datasets
https://www.kaggle.com/datasets
https://data.world
https://archive.org
Proxy collectors

You can automatically build proxy lists from:

Shodan
Censys
ZoomEye
FOFA
Where to Integrate Proxy Sources

Add proxy ingestion pipelines here:

proxy.txt

Or extend code to fetch dynamically from:

GitHub proxy lists
Proxy APIs
Public proxy feeds
Tor exit nodes
Research networks
Logging

Logs stored in:

proxy_manager.log

Log rotation enabled.

Example log entry:

2026-03-16 INFO Circuit rotated

Structured JSON logging supported.

Use Cases (Beyond Cybersecurity)

This tool is not limited to security testing.

Network Research

Traffic routing experiments

Distributed Systems

Multi-node request routing

Data Engineering

Large scale data collection pipelines

Internet Measurement

Latency measurement studies

Privacy Research

Network path analysis

CDN testing

Geographic network route simulation

Load distribution

Traffic balancing experiments

Academic Research

Network topology studies

IoT testing

Testing device traffic paths

Reliability Engineering

Network fault tolerance experiments

Security & Responsible Use

This software is intended for:

network research

development

privacy studies

distributed systems experiments

security testing in authorized environments

Disclaimer

This software is provided for educational and research purposes only.

The authors do not encourage or support illegal activity.

Users are responsible for complying with all applicable laws and regulations when using this software.

Misuse of this software for:

unauthorized access

illegal scraping

abusive traffic

network attacks

is strictly discouraged.

The developers assume no liability for misuse of this software.

Performance Notes

Designed to handle:

1000+ proxies
hundreds of concurrent clients
async network workloads

Key design principles:

non-blocking I/O

failure isolation

circuit resilience

connection timeout control

Example Workflow
1. Load proxy pool
2. Health check proxies
3. Score proxies
4. Select best proxies
5. Build multi-hop circuit
6. Accept SOCKS5 clients
7. Forward traffic through circuit
8. Rotate circuits periodically
Future Improvements

Possible enhancements:

automatic proxy scraping

proxy reputation scoring

geo-based proxy selection

Tor integration

Web dashboard

metrics export (Prometheus)

distributed proxy clusters

Contributing

Contributions welcome.

Possible areas:

proxy scraping modules

UI dashboard

circuit optimization

proxy fingerprint detection

License

MIT License
