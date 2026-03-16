# Async SOCKS5 Proxy Manager

High-performance **asynchronous SOCKS5 proxy manager** and **multi-hop circuit router** built with Python `asyncio`.

This tool aggregates large proxy pools, performs automated health checks, ranks proxies by reliability and latency, and exposes a **local SOCKS5 proxy server** that routes traffic through **multi-hop proxy circuits**.

It is designed for **network engineering, distributed systems research, traffic routing experiments, and large-scale connectivity testing**.

---

# Features

## Core Capabilities

- Full **SOCKS5 server implementation**
- Supports:
  - IPv4
  - IPv6
  - Domain names
- **Multi-hop proxy circuits**
- Per-hop authentication support (**RFC1929**)

---

## Reliability

- Automatic proxy **health checks**
- **Failure scoring system**
- Automatic **proxy eviction + cooldown**
- **Latency-based proxy ranking**

---

## Performance

- Fully **asynchronous I/O** using `asyncio`
- Concurrent proxy health sweeps
- Configurable connection timeouts
- Idle timeout detection

---

## Operational Features

- Proxy **score persistence across restarts**
- Automatic **circuit rotation**
- Structured logging
- Rotating log files
- Environment variable configuration

---

## Safety Controls

- Hard client limit (`MAX_CLIENTS`)
- Idle connection cleanup
- Graceful shutdown handling
- Robust timeout controls

---

# Architecture

```
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
```

The tool dynamically selects healthy proxies and builds circuits such as:

```
Client → Local SOCKS5 → Proxy1 → Proxy2 → Proxy3 → Target
```

---

# Requirements

## Python Version

Python **3.10 or higher**

Tested with:

- Python 3.10
- Python 3.11
- Python 3.12

---

## Dependencies

No external dependencies required.

Uses only the **Python standard library**:

```
asyncio
socket
ipaddress
logging
json
struct
dataclasses
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/hackersclub29/Proxy-Chaining.git
```

Enter the directory:

```bash
cd Proxy-Chaining
```

Run the server:

```bash
python3 proxy_manager.py
```

---

# Usage

## 1. Add Proxies

Create a file:

```
proxy.txt
```

Example content:

```
1.2.3.4:1080
5.6.7.8:1080
user:pass@10.0.0.5:1080
[2001:db8::1]:1080
```

Supported formats:

```
IP:PORT
USER:PASS@IP:PORT
DOMAIN:PORT
IPv6
```

---

## 2. Start the Proxy Manager

```bash
python3 proxy_manager.py
```

Server listens on:

```
127.0.0.1:1080
```

---

## 3. Use the Proxy

Configure applications to use:

```
SOCKS5
127.0.0.1
1080
```

---

## Example: curl

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

---

## Example: Proxychains

```bash
proxychains curl https://example.com
```

---

## Browser Configuration

Set SOCKS5 proxy:

```
127.0.0.1
1080
```

---

# Configuration

Configuration is handled through **environment variables**.

Example:

```bash
export LOCAL_HOST=127.0.0.1
export LOCAL_PORT=1080
export CIRCUIT_SIZE=3
export MAX_CLIENTS=256
```

---

# Important Settings

| Variable | Description |
|--------|-------------|
| LOCAL_HOST | Local bind address |
| LOCAL_PORT | SOCKS5 listening port |
| PROXY_FILE | Proxy list file |
| SCORE_FILE | Proxy score database |
| MAX_CLIENTS | Maximum concurrent clients |
| HEALTH_INTERVAL | Proxy health check interval |
| ROTATE_INTERVAL | Circuit rotation interval |
| CIRCUIT_SIZE | Number of hops in circuit |
| MAX_FAILURES | Proxy failure threshold |

---

# Proxy Sources (Open Source)

You can collect proxies from **public datasets and open repositories**.

## GitHub Lists

```
https://github.com/TheSpeedX/PROXY-List
https://github.com/clarketm/proxy-list
https://github.com/monosans/proxy-list
https://github.com/ShiftyTR/Proxy-List
https://github.com/mmpx12/proxy-list
```

---

## Proxy APIs

```
https://proxylist.geonode.com/api/proxy-list
https://pubproxy.com/api/proxy
https://proxyscrape.com/api
```

---

## Open Datasets

```
https://www.kaggle.com/datasets
https://data.world
https://archive.org
```

---

## Network Search Platforms

Proxy discovery may also be performed using:

- Shodan
- Censys
- ZoomEye
- FOFA

---

# Where to Integrate Proxy Sources

You can inject proxies into:

```
proxy.txt
```

Or extend the code to fetch dynamically from:

- GitHub proxy lists
- Proxy APIs
- Public proxy feeds
- Tor exit nodes
- Research networks

---

# Logging

Logs are stored in:

```
proxy_manager.log
```

Log rotation is enabled.

Example log entry:

```
2026-03-16 INFO Circuit rotated
```

Structured **JSON logging** is supported.

---

# Use Cases (Beyond Cybersecurity)

This system can support many research and engineering tasks.

---

## Network Research

- Traffic routing experiments
- Path diversity testing
- Network resilience studies

---

## Distributed Systems

- Multi-node request routing
- Distributed traffic relays
- Failover routing experiments

---

## Data Engineering

- Large-scale data collection pipelines
- Network sampling infrastructure
- Distributed request scheduling

---

## Internet Measurement

- Latency measurement
- Route diversity studies
- CDN behavior analysis

---

## Privacy Research

- Network path analysis
- Traffic anonymization experiments

---

## Infrastructure Testing

- Geographic routing simulation
- Load balancing experiments
- CDN validation

---

## Academic Research

- Network topology studies
- Protocol behavior testing
- IoT traffic routing simulations

---

## Reliability Engineering

- Network fault tolerance testing
- Traffic resilience experiments

---

# Security & Responsible Use

This software is intended for:

- network research
- development environments
- privacy studies
- distributed systems experiments
- authorized security testing

---

# Disclaimer

This software is provided for **educational and research purposes only**.

The authors **do not encourage or support illegal activity**.

Users are responsible for complying with all applicable **laws and regulations** when using this software.

Misuse of this software for:

- unauthorized access
- illegal scraping
- abusive traffic
- network attacks

is strictly discouraged.

The developers assume **no liability for misuse of this software**.

---

# Performance Notes

The system is designed to handle:

- **1000+ proxies**
- **hundreds of concurrent clients**
- large async network workloads

Key design principles:

- non-blocking I/O
- failure isolation
- circuit resilience
- connection timeout control

---

# Example Workflow

1. Load proxy pool
2. Health check proxies
3. Score proxies
4. Select best proxies
5. Build multi-hop circuit
6. Accept SOCKS5 clients
7. Forward traffic through circuit
8. Rotate circuits periodically

---

# Future Improvements

Possible enhancements include:

- automatic proxy scraping
- proxy reputation scoring
- geo-based proxy selection
- Tor integration
- web dashboard
- metrics export (Prometheus)
- distributed proxy clusters

---

# Contributing

Contributions are welcome.

Possible areas of contribution:

- proxy scraping modules
- UI dashboard
- circuit optimization
- proxy fingerprint detection
- monitoring and metrics

---

# License

MIT License
