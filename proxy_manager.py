#!/usr/bin/env python3
"""
Production-hardened async SOCKS5 proxy manager.

Features
--------
* Full SOCKS5 server handshake — IPv4, IPv6, domain (ATYP 0x01/0x03/0x04)
* True multi-hop circuit chaining with per-hop auth (RFC 1929)
* asyncio.wait_for on EVERY network operation (connect, read, drain, DNS)
* MAX_CLIENTS semaphore — hard cap on concurrent sessions
* Health sweeps use gather(..., return_exceptions=True) — one bad probe
  never blocks the rest
* Proxy eviction: proxies that exceed MAX_FAILURES are suspended for
  EVICT_COOLDOWN seconds and then re-admitted automatically
* Async DNS resolution with configurable timeout (domain-name proxies)
* _pipe() with idle timeout and half-close awareness
* Strict cleanup — every writer.close() / wait_closed() in all paths
* asyncio.create_task everywhere (no ensure_future)
* All shared state (circuit, scores) under their own asyncio.Lock
* Per-session connection + idle timeouts
* JSON score persistence across restarts (SCORE_FILE)
* Structured logging: JSON-formatted records + rotating file handler
* Full config via environment variables with documented defaults
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import secrets
import signal
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Config  (all overridable via environment variables)
# ─────────────────────────────────────────────────────────────────────────────

def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)

def _env_int(key: str, default: int) -> int:
    return int(os.environ.get(key, default))

def _env_float(key: str, default: float) -> float:
    return float(os.environ.get(key, default))


@dataclass(frozen=True)
class Config:
    # Listener
    local_host:       str   = field(default_factory=lambda: _env("LOCAL_HOST",  "127.0.0.1"))
    local_port:       int   = field(default_factory=lambda: _env_int("LOCAL_PORT", 1080))

    # Files
    proxy_file:       str   = field(default_factory=lambda: _env("PROXY_FILE",  "proxy.txt"))
    score_file:       str   = field(default_factory=lambda: _env("SCORE_FILE",  "proxy_scores.json"))
    log_file:         str   = field(default_factory=lambda: _env("LOG_FILE",    "proxy_manager.log"))

    # Timeouts  (seconds)
    tcp_timeout:      float = field(default_factory=lambda: _env_float("TCP_TIMEOUT",    2.0))
    dns_timeout:      float = field(default_factory=lambda: _env_float("DNS_TIMEOUT",    3.0))
    chain_timeout:    float = field(default_factory=lambda: _env_float("CHAIN_TIMEOUT",  10.0))
    handshake_timeout:float = field(default_factory=lambda: _env_float("HANDSHAKE_TIMEOUT", 5.0))
    drain_timeout:    float = field(default_factory=lambda: _env_float("DRAIN_TIMEOUT",  5.0))
    idle_timeout:     float = field(default_factory=lambda: _env_float("IDLE_TIMEOUT",   120.0))

    # Intervals
    health_interval:  float = field(default_factory=lambda: _env_float("HEALTH_INTERVAL", 30.0))
    rotate_interval:  float = field(default_factory=lambda: _env_float("ROTATE_INTERVAL", 180.0))
    evict_cooldown:   float = field(default_factory=lambda: _env_float("EVICT_COOLDOWN",  120.0))

    # Pool / circuit
    health_concur:    int   = field(default_factory=lambda: _env_int("HEALTH_CONCUR",  20))
    max_clients:      int   = field(default_factory=lambda: _env_int("MAX_CLIENTS",    256))
    max_failures:     int   = field(default_factory=lambda: _env_int("MAX_FAILURES",   5))
    stale_factor:     int   = field(default_factory=lambda: _env_int("STALE_FACTOR",   3))
    circuit_size:     int   = field(default_factory=lambda: _env_int("CIRCUIT_SIZE",   3))
    pool_candidates:  int   = field(default_factory=lambda: _env_int("POOL_CANDIDATES",5))

    # Logging
    log_level_console:str   = field(default_factory=lambda: _env("LOG_LEVEL_CONSOLE", "INFO"))
    log_level_file:   str   = field(default_factory=lambda: _env("LOG_LEVEL_FILE",    "DEBUG"))
    log_json:         bool  = field(default_factory=lambda: _env("LOG_JSON", "0") == "1")


CFG = Config()
_rng = secrets.SystemRandom()


# ─────────────────────────────────────────────────────────────────────────────
# Structured logging
# ─────────────────────────────────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict = {
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        # Copy any extra structured fields attached via logger.info(..., extra={...})
        for key, val in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith("_"):
                doc[key] = val
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


def _build_logger() -> logging.Logger:
    log = logging.getLogger("proxy_manager")
    log.setLevel(logging.DEBUG)
    log.propagate = False

    fmt_cls   = _JsonFormatter if CFG.log_json else logging.Formatter
    plain_fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    formatter = fmt_cls(plain_fmt) if not CFG.log_json else fmt_cls()

    console = logging.StreamHandler()
    console.setLevel(getattr(logging, CFG.log_level_console.upper(), logging.INFO))
    console.setFormatter(formatter)
    log.addHandler(console)

    fh = logging.handlers.RotatingFileHandler(
        CFG.log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(getattr(logging, CFG.log_level_file.upper(), logging.DEBUG))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    return log


_log = _build_logger()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — timed wrappers so every await has an explicit deadline
# ─────────────────────────────────────────────────────────────────────────────

async def _timed_open(host: str, port: int, timeout: float):
    """Open a TCP connection with a hard timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except asyncio.TimeoutError:
        raise ConnectionError(f"TCP connect to {host}:{port} timed out ({timeout}s)")


async def _timed_read_exactly(
    reader: asyncio.StreamReader, n: int, timeout: float
) -> bytes:
    try:
        return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
    except asyncio.TimeoutError:
        raise ConnectionError(f"readexactly({n}) timed out ({timeout}s)")


async def _timed_read(
    reader: asyncio.StreamReader, n: int, timeout: float
) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout=timeout)
    except asyncio.TimeoutError:
        raise ConnectionError(f"read({n}) timed out ({timeout}s)")


async def _timed_drain(writer: asyncio.StreamWriter, timeout: float) -> None:
    try:
        await asyncio.wait_for(writer.drain(), timeout=timeout)
    except asyncio.TimeoutError:
        raise ConnectionError(f"drain timed out ({timeout}s)")


async def _resolve_host(host: str, timeout: float) -> str:
    """
    Resolve a domain name to its first IPv4/IPv6 address with a hard timeout.
    Returns the original string unchanged for bare IP addresses.
    """
    try:
        ipaddress.ip_address(host)
        return host                 # already an IP literal
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        results = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise ConnectionError(f"DNS resolution of {host!r} timed out ({timeout}s)")

    if not results:
        raise ConnectionError(f"DNS resolution of {host!r} returned no results")

    return results[0][4][0]         # first address string


async def _safe_close(writer: Optional[asyncio.StreamWriter]) -> None:
    """Close a StreamWriter silently, always awaiting wait_closed()."""
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Proxy model
# ─────────────────────────────────────────────────────────────────────────────

class Proxy:
    __slots__ = (
        "ip", "port", "username", "password",
        "latency", "failures", "score", "last_check",
        "evicted_until", "_lock",
    )

    def __init__(
        self,
        ip:       str,
        port:     int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.ip            = ip
        self.port          = port
        self.username      = username
        self.password      = password
        self.latency:  Optional[float] = None
        self.failures: int   = 0
        self.score:    float = 9999.0
        self.last_check: float = 0.0
        self.evicted_until: float = 0.0   # epoch; 0 = not evicted
        self._lock = asyncio.Lock()

    # ── Key for score persistence ─────────────────────────────────────────────
    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}"

    # ── Health check ──────────────────────────────────────────────────────────
    async def check(self) -> None:
        """TCP probe; updates score and eviction state under the proxy lock."""
        try:
            start = time.monotonic()
            _, w = await _timed_open(self.ip, self.port, CFG.tcp_timeout)
            elapsed = (time.monotonic() - start) * 1000.0
            await _safe_close(w)

            async with self._lock:
                self.latency  = elapsed
                self.failures = 0
                self.evicted_until = 0.0

        except Exception as exc:
            async with self._lock:
                self.failures += 1
                self.latency   = None
                if self.failures >= CFG.max_failures:
                    self.evicted_until = time.time() + CFG.evict_cooldown
                    _log.warning(
                        "Proxy evicted",
                        extra={
                            "event":   "proxy_evicted",
                            "proxy":   self.key,
                            "failures": self.failures,
                            "until":   self.evicted_until,
                            "reason":  str(exc),
                        },
                    )

        async with self._lock:
            self.last_check = time.time()
            self._calc_score()

    def _calc_score(self) -> None:
        """Recalculate score — must be called while self._lock is held."""
        self.score = (
            9999.0 if self.latency is None
            else self.latency + self.failures * 500.0
        )

    # ── State accessors (no lock needed for simple reads in single thread) ───
    def is_evicted(self) -> bool:
        return time.time() < self.evicted_until

    def is_stale(self) -> bool:
        limit = CFG.health_interval * CFG.stale_factor
        return (time.time() - self.last_check) >= limit

    def is_candidate(self) -> bool:
        return (
            self.latency is not None
            and not self.is_evicted()
            and not self.is_stale()
        )

    def has_auth(self) -> bool:
        return bool(self.username and self.password)

    def __repr__(self) -> str:
        auth = f"{self.username}:***@" if self.has_auth() else ""
        evict = f" [EVICTED]" if self.is_evicted() else ""
        return f"{auth}{self.ip}:{self.port}(score={self.score:.0f}){evict}"


# ─────────────────────────────────────────────────────────────────────────────
# Proxy line parser
# ─────────────────────────────────────────────────────────────────────────────

_PROXY_RE = re.compile(
    r"^(?:(?P<user>[^:@\s]+):(?P<password>[^@\s]+)@)?"   # optional user:pass@
    r"(?P<host>\[[^\]]+\]|[^\[\]:\s]+)"                  # host or [IPv6]
    r":(?P<port>\d{1,5})$"
)


def _parse_proxy_line(raw: str) -> Optional[Proxy]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    m = _PROXY_RE.match(line)
    if not m:
        _log.warning("Unparseable proxy line: %r", line)
        return None
    host = m["host"].strip("[]")
    port = int(m["port"])
    if not (1 <= port <= 65535):
        _log.warning("Invalid port in proxy line: %r", line)
        return None
    # Normalise IP literals; leave domain names as-is
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return Proxy(host, port, username=m["user"], password=m["password"])


# ─────────────────────────────────────────────────────────────────────────────
# Score persistence (JSON)
# ─────────────────────────────────────────────────────────────────────────────

def _load_scores(pool: list[Proxy]) -> None:
    path = Path(CFG.score_file)
    if not path.exists():
        return
    try:
        data: dict = json.loads(path.read_text())
        by_key = {p.key: p for p in pool}
        restored = 0
        for key, rec in data.items():
            if key in by_key:
                p = by_key[key]
                p.latency      = rec.get("latency")
                p.failures     = int(rec.get("failures", 0))
                p.score        = float(rec.get("score",   9999.0))
                p.last_check   = float(rec.get("last_check", 0.0))
                p.evicted_until = float(rec.get("evicted_until", 0.0))
                restored += 1
        _log.info("Restored scores for %d proxies from %s", restored, CFG.score_file)
    except Exception as exc:
        _log.warning("Could not load score file %s: %s", CFG.score_file, exc)


async def _save_scores(pool: list[Proxy]) -> None:
    data = {}
    for p in pool:
        async with p._lock:
            data[p.key] = {
                "latency":       p.latency,
                "failures":      p.failures,
                "score":         p.score,
                "last_check":    p.last_check,
                "evicted_until": p.evicted_until,
            }
    try:
        Path(CFG.score_file).write_text(json.dumps(data, indent=2))
    except Exception as exc:
        _log.warning("Could not save scores: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Proxy pool manager
# ─────────────────────────────────────────────────────────────────────────────

class ProxyManager:
    def __init__(self) -> None:
        self.pool:  list[Proxy] = []
        self._sem = asyncio.Semaphore(CFG.health_concur)

    def load(self) -> None:
        path = Path(CFG.proxy_file)
        if not path.exists():
            _log.error("Proxy file not found: %s", CFG.proxy_file)
            return
        with path.open() as fh:
            for raw in fh:
                p = _parse_proxy_line(raw)
                if p:
                    self.pool.append(p)
        _log.info(
            "Loaded proxies",
            extra={"event": "pool_loaded", "count": len(self.pool), "file": CFG.proxy_file},
        )

    async def _check_one(self, proxy: Proxy) -> None:
        async with self._sem:
            await proxy.check()

    async def health_monitor(self) -> None:
        try:
            while True:
                results = await asyncio.gather(
                    *[self._check_one(p) for p in self.pool],
                    return_exceptions=True,
                )
                # Log any unexpected exceptions that escaped proxy.check()
                for r in results:
                    if isinstance(r, Exception):
                        _log.error("Unexpected health-check exception: %s", r)

                alive    = sum(1 for p in self.pool if p.latency is not None)
                evicted  = sum(1 for p in self.pool if p.is_evicted())
                _log.info(
                    "Health sweep complete",
                    extra={
                        "event":   "health_sweep",
                        "alive":   alive,
                        "evicted": evicted,
                        "total":   len(self.pool),
                    },
                )
                await _save_scores(self.pool)
                await asyncio.sleep(CFG.health_interval)
        except asyncio.CancelledError:
            _log.info("health_monitor shutting down")
            raise

    def best_proxies(self, n: int) -> list[Proxy]:
        candidates = [p for p in self.pool if p.is_candidate()]
        candidates.sort(key=lambda p: p.score)
        return candidates[:n]


# ─────────────────────────────────────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────────────────────────────────────

_manager           = ProxyManager()
_current_circuit:  list[Proxy] = []
_last_good_circuit:list[Proxy] = []
_circuit_lock:     asyncio.Lock          # set in main()
_client_sem:       asyncio.Semaphore     # set in main()
_bg_tasks:         list[asyncio.Task]  = []


# ─────────────────────────────────────────────────────────────────────────────
# SOCKS5 — server side (downstream client → us)
# ─────────────────────────────────────────────────────────────────────────────

async def _s5_server_negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
) -> tuple[str, int]:
    """
    Perform the server-side SOCKS5 handshake with the local downstream client.
    Returns (dest_host, dest_port).
    The success reply is withheld until the upstream tunnel is confirmed live.
    """
    # Greeting
    hdr = await _timed_read_exactly(reader, 2, timeout)
    if hdr[0] != 0x05:
        raise ValueError(f"Not SOCKS5 (version={hdr[0]:#04x})")
    nmethods = hdr[1]
    methods  = await _timed_read_exactly(reader, nmethods, timeout)
    if 0x00 not in methods:
        writer.write(b"\x05\xff")
        await _timed_drain(writer, timeout)
        raise ValueError("Client requires authentication; only no-auth supported")
    writer.write(b"\x05\x00")
    await _timed_drain(writer, timeout)

    # Request
    req  = await _timed_read_exactly(reader, 4, timeout)
    if req[0] != 0x05:
        raise ValueError(f"Bad request version ({req[0]:#04x})")
    cmd, atyp = req[1], req[3]
    if cmd != 0x01:
        writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
        await _timed_drain(writer, timeout)
        raise ValueError(f"Unsupported command {cmd:#04x} (only CONNECT=0x01)")

    if atyp == 0x01:      # IPv4
        raw  = await _timed_read_exactly(reader, 4, timeout)
        host = socket.inet_ntoa(raw)
    elif atyp == 0x03:    # domain name
        dlen = (await _timed_read_exactly(reader, 1, timeout))[0]
        host = (await _timed_read_exactly(reader, dlen, timeout)).decode()
    elif atyp == 0x04:    # IPv6
        raw  = await _timed_read_exactly(reader, 16, timeout)
        host = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        raise ValueError(f"Unknown ATYP {atyp:#04x}")

    port = struct.unpack("!H", await _timed_read_exactly(reader, 2, timeout))[0]
    return host, port


# ─────────────────────────────────────────────────────────────────────────────
# SOCKS5 — client side (us → upstream proxy)
# ─────────────────────────────────────────────────────────────────────────────

async def _s5_client_connect(
    reader:      asyncio.StreamReader,
    writer:      asyncio.StreamWriter,
    proxy:       Proxy,
    target_host: str,
    target_port: int,
    timeout:     float,
) -> None:
    """
    SOCKS5 client handshake on an existing stream.
    Supports no-auth (0x00) and RFC 1929 username/password (0x02).
    Always encodes the target as ATYP 0x03 so the upstream resolves DNS.
    """
    # Method negotiation
    writer.write(b"\x05\x02\x00\x02" if proxy.has_auth() else b"\x05\x01\x00")
    await _timed_drain(writer, timeout)

    resp = await _timed_read_exactly(reader, 2, timeout)
    if resp[0] != 0x05:
        raise ConnectionError(f"Upstream not SOCKS5: {resp!r}")
    chosen = resp[1]
    if chosen == 0xFF:
        raise ConnectionError("Upstream rejected all auth methods")

    # RFC 1929 sub-auth
    if chosen == 0x02:
        if not proxy.has_auth():
            raise ConnectionError("Upstream requires credentials but none configured")
        u = proxy.username.encode()
        p = proxy.password.encode()
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await _timed_drain(writer, timeout)
        ar = await _timed_read_exactly(reader, 2, timeout)
        if ar[1] != 0x00:
            raise ConnectionError(f"Auth rejected: {ar!r}")
    elif chosen != 0x00:
        raise ConnectionError(f"Unknown auth method selected: {chosen:#04x}")

    # CONNECT request
    host_b = target_host.encode()
    writer.write(
        b"\x05\x01\x00\x03"
        + bytes([len(host_b)])
        + host_b
        + struct.pack("!H", target_port)
    )
    await _timed_drain(writer, timeout)

    # Response
    rh = await _timed_read_exactly(reader, 4, timeout)
    if rh[1] != 0x00:
        raise ConnectionError(f"CONNECT failed REP={rh[1]:#04x}")

    atyp = rh[3]
    if atyp == 0x01:
        await _timed_read_exactly(reader, 6,  timeout)
    elif atyp == 0x03:
        dlen = (await _timed_read_exactly(reader, 1, timeout))[0]
        await _timed_read_exactly(reader, dlen + 2, timeout)
    elif atyp == 0x04:
        await _timed_read_exactly(reader, 18, timeout)
    else:
        raise ConnectionError(f"Unknown ATYP in upstream response: {atyp:#04x}")


# ─────────────────────────────────────────────────────────────────────────────
# Circuit builder
# ─────────────────────────────────────────────────────────────────────────────

async def _build_chain_inner(
    circuit:   list[Proxy],
    dest_host: str,
    dest_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    TCP-connect to circuit[0], then extend one SOCKS5 CONNECT per hop:

        TCP → P0(auth?) → P1(auth?) → … → Pn(auth?) → dest

    Each hop is told to CONNECT to the next hop, or to dest on the last leg.
    If a domain-name proxy is encountered, its host is resolved with a timeout
    before the TCP connection is attempted.
    """
    if not circuit:
        raise ValueError("Empty circuit")

    entry = circuit[0]
    resolved_ip = await _resolve_host(entry.ip, CFG.dns_timeout)
    reader, writer = await _timed_open(resolved_ip, entry.port, CFG.tcp_timeout)

    try:
        for i, hop in enumerate(circuit):
            is_last   = (i == len(circuit) - 1)
            next_host = dest_host        if is_last else circuit[i + 1].ip
            next_port = dest_port        if is_last else circuit[i + 1].port
            await _s5_client_connect(
                reader, writer, hop, next_host, next_port, CFG.chain_timeout
            )
    except Exception:
        await _safe_close(writer)
        raise

    return reader, writer


async def _build_chain(
    circuit:   list[Proxy],
    dest_host: str,
    dest_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Wraps _build_chain_inner with a global chain-build deadline."""
    try:
        return await asyncio.wait_for(
            _build_chain_inner(circuit, dest_host, dest_port),
            timeout=CFG.chain_timeout,
        )
    except asyncio.TimeoutError:
        hops = " → ".join(repr(p) for p in circuit)
        raise ConnectionError(
            f"Chain build timed out after {CFG.chain_timeout}s [{hops}]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Bidirectional pipe with idle timeout and half-close awareness
# ─────────────────────────────────────────────────────────────────────────────

async def _pipe(
    src:   asyncio.StreamReader,
    dst:   asyncio.StreamWriter,
    label: str = "",
    idle:  float = 0.0,
) -> None:
    """
    Forward bytes from src to dst until:
      - src signals EOF (half-close: the remote end shut down its write side)
      - an OSError / BrokenPipeError occurs on either end
      - no data arrives within `idle` seconds (idle timeout, 0 = disabled)

    After src is exhausted we call dst.write_eof() if the transport supports
    it so the remote end sees a clean TCP FIN instead of a hard RST.
    """
    _PIPE_CHUNK = 65536
    try:
        while True:
            if idle > 0:
                try:
                    chunk = await asyncio.wait_for(
                        src.read(_PIPE_CHUNK), timeout=idle
                    )
                except asyncio.TimeoutError:
                    _log.debug("pipe%s idle timeout (%.0fs) — closing", label, idle)
                    return
            else:
                chunk = await src.read(_PIPE_CHUNK)

            if not chunk:
                # src half-closed — propagate FIN to dst if possible
                _log.debug("pipe%s EOF from source", label)
                if dst.can_write_eof():
                    try:
                        dst.write_eof()
                        await _timed_drain(dst, CFG.drain_timeout)
                    except OSError:
                        pass
                return

            _log.debug("pipe%s %d bytes", label, len(chunk))
            dst.write(chunk)
            await _timed_drain(dst, CFG.drain_timeout)

    except (
        asyncio.IncompleteReadError,
        ConnectionResetError,
        BrokenPipeError,
        OSError,
    ):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Per-connection handler
# ─────────────────────────────────────────────────────────────────────────────

async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername", "?")

    # ── Enforce MAX_CLIENTS ───────────────────────────────────────────────────
    if not _client_sem._value:      # non-blocking peek — avoid awaiting
        _log.warning(
            "MAX_CLIENTS reached — rejecting %s", peer,
            extra={"event": "client_rejected", "peer": str(peer), "reason": "max_clients"},
        )
        await _safe_close(writer)
        return

    async with _client_sem:
        await _handle_client_inner(reader, writer, peer)


async def _handle_client_inner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    peer:   object,
) -> None:
    upstream_writer: Optional[asyncio.StreamWriter] = None

    try:
        # ── SOCKS5 handshake with downstream client ───────────────────────────
        dest_host, dest_port = await _s5_server_negotiate(
            reader, writer, CFG.handshake_timeout
        )
        _log.info(
            "New CONNECT request",
            extra={
                "event": "connect",
                "peer":  str(peer),
                "dest":  f"{dest_host}:{dest_port}",
            },
        )

        # ── Snapshot circuit under lock ───────────────────────────────────────
        async with _circuit_lock:
            circuit = list(_current_circuit)

        if not circuit:
            _log.warning(
                "No circuit — rejecting %s", peer,
                extra={"event": "connect_rejected", "reason": "no_circuit"},
            )
            writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
            await _timed_drain(writer, CFG.drain_timeout)
            return

        # ── Build the multi-hop tunnel ────────────────────────────────────────
        upstream_reader, upstream_writer = await _build_chain(
            circuit, dest_host, dest_port
        )

        # ── Inform downstream client that the tunnel is ready ─────────────────
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await _timed_drain(writer, CFG.drain_timeout)

        _log.debug("Tunnel established for %s → %s:%d", peer, dest_host, dest_port)

        # ── Relay — both directions concurrently, with idle timeout ───────────
        await asyncio.gather(
            _pipe(upstream_reader, writer,         label="↓", idle=CFG.idle_timeout),
            _pipe(reader,          upstream_writer, label="↑", idle=CFG.idle_timeout),
        )

    except Exception as exc:
        _log.debug(
            "Session error",
            extra={"event": "session_error", "peer": str(peer), "error": str(exc)},
        )
        # Send SOCKS5 general-failure to client if we haven't sent success yet
        try:
            writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
            await _timed_drain(writer, CFG.drain_timeout)
        except OSError:
            pass

        # Penalise the entry proxy under its lock
        async with _circuit_lock:
            if _current_circuit:
                entry = _current_circuit[0]
                async with entry._lock:
                    entry.failures += 1
                    if entry.failures >= CFG.max_failures:
                        entry.evicted_until = time.time() + CFG.evict_cooldown
                    entry._calc_score()
                _log.warning(
                    "Entry proxy penalised",
                    extra={
                        "event":    "proxy_penalised",
                        "proxy":    entry.key,
                        "failures": entry.failures,
                        "evicted":  entry.is_evicted(),
                    },
                )

    finally:
        await _safe_close(upstream_writer)
        await _safe_close(writer)


# ─────────────────────────────────────────────────────────────────────────────
# Circuit rotation
# ─────────────────────────────────────────────────────────────────────────────

async def _rotate_circuit() -> None:
    global _current_circuit, _last_good_circuit
    try:
        while True:
            best = _manager.best_proxies(CFG.pool_candidates)
            async with _circuit_lock:
                if best:
                    size    = min(CFG.circuit_size, len(best))
                    new_c   = _rng.sample(best, size)
                    _current_circuit   = new_c
                    _last_good_circuit = list(new_c)
                    _log.info(
                        "Circuit rotated",
                        extra={
                            "event":   "circuit_rotated",
                            "circuit": [p.key for p in new_c],
                            "scores":  [round(p.score, 1) for p in new_c],
                        },
                    )
                elif _last_good_circuit:
                    _current_circuit = list(_last_good_circuit)
                    _log.warning(
                        "No healthy proxies — retaining last-known-good circuit",
                        extra={
                            "event":   "circuit_fallback",
                            "circuit": [p.key for p in _last_good_circuit],
                        },
                    )
                else:
                    _current_circuit = []
                    _log.error(
                        "No healthy proxies and no fallback — all new connections "
                        "will be rejected",
                        extra={"event": "circuit_empty"},
                    )
            await asyncio.sleep(CFG.rotate_interval)
    except asyncio.CancelledError:
        _log.info("rotate_circuit shutting down")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Graceful shutdown
# ─────────────────────────────────────────────────────────────────────────────

async def _shutdown(server: asyncio.Server) -> None:
    _log.info("Shutdown signal received — draining …")

    # Stop accepting new clients
    server.close()
    await server.wait_closed()

    # Cancel background tasks and wait for them to exit cleanly
    for t in _bg_tasks:
        t.cancel()
    results = await asyncio.gather(*_bg_tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception) and not isinstance(r, asyncio.CancelledError):
            _log.error("Background task error during shutdown: %s", r)

    # Persist final scores
    await _save_scores(_manager.pool)

    _log.info("Shutdown complete")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    global _circuit_lock, _client_sem, _current_circuit, _last_good_circuit

    _circuit_lock = asyncio.Lock()
    _client_sem   = asyncio.Semaphore(CFG.max_clients)

    _log.info(
        "Starting proxy manager",
        extra={
            "event": "startup",
            "config": {
                "local":          f"{CFG.local_host}:{CFG.local_port}",
                "max_clients":    CFG.max_clients,
                "max_failures":   CFG.max_failures,
                "health_concur":  CFG.health_concur,
                "circuit_size":   CFG.circuit_size,
                "idle_timeout":   CFG.idle_timeout,
                "chain_timeout":  CFG.chain_timeout,
                "evict_cooldown": CFG.evict_cooldown,
            },
        },
    )

    _manager.load()
    if not _manager.pool:
        _log.error("No proxies loaded — exiting")
        return

    # Restore persisted scores before the first sweep
    _load_scores(_manager.pool)

    # Initial health sweep — ensures the first circuit is based on live data
    _log.info("Running initial health sweep …")
    results = await asyncio.gather(
        *[_manager._check_one(p) for p in _manager.pool],
        return_exceptions=True,
    )
    for r in results:
        if isinstance(r, Exception):
            _log.error("Initial health-check exception: %s", r)

    # Bootstrap the first circuit
    best = _manager.best_proxies(CFG.pool_candidates)
    async with _circuit_lock:
        if best:
            _current_circuit   = _rng.sample(best, min(CFG.circuit_size, len(best)))
            _last_good_circuit = list(_current_circuit)
            _log.info(
                "Initial circuit selected",
                extra={
                    "event":   "circuit_initial",
                    "circuit": [p.key for p in _current_circuit],
                },
            )
        else:
            _log.warning("No healthy proxies after initial sweep — circuit empty")

    # Background tasks
    _bg_tasks.append(
        asyncio.create_task(_manager.health_monitor(), name="health_monitor")
    )
    _bg_tasks.append(
        asyncio.create_task(_rotate_circuit(),         name="rotate_circuit")
    )

    server = await asyncio.start_server(
        handle_client, CFG.local_host, CFG.local_port
    )
    _log.info(
        "SOCKS5 proxy listening",
        extra={"event": "listening", "host": CFG.local_host, "port": CFG.local_port},
    )

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig,
            lambda: asyncio.create_task(_shutdown(server)),
        )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
