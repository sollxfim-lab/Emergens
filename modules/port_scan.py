#!/usr/bin/env python3
"""
Port Scan — Ultra-Fast TCP Connect Scanner with Persistent Thread Pool

Features:
    - Basic mode: ports 1-1000 (all well-known ports, ~1-3s typical)
    - Expert mode: Reads ONLY from porttxt/ folder (port1.txt, port2.txt, ...)
      NO fallback — if folder is empty or missing, returns an error.
    - Persistent 400-thread pool reused across scans (no pool creation overhead)
    - Max 65535 ports loaded from txt files (safety cap)
    - Service detection for open ports
    - TCP_NODELAY + SO_LINGER (RST-on-close) for zero TIME_WAIT accumulation
    - Explicit socket close — no FD leaks under sustained load
    - IPv4 + IPv6 resolution with IPv4 preference
    - 0.2s aggressive timeout
    - executor.map() with functools.partial — minimal dispatch overhead
    - Thread exhaustion recovery: halves workers on failure, down to 32
    - Robust path resolution: PORT_DATA_PATH env -> __file__ sibling -> CWD
    - Isolated logger — no duplicate output with Flask/root handlers
    - Thread-safe, production-ready
    - Drop-in compatible with app.py Flask integration

Performance (v3.5.0 -> v3.6.0):
    - Basic mode expanded: 20 → 1000 ports (all well-known services)
    - URL parsing via urllib.parse — handles IPv6 brackets & userinfo correctly
    - Custom basic range via `basic_port_range` kwarg
    - Reduced logger noise for short scans

Author: Yanxzyx
Version: 3.6.0 — basic 1-1000, robust URL parsing, IPv6-safe
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import glob as glob_module
import json
import logging
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated, no duplicate with Flask/root
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.port_scan")
logger.propagate = False
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
MAX_PORT         = 65535
MIN_PORT         = 1
MAX_TOTAL_PORTS  = 65535
DEFAULT_TIMEOUT  = 0.2
DEFAULT_THREADS  = 400
MAX_THREADS      = 450
MIN_THREADS      = 32
DNS_TIMEOUT      = 5.0

# Basic mode range — inclusive on both ends, i.e. this scans 1..1000.
BASIC_PORT_START = 1
BASIC_PORT_END   = 1000

TOOL_INFO = {
    "name": "Port Scan",
    "version": "3.6.0",
    "description": (
        "Ultra-fast TCP connect port scanner. "
        "Basic: ports 1-1000 (all well-known). Expert: reads from porttxt/ folder ONLY. "
        "400 persistent threads, 0.2s timeout, TCP_NODELAY + SO_LINGER."
    ),
    "author": "Yanxzyx",
}

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE TABLE
# ═══════════════════════════════════════════════════════════════════════════
SERVICES: Dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    26: "RSFTP", 37: "Time", 43: "WHOIS", 49: "TACACS", 53: "DNS",
    67: "DHCP-server", 69: "TFTP", 79: "Finger", 80: "HTTP", 88: "Kerberos",
    102: "ISO-TSAP", 110: "POP3", 111: "RPCbind", 113: "Ident", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-ns", 138: "NetBIOS-dgm",
    139: "NetBIOS-ssn", 143: "IMAP", 161: "SNMP", 162: "SNMP-trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 427: "SLP", 443: "HTTPS",
    444: "SNPP", 445: "SMB", 464: "Kerberos-chg", 465: "SMTPS",
    500: "IKE", 514: "Syslog", 515: "LPD", 520: "RIP", 523: "IBM-DB2",
    524: "NFS", 540: "UUCP", 548: "AFP", 554: "RTSP", 563: "NNTP-SSL",
    587: "SMTP-submit", 591: "FileMaker", 593: "RPC-over-HTTP",
    631: "IPP", 636: "LDAPS", 646: "LDP", 705: "Z39.50", 771: "RTSP-alt",
    777: "Multiling-HTTP", 873: "Rsync", 902: "VMware", 989: "FTP-SSL-data",
    990: "FTP-SSL", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-mon", 1521: "Oracle",
    1723: "PPTP", 1900: "UPnP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WebHost", 2087: "WebHost-SSL",
    2095: "WebMail", 2096: "WebMail-SSL", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker-SSL", 3000: "Rails", 3128: "Squid",
    3268: "LDAP-GC", 3269: "LDAP-GC-SSL", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 4567: "Cassandra", 4848: "GlassFish",
    5000: "UPnP", 5001: "Perforce", 5060: "SIP", 5061: "SIP-TLS",
    5222: "XMPP", 5353: "mDNS", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "RabbitMQ", 5900: "VNC", 5901: "VNC-1", 5984: "CouchDB",
    5985: "WinRM", 5986: "WinRM-SSL", 6000: "X11", 6379: "Redis",
    6443: "K8s-API", 6660: "IRC", 6666: "IRC", 6667: "IRC",
    7000: "Cassandra", 7001: "WebLogic", 7070: "RealMedia",
    7077: "Spark", 7443: "Oracle-SSL", 7777: "Oracle",
    8000: "HTTP-alt", 8009: "AJP13", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8088: "HTTP-alt", 8161: "ActiveMQ", 8200: "VMware", 8333: "Bitcoin",
    8443: "HTTPS-alt", 8500: "Consul", 8888: "HTTP-alt", 8983: "Solr",
    9000: "HBase", 9001: "Tor", 9042: "Cassandra", 9090: "Prometheus",
    9092: "Kafka", 9100: "PDL", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9418: "Git", 9999: "Distinct", 10000: "Webmin", 11211: "Memcached",
    15672: "RabbitMQ-UI", 16379: "Redis", 18080: "HTTP-alt", 20000: "DNP",
    27015: "Steam", 27017: "MongoDB", 28015: "Rust", 32400: "Plex",
    50000: "SAP", 50070: "HDFS",
}

# Basic mode: full range of IANA well-known ports (1-1000 inclusive).
BASIC_PORTS: List[int] = list(range(BASIC_PORT_START, BASIC_PORT_END + 1))

# SO_LINGER value: {l_onoff=1, l_linger=0} → close() sends RST immediately,
# avoiding TIME_WAIT accumulation which is critical for high-volume scanning.
_SO_LINGER_RST = struct.pack("ii", 1, 0)


# ═══════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class ScanResult:
    """Single-port scan result."""
    port: int
    is_open: bool
    service: str = "unknown"
    response_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "is_open": self.is_open,
            "service": self.service,
            "response_time": round(self.response_time, 3),
        }


# ═══════════════════════════════════════════════════════════════════════════
# PERSISTENT THREAD POOL
# ═══════════════════════════════════════════════════════════════════════════
_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
_pool_workers: int = 0


def _get_pool(workers: int) -> concurrent.futures.ThreadPoolExecutor:
    """Return a persistent thread pool, recreating only if worker count changes."""
    global _pool, _pool_workers
    if _pool is None or _pool_workers != workers:
        if _pool is not None:
            _pool.shutdown(wait=False)
        _pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="oxysintx-pscan",
        )
        _pool_workers = workers
        logger.debug("Thread pool created: %d workers", workers)
    return _pool


def _shutdown_pool() -> None:
    """Cleanup registered with atexit."""
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=False)
        _pool = None


atexit.register(_shutdown_pool)


# ═══════════════════════════════════════════════════════════════════════════
# PATH RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_porttxt_path(folder_hint: Optional[str] = None) -> Path:
    """Resolve the porttxt folder path with multiple fallbacks."""
    env_path = os.environ.get("PORT_DATA_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_dir():
            return candidate

    if folder_hint:
        candidate = Path(folder_hint)
        if candidate.is_absolute():
            return candidate
        return Path.cwd() / candidate

    try:
        module_dir = Path(__file__).resolve().parent
        for sibling in (module_dir.parent / "porttxt", module_dir / "porttxt"):
            if sibling.is_dir():
                return sibling
    except (NameError, OSError):
        pass

    for cwd_candidate in (
        Path.cwd() / "porttxt",
        Path.cwd() / "Oxysintx" / "porttxt",
    ):
        if cwd_candidate.is_dir():
            return cwd_candidate

    return Path.cwd() / "porttxt"


# ═══════════════════════════════════════════════════════════════════════════
# PORT LOADER
# ═══════════════════════════════════════════════════════════════════════════
def _parse_port_file(fpath: Path, ports: Set[int], cap_tracker: List[bool]) -> int:
    """
    Parse a single port file into `ports`. Returns number of ports added.
    cap_tracker is a single-element list used as a mutable flag for capping.
    """
    count = 0
    try:
        with open(fpath, "r", encoding="utf-8") as fh:
            for line in fh:
                if len(ports) >= MAX_TOTAL_PORTS:
                    cap_tracker[0] = True
                    return count

                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                for token in line.replace(",", " ").split():
                    token = token.strip()
                    if not token:
                        continue

                    # Range notation "80-90"
                    if "-" in token and not token.startswith("-"):
                        try:
                            s, e = token.split("-", 1)
                            si, ei = int(s.strip()), int(e.strip())
                            if si > ei:
                                si, ei = ei, si
                            if MIN_PORT <= si <= MAX_PORT and MIN_PORT <= ei <= MAX_PORT:
                                available = MAX_TOTAL_PORTS - len(ports)
                                if available <= 0:
                                    cap_tracker[0] = True
                                    return count
                                rp = list(range(si, ei + 1))
                                if len(rp) > available:
                                    rp = rp[:available]
                                    cap_tracker[0] = True
                                ports.update(rp)
                                count += len(rp)
                                if cap_tracker[0]:
                                    return count
                        except ValueError:
                            continue
                    else:
                        try:
                            p = int(token)
                            if MIN_PORT <= p <= MAX_PORT:
                                if len(ports) >= MAX_TOTAL_PORTS:
                                    cap_tracker[0] = True
                                    return count
                                ports.add(p)
                                count += 1
                        except ValueError:
                            continue
    except OSError as e:
        logger.warning("Cannot read %s: %s", fpath, e)
        return 0
    return count


def load_ports_from_folder(
    folder_path: Optional[str] = None
) -> Tuple[List[int], Dict[str, Any]]:
    """Load ports from the porttxt folder. Returns (sorted_ports, metadata)."""
    base = _resolve_porttxt_path(folder_path)
    ports: Set[int] = set()
    files_read: List[str] = []
    files_seen: Set[str] = set()
    errors: List[str] = []
    cap_tracker: List[bool] = [False]

    if not base.is_dir():
        return [], {
            "directory": str(base),
            "files_read": 0,
            "file_names": [],
            "total_ports_loaded": 0,
            "capped": False,
            "errors": [f"Directory not found: {base}"],
        }

    # Pass 1: explicit port1.txt .. port10.txt
    for idx in range(1, 11):
        if len(ports) >= MAX_TOTAL_PORTS:
            break
        fpath = base / f"port{idx}.txt"
        if not fpath.is_file():
            continue
        files_seen.add(fpath.name)
        added = _parse_port_file(fpath, ports, cap_tracker)
        if added > 0:
            files_read.append(fpath.name)

    # Pass 2: glob any remaining port*.txt files not yet tried
    if len(ports) < MAX_TOTAL_PORTS:
        for fpath_str in sorted(glob_module.glob(str(base / "port*.txt"))):
            if len(ports) >= MAX_TOTAL_PORTS:
                break
            fpath = Path(fpath_str)
            if not fpath.is_file() or fpath.name in files_seen:
                continue
            files_seen.add(fpath.name)
            added = _parse_port_file(fpath, ports, cap_tracker)
            if added > 0:
                files_read.append(fpath.name)

    return sorted(ports), {
        "directory": str(base),
        "files_read": len(files_read),
        "file_names": files_read,
        "total_ports_loaded": len(ports),
        "capped": cap_tracker[0],
        "errors": errors,
    }


# ═══════════════════════════════════════════════════════════════════════════
# TARGET / URL PARSING
# ═══════════════════════════════════════════════════════════════════════════
def _extract_host(target: str) -> str:
    """
    Extract a clean hostname or IP from a user-supplied target string.
    Handles:
        example.com
        example.com:8080
        https://example.com/path
        user:pass@example.com:443
        [::1]:8080
        2001:db8::1
    """
    s = (target or "").strip()
    if not s:
        return ""

    # Bare IPv6 literal (contains ":" but no brackets and no scheme)
    if "://" not in s and s.count(":") >= 2 and not s.startswith("["):
        # Likely a raw IPv6 literal like "2001:db8::1" (no port suffix)
        return s

    # If there's no scheme, temporarily prepend "//" so urlparse treats the
    # leading token as the netloc instead of a path.
    candidate = s if "://" in s else "//" + s

    try:
        parsed = urlparse(candidate)
        if parsed.hostname:
            return parsed.hostname
    except ValueError:
        pass

    # Fallback for cases urlparse struggles with
    return (
        s.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split("@")[-1]
        .split(":")[0]
        .strip("[]")
        .strip()
    )


# ═══════════════════════════════════════════════════════════════════════════
# DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_target(host: str) -> Tuple[str, int]:
    """
    Resolve host to (ip, family). Prefers IPv4; falls back to IPv6.
    Raises socket.gaierror if resolution fails.
    """
    # Already an IPv4 literal?
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host, socket.AF_INET
    except (OSError, ValueError):
        pass

    # Already an IPv6 literal?
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host, socket.AF_INET6
    except (OSError, ValueError):
        pass

    # Hostname — resolve with a bounded timeout
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    finally:
        socket.setdefaulttimeout(old_timeout)

    if not infos:
        raise socket.gaierror(f"No addresses found for {host}")

    # Prefer IPv4
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0], socket.AF_INET

    family, _, _, _, sockaddr = infos[0]
    return sockaddr[0], family


# ═══════════════════════════════════════════════════════════════════════════
# SCANNING ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class PortScanner:
    """Ultra-fast TCP connect port scanner with persistent thread pool."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_THREADS,
    ):
        self.timeout = timeout
        self.max_workers = max(MIN_THREADS, min(max_workers, MAX_THREADS))

    # ------------------------------------------------------------------
    # Hot path — called by executor.map() for every port
    # ------------------------------------------------------------------
    @staticmethod
    def _probe(
        host: str,
        port: int,
        timeout: float,
        family: int = socket.AF_INET,
    ) -> ScanResult:
        """
        Single TCP connect probe. Socket is always closed explicitly to
        prevent FD exhaustion under sustained scanning. SO_LINGER=RST
        ensures close() releases the connection immediately with no
        TIME_WAIT accumulation.
        """
        start = time.time()
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _SO_LINGER_RST)
            except (OSError, AttributeError):
                # Not supported on all platforms — best-effort only
                pass
            sock.settimeout(timeout)
            sock.connect((host, port))
            elapsed = time.time() - start
            return ScanResult(
                port=port,
                is_open=True,
                service=SERVICES.get(port, "unknown"),
                response_time=elapsed,
            )
        except socket.timeout:
            return ScanResult(port=port, is_open=False, response_time=timeout)
        except (ConnectionRefusedError, ConnectionResetError):
            return ScanResult(port=port, is_open=False)
        except OSError:
            return ScanResult(port=port, is_open=False)
        except Exception:
            return ScanResult(port=port, is_open=False)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Scan with adaptive worker count
    # ------------------------------------------------------------------
    def scan(
        self, target: str, ports: List[int]
    ) -> Tuple[List[ScanResult], float, int, str, int]:
        """
        Returns (results, elapsed, workers_used, resolved_ip, family).
        Raises socket.gaierror if DNS resolution fails.
        Raises RuntimeError if thread pool cannot be sustained.
        """
        if not ports:
            return [], 0.0, 0, target, socket.AF_INET

        # Resolve once — caller reuses the result
        resolved_ip, family = _resolve_target(target)

        workers = self.max_workers
        last_error: Optional[BaseException] = None

        while workers >= MIN_THREADS:
            try:
                # Only log the plan once at INFO — avoid noise on retries.
                logger.info(
                    "Scanning %d ports on %s (%s) [%d threads]",
                    len(ports), target, resolved_ip, workers,
                )

                pool = _get_pool(workers)

                # functools.partial binds host/timeout/family — the map call
                # only passes `port` positionally → minimal per-task overhead.
                probe = partial(
                    PortScanner._probe,
                    resolved_ip,
                    timeout=self.timeout,
                    family=family,
                )

                # Chunk size balances dispatch overhead vs. worker utilization.
                # For 1-1000 ports and 400 workers, chunksize=1 is ideal.
                chunk = max(1, len(ports) // (workers * 4))

                start_time = time.time()
                results = list(pool.map(probe, ports, chunksize=chunk))
                elapsed = time.time() - start_time

                open_count = sum(1 for r in results if r.is_open)
                logger.info(
                    "Scan complete: %d open ports in %.2fs (%d threads)",
                    open_count, elapsed, workers,
                )
                return results, elapsed, workers, resolved_ip, family

            except (RuntimeError, OSError) as e:
                last_error = e
                new_workers = workers // 2
                if new_workers < MIN_THREADS:
                    break
                logger.warning(
                    "Thread exhaustion at %d — retrying with %d (%s)",
                    workers, new_workers, e,
                )
                workers = new_workers
                time.sleep(0.15)

        raise RuntimeError(
            f"Thread allocation failed. Tried {self.max_workers} down to "
            f"{MIN_THREADS}. Last error: {last_error}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# MAIN SCAN FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> dict:
    timeout     = kwargs.get("timeout", DEFAULT_TIMEOUT)
    max_workers = kwargs.get("max_workers", DEFAULT_THREADS)
    folder_path = kwargs.get("folder_path", None)
    verbose     = kwargs.get("verbose", False)

    # Optional override for the basic-mode range (inclusive).
    # Accepts a (start, end) tuple or list. Defaults to (1, 1000).
    basic_range = kwargs.get("basic_port_range", (BASIC_PORT_START, BASIC_PORT_END))
    try:
        b_start, b_end = int(basic_range[0]), int(basic_range[1])
    except (TypeError, ValueError, IndexError):
        b_start, b_end = BASIC_PORT_START, BASIC_PORT_END

    if verbose:
        logger.setLevel(logging.DEBUG)

    host = _extract_host(target)
    if not host:
        return {
            "tool": "port_scan",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {},
            "error": "Empty target — provide a hostname or IP address.",
        }

    ports_source = "builtin"
    load_metadata: Dict[str, Any] = {}
    ports_to_scan: List[int]

    if mode == "expert":
        file_ports, load_metadata = load_ports_from_folder(folder_path)
        if not file_ports:
            err_msg = (
                f"No port files found in {load_metadata.get('directory', 'unknown')}. "
                "Expert mode requires port*.txt files in the porttxt folder."
            )
            logger.error(err_msg)
            return {
                "tool": "port_scan",
                "version": TOOL_INFO["version"],
                "target": target,
                "data": {
                    "resolved_ip": None,
                    "mode": mode,
                    "ports_checked": 0,
                    "open_ports": [],
                    "open_ports_details": [],
                    "open_count": 0,
                    "scan_time": 0,
                    "source": "file",
                    "threads_used": 0,
                    "load_metadata": load_metadata,
                },
                "error": err_msg,
            }
        ports_to_scan = file_ports
        ports_source = "file"
        logger.info(
            "Expert mode: %d ports from %d file(s)",
            len(ports_to_scan), load_metadata.get("files_read", 0),
        )
    else:
        # Basic mode — full 1-1000 range by default, overridable via kwarg.
        if b_start > b_end:
            b_start, b_end = b_end, b_start
        b_start = max(MIN_PORT, b_start)
        b_end   = min(MAX_PORT, b_end)
        ports_to_scan = list(range(b_start, b_end + 1))
        logger.info(
            "Basic mode: scanning ports %d-%d (%d ports)",
            b_start, b_end, len(ports_to_scan),
        )

    scanner = PortScanner(timeout=timeout, max_workers=max_workers)

    try:
        results, elapsed, actual_workers, resolved_ip, _family = scanner.scan(
            host, ports_to_scan
        )
        open_results = [r for r in results if r.is_open]

        data: Dict[str, Any] = {
            "resolved_ip": resolved_ip,
            "mode": mode,
            "ports_checked": len(ports_to_scan),
            "open_ports": [r.port for r in open_results],
            "open_ports_details": [r.to_dict() for r in open_results],
            "open_count": len(open_results),
            "scan_time": round(elapsed, 2),
            "source": ports_source,
            "threads_used": actual_workers,
        }
        if mode == "basic":
            data["port_range"] = [b_start, b_end]
        if load_metadata:
            data["load_metadata"] = load_metadata

        return {
            "tool": "port_scan",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": data,
            "error": None,
        }

    except socket.gaierror as e:
        logger.error("DNS resolution failed for %s: %s", host, e)
        return {
            "tool": "port_scan",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {
                "resolved_ip": None,
                "mode": mode,
                "ports_checked": 0,
                "open_ports": [],
                "open_ports_details": [],
                "open_count": 0,
                "scan_time": 0,
                "source": ports_source,
                "threads_used": 0,
            },
            "error": f"DNS resolution failed for '{host}': {e}",
        }

    except RuntimeError as e:
        logger.error("Scan aborted: %s", e)
        return {
            "tool": "port_scan",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {
                "resolved_ip": None,
                "mode": mode,
                "ports_checked": len(ports_to_scan),
                "open_ports": [],
                "open_ports_details": [],
                "open_count": 0,
                "scan_time": 0,
                "source": ports_source,
                "threads_used": 0,
            },
            "error": f"Thread allocation failed: {e}",
        }

    except Exception as e:
        logger.exception("Scan failed for %s: %s", host, e)
        return {
            "tool": "port_scan",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {},
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION HELPER
# ═══════════════════════════════════════════════════════════════════════════
def validate_port_files(folder_path: Optional[str] = None) -> dict:
    ports, metadata = load_ports_from_folder(folder_path)
    return {
        "valid": len(ports) > 0,
        "total_ports": len(ports),
        "sample_ports": ports[:20] if ports else [],
        **metadata,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        description=TOOL_INFO["description"],
        epilog=f"Version {TOOL_INFO['version']} — {TOOL_INFO['author']}",
    )
    parser.add_argument("target", nargs="?", help="Domain or IP address to scan")
    parser.add_argument("-m", "--mode", choices=["basic", "expert"], default="basic",
                        help="Scan mode (default: basic — ports 1-1000)")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-port timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_THREADS,
                        help=f"Max worker threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-f", "--folder", default=None,
                        help="Port files folder (expert mode)")
    parser.add_argument("--range", dest="port_range", default=None,
                        help="Override basic-mode range, e.g. --range 1-1024")
    parser.add_argument("-o", "--output", help="Save JSON result to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--validate", action="store_true",
                        help="Validate porttxt folder and exit")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.validate:
        print("\n" + "=" * 60)
        print(f"  Port File Validation — v{TOOL_INFO['version']}")
        print("=" * 60)
        r = validate_port_files(args.folder)
        print(f"Directory:    {r['directory']}")
        print(f"Files found:  {r['files_read']}")
        for fn in r.get("file_names", []):
            print(f"  - {fn}")
        print(f"Total ports:  {r['total_ports']}")
        if r.get("capped"):
            print(f"  WARN: CAPPED at {MAX_TOTAL_PORTS}")
        if r.get("errors"):
            for e in r["errors"]:
                print(f"  WARN: {e}")
        print(f"Valid:        {'YES' if r['valid'] else 'NO — expert mode will fail'}")
        print("=" * 60)
        sys.exit(0 if r["valid"] else 1)

    if not args.target:
        parser.error("target is required (or use --validate)")

    # Parse --range override
    basic_range = (BASIC_PORT_START, BASIC_PORT_END)
    if args.port_range:
        try:
            s, e = args.port_range.split("-", 1)
            basic_range = (int(s), int(e))
        except (ValueError, AttributeError):
            parser.error("--range must look like START-END, e.g. 1-1024")

    result = run(
        target=args.target,
        mode=args.mode,
        timeout=args.timeout,
        max_workers=args.workers,
        folder_path=args.folder,
        verbose=args.verbose,
        basic_port_range=basic_range,
    )

    print("\n" + "=" * 60)
    print(f"  Port Scan v{TOOL_INFO['version']}")
    print("=" * 60)

    if result.get("error"):
        print(f"\nERROR: {result['error']}")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        sys.exit(1)

    d = result.get("data", {})
    print(f"Target:      {result['target']}")
    print(f"Resolved:    {d.get('resolved_ip', 'unknown')}")
    print(f"Mode:        {d.get('mode', 'basic')}")
    if d.get("port_range"):
        print(f"Range:       {d['port_range'][0]}-{d['port_range'][1]}")
    print(f"Ports:       {d.get('ports_checked', 0)} checked")
    print(f"Open:        {d.get('open_count', 0)} found")
    print(f"Time:        {d.get('scan_time', 0):.2f}s")
    print(f"Source:      {d.get('source', 'builtin')}")
    print(f"Threads:     {d.get('threads_used', 0)}")
    if d.get("load_metadata"):
        m = d["load_metadata"]
        print(f"Port files:  {m.get('files_read', 0)} read")
        if m.get("capped"):
            print(f"  WARN: Capped at {MAX_TOTAL_PORTS}")
    print("-" * 60)
    for p in d.get("open_ports_details", []):
        print(f"  {p['port']:5d}/tcp  {p['service']:14s}  {p['response_time']:.3f}s")
    if not d.get("open_ports_details"):
        print("  No open ports found.")
    print("=" * 60)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
