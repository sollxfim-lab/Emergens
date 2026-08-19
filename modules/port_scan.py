#!/usr/bin/env python3
"""
Port Scan — Ultra-Fast TCP Connect Scanner with Persistent Thread Pool

Features:
    - Basic mode: 20 common ports (fast, built-in)
    - Expert mode: Reads ONLY from porttxt/ folder (port1.txt, port2.txt, ...)
      NO fallback — if folder is empty or missing, returns an error.
    - Persistent 500-thread pool reused across scans (no pool creation overhead)
    - Max 65535 ports loaded from txt files (safety cap)
    - Service detection for open ports
    - TCP_NODELAY enabled, 0.2s aggressive timeout
    - executor.map() for minimal dispatch overhead
    - Thread exhaustion recovery: halves workers on failure, down to 32
    - Robust path resolution: PORT_DATA_PATH env -> __file__ sibling -> CWD
    - Thread-safe, production-ready
    - Drop-in compatible with app.py Flask integration

Performance (v3.3.0 -> v3.4.0):
    - Persistent thread pool — zero pool-creation latency
    - executor.map() replaces submit/as_completed (lower dispatch overhead)
    - Timeout 0.5s -> 0.2s (3x faster on unresponsive ports)
    - Removed per-socket explicit close() in hot path
    - Estimated throughput: ~1500 ports/sec at 500 threads (was ~800)

Author: Yanxzyx
Version: 3.4.0 — persistent pool, map(), 0.2s timeout, bare-metal hot path
"""

import os
import socket
import concurrent.futures
import time
import logging
from pathlib import Path
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import sys
import json
import glob as glob_module
import atexit

# ---------- LOGGING ----------
logger = logging.getLogger(__name__)

# ---------- CONSTANTS ----------
MAX_PORT = 65535
MIN_PORT = 1
MAX_TOTAL_PORTS = 65535
DEFAULT_TIMEOUT = 0.2             # Aggressive — most hosts ACK within 50ms on decent networks
DEFAULT_THREADS = 500
MAX_THREADS = 550
MIN_THREADS = 32

# ---------- TOOL INFO ----------
TOOL_INFO = {
    "name": "Port Scan",
    "version": "3.4.0",
    "description": (
        "Ultra-fast TCP connect port scanner. "
        "Basic: ~20 common ports. Expert: reads from porttxt/ folder ONLY. "
        "500 persistent threads, 0.2s timeout, TCP_NODELAY, executor.map()."
    ),
    "author": "Yanxzyx"
}

# ---------- SERVICE MAPPING ----------
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
    50000: "SAP", 50070: "HDFS"
}

# ---------- PORT LISTS ----------
BASIC_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 27017,
]


# ---------- DATACLASSES ----------
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
            "response_time": round(self.response_time, 3)
        }


# ---------- PERSISTENT THREAD POOL ----------
_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
_pool_workers: int = 0


def _get_pool(workers: int) -> concurrent.futures.ThreadPoolExecutor:
    """Return a persistent thread pool, recreating only if worker count changes."""
    global _pool, _pool_workers
    if _pool is None or _pool_workers != workers:
        if _pool is not None:
            _pool.shutdown(wait=False)
        _pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        _pool_workers = workers
        logger.debug(f"Thread pool created: {workers} workers")
    return _pool


def _shutdown_pool():
    """Cleanup registered with atexit."""
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=False)
        _pool = None


atexit.register(_shutdown_pool)


# ---------- PATH RESOLUTION ----------
def _resolve_porttxt_path(folder_hint: Optional[str] = None) -> Path:
    env_path = os.environ.get("PORT_DATA_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_dir():
            return candidate
    if folder_hint:
        candidate = Path(folder_hint)
        if candidate.is_absolute() and candidate.is_dir():
            return candidate
        abs_candidate = Path.cwd() / candidate
        if abs_candidate.is_dir():
            return abs_candidate
        return abs_candidate
    try:
        module_dir = Path(__file__).resolve().parent
        sibling = module_dir.parent / "porttxt"
        if sibling.is_dir():
            return sibling
    except (NameError, OSError):
        pass
    cwd_candidate = Path.cwd() / "porttxt"
    if cwd_candidate.is_dir():
        return cwd_candidate
    oxy_cwd = Path.cwd() / "Oxysintx" / "porttxt"
    if oxy_cwd.is_dir():
        return oxy_cwd
    return Path.cwd() / "porttxt"


# ---------- PORT LOADER ----------
def load_ports_from_folder(folder_path: Optional[str] = None) -> Tuple[List[int], Dict[str, Any]]:
    base = _resolve_porttxt_path(folder_path)
    ports: Set[int] = set()
    files_read: List[str] = []
    errors: List[str] = []
    capped = False

    if not base.is_dir():
        return [], {
            "directory": str(base), "files_read": 0, "file_names": [],
            "total_ports_loaded": 0, "capped": False,
            "errors": [f"Directory not found: {base}"]
        }

    def _parse_file(fpath: Path) -> int:
        nonlocal capped
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                for line in fh:
                    if len(ports) >= MAX_TOTAL_PORTS:
                        if not capped:
                            capped = True
                        return count
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for token in line.replace(',', ' ').split():
                        token = token.strip()
                        if not token:
                            continue
                        if '-' in token and not token.startswith('-'):
                            try:
                                s, e = token.split('-', 1)
                                si, ei = int(s.strip()), int(e.strip())
                                if si > ei:
                                    si, ei = ei, si
                                if MIN_PORT <= si <= MAX_PORT and MIN_PORT <= ei <= MAX_PORT:
                                    available = MAX_TOTAL_PORTS - len(ports)
                                    rp = list(range(si, ei + 1))
                                    if len(rp) > available:
                                        rp = rp[:available]
                                        capped = True
                                    ports.update(rp)
                                    count += len(rp)
                            except ValueError:
                                continue
                        else:
                            try:
                                p = int(token)
                                if MIN_PORT <= p <= MAX_PORT:
                                    if len(ports) >= MAX_TOTAL_PORTS:
                                        capped = True
                                        return count
                                    ports.add(p)
                                    count += 1
                            except ValueError:
                                continue
        except OSError as e:
            errors.append(f"Cannot read {fpath}: {e}")
            return 0
        return count

    for idx in range(1, 11):
        if len(ports) >= MAX_TOTAL_PORTS:
            break
        fpath = base / f"port{idx}.txt"
        if not fpath.is_file():
            continue
        added = _parse_file(fpath)
        if added > 0:
            files_read.append(fpath.name)

    if not files_read and len(ports) < MAX_TOTAL_PORTS:
        for fpath_str in sorted(glob_module.glob(str(base / "port*.txt"))):
            if len(ports) >= MAX_TOTAL_PORTS:
                break
            fpath = Path(fpath_str)
            if not fpath.is_file():
                continue
            added = _parse_file(fpath)
            if added > 0:
                files_read.append(fpath.name)

    sorted_ports = sorted(ports)
    return sorted_ports, {
        "directory": str(base), "files_read": len(files_read),
        "file_names": files_read, "total_ports_loaded": len(sorted_ports),
        "capped": capped, "errors": errors
    }


# ---------- SCANNING ENGINE ----------
class PortScanner:
    """Ultra-fast TCP connect port scanner with persistent thread pool."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, max_workers: int = DEFAULT_THREADS):
        self.timeout = timeout
        self.max_workers = min(max_workers, MAX_THREADS)

    # ------------------------------------------------------------------
    # Hot path — called by executor.map() for every port
    # ------------------------------------------------------------------
    @staticmethod
    def _probe(host: str, port: int, timeout: float) -> ScanResult:
        """Single TCP connect — zero allocation beyond the result."""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(timeout)
            sock.connect((host, port))
            elapsed = time.time() - start
            # Don't explicitly close — let GC handle it on the fast path
            return ScanResult(port=port, is_open=True, service=SERVICES.get(port, "unknown"), response_time=elapsed)
        except socket.timeout:
            return ScanResult(port=port, is_open=False, response_time=timeout)
        except (ConnectionRefusedError, OSError):
            return ScanResult(port=port, is_open=False)
        except Exception:
            return ScanResult(port=port, is_open=False)

    # ------------------------------------------------------------------
    # Scan with adaptive worker count
    # ------------------------------------------------------------------
    def scan(self, target: str, ports: List[int]) -> Tuple[List[ScanResult], float, int]:
        """Returns (results, elapsed_seconds, actual_workers_used)."""
        if not ports:
            return [], 0.0, 0

        # DNS
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.warning(f"DNS resolution failed for '{target}'")
            return [], 0.0, 0
        except Exception as e:
            logger.error(f"DNS error: {e}")
            return [], 0.0, 0

        workers = self.max_workers
        last_error = None

        while workers >= MIN_THREADS:
            try:
                logger.info(f"Scanning {len(ports)} ports on {target} ({resolved_ip}) [{workers} threads]")
                pool = _get_pool(workers)

                start_time = time.time()

                # ---- executor.map — minimal dispatch overhead ----
                # Build args tuples: (host, port, timeout) for each port
                args_iter = ((resolved_ip, p, self.timeout) for p in ports)
                results = list(pool.map(lambda a: PortScanner._probe(*a), args_iter, chunksize=max(1, len(ports) // workers // 4)))

                elapsed = time.time() - start_time
                open_count = sum(1 for r in results if r.is_open)
                logger.info(f"Scan complete: {open_count} open ports in {elapsed:.2f}s ({workers} threads)")
                return results, elapsed, workers

            except (RuntimeError, OSError) as e:
                last_error = e
                new_workers = workers // 2
                if new_workers < MIN_THREADS:
                    break
                logger.warning(f"Thread exhaustion at {workers} — retrying with {new_workers}")
                workers = new_workers
                time.sleep(0.15)

        raise RuntimeError(
            f"Thread allocation failed. Tried {self.max_workers} down to {MIN_THREADS}. "
            f"Last error: {last_error}"
        )


# ---------- MAIN SCAN FUNCTION ----------
def run(target: str, mode: str = "basic", **kwargs) -> dict:
    timeout     = kwargs.get('timeout', DEFAULT_TIMEOUT)
    max_workers = min(kwargs.get('max_workers', DEFAULT_THREADS), MAX_THREADS)
    folder_path = kwargs.get('folder_path', None)
    verbose     = kwargs.get('verbose', False)

    if verbose:
        logger.setLevel(logging.DEBUG)

    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    ports_source = "builtin"
    load_metadata: Dict[str, Any] = {}

    if mode == "expert":
        file_ports, load_metadata = load_ports_from_folder(folder_path)
        if not file_ports:
            err_msg = f"No port files found in {load_metadata.get('directory', 'unknown')}. Expert mode requires port*.txt files in the porttxt folder."
            logger.error(err_msg)
            return {
                "tool": "port_scan", "version": TOOL_INFO["version"], "target": target,
                "data": {"resolved_ip": None, "mode": mode, "ports_checked": 0,
                         "open_ports": [], "open_ports_details": [], "open_count": 0,
                         "scan_time": 0, "source": "file", "threads_used": 0,
                         "load_metadata": load_metadata},
                "error": err_msg
            }
        ports_to_scan = file_ports
        ports_source = "file"
        logger.info(f"Expert mode: {len(ports_to_scan)} ports from {load_metadata.get('files_read', 0)} file(s)")
    else:
        ports_to_scan = BASIC_PORTS
        logger.info(f"Basic mode: {len(ports_to_scan)} common ports")

    scanner = PortScanner(timeout=timeout, max_workers=max_workers)

    try:
        results, elapsed, actual_workers = scanner.scan(host, ports_to_scan)
        open_results = [r for r in results if r.is_open]

        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            resolved_ip = "unresolvable"

        data: Dict[str, Any] = {
            "resolved_ip": resolved_ip, "mode": mode,
            "ports_checked": len(ports_to_scan),
            "open_ports": [r.port for r in open_results],
            "open_ports_details": [r.to_dict() for r in open_results],
            "open_count": len(open_results),
            "scan_time": round(elapsed, 2),
            "source": ports_source,
            "threads_used": actual_workers,
        }
        if load_metadata:
            data["load_metadata"] = load_metadata

        return {"tool": "port_scan", "version": TOOL_INFO["version"], "target": target, "data": data, "error": None}

    except RuntimeError as e:
        logger.error(f"Scan aborted: {e}")
        return {"tool": "port_scan", "version": TOOL_INFO["version"], "target": target,
                "data": {"resolved_ip": None, "mode": mode, "ports_checked": len(ports_to_scan),
                         "open_ports": [], "open_ports_details": [], "open_count": 0,
                         "scan_time": 0, "source": ports_source, "threads_used": 0},
                "error": f"Thread allocation failed: {e}"}
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return {"tool": "port_scan", "version": TOOL_INFO["version"], "target": target, "data": {}, "error": str(e)}


# ---------- VALIDATION ----------
def validate_port_files(folder_path: Optional[str] = None) -> dict:
    ports, metadata = load_ports_from_folder(folder_path)
    return {"valid": len(ports) > 0, "total_ports": len(ports), "sample_ports": ports[:20] if ports else [], **metadata}


# ---------- CLI ----------
def main():
    import argparse
    parser = argparse.ArgumentParser(description=TOOL_INFO["description"], epilog=f"Version {TOOL_INFO['version']} — {TOOL_INFO['author']}")
    parser.add_argument("target", nargs="?", help="Domain or IP address to scan")
    parser.add_argument("-m", "--mode", choices=["basic", "expert"], default="basic")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_THREADS)
    parser.add_argument("-f", "--folder", default=None)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--validate", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        logger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    if args.validate:
        print("\n" + "=" * 60)
        print(f"  Port File Validation — v{TOOL_INFO['version']}")
        print("=" * 60)
        r = validate_port_files(args.folder)
        print(f"Directory:    {r['directory']}")
        print(f"Files found:  {r['files_read']}")
        for fn in r.get('file_names', []):
            print(f"  - {fn}")
        print(f"Total ports:  {r['total_ports']}")
        if r.get('capped'):
            print(f"  WARN: CAPPED at {MAX_TOTAL_PORTS}")
        if r.get('errors'):
            for e in r['errors']:
                print(f"  WARN: {e}")
        print(f"Valid:        {'YES' if r['valid'] else 'NO — expert mode will fail'}")
        print("=" * 60)
        sys.exit(0 if r['valid'] else 1)

    if not args.target:
        parser.error("target is required (or use --validate)")

    result = run(target=args.target, mode=args.mode, timeout=args.timeout,
                 max_workers=args.workers, folder_path=args.folder, verbose=args.verbose)

    print("\n" + "=" * 60)
    print(f"  Port Scan v{TOOL_INFO['version']}")
    print("=" * 60)

    if result.get("error"):
        print(f"\nERROR: {result['error']}")
        sys.exit(1)

    d = result.get("data", {})
    print(f"Target:      {result['target']}")
    print(f"Resolved:    {d.get('resolved_ip', 'unknown')}")
    print(f"Mode:        {d.get('mode', 'basic')}")
    print(f"Ports:       {d.get('ports_checked', 0)} checked")
    print(f"Open:        {d.get('open_count', 0)} found")
    print(f"Time:        {d.get('scan_time', 0):.2f}s")
    print(f"Source:      {d.get('source', 'builtin')}")
    print(f"Threads:     {d.get('threads_used', 0)}")
    if d.get("load_metadata"):
        m = d["load_metadata"]
        print(f"Port files:  {m.get('files_read', 0)} read")
        if m.get('capped'):
            print(f"  WARN: Capped at {MAX_TOTAL_PORTS}")
    print("-" * 60)
    for p in d.get('open_ports_details', []):
        print(f"  {p['port']:5d}/tcp  {p['service']:14s}  {p['response_time']:.3f}s")
    if not d.get('open_ports_details'):
        print("  No open ports found.")
    print("=" * 60)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()