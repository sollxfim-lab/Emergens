"""
Connectivity / latency check.

True ICMP ping needs raw sockets, which normally requires elevated OS
privileges. This measures round-trip time of a plain TCP handshake to
port 443 instead - same practical purpose (is it up, how fast does it
respond) without needing special privileges or platform-specific code.
"""
import socket
import time

TOOL_INFO = {
    "name": "Connectivity Check",
    "description": "Reachability and round-trip latency via a TCP handshake - "
    "a practical stand-in for ICMP ping.",
}


def _tcp_ping(host: str, port: int, timeout: float = 3.0):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000
    except Exception:
        return None


def run(target: str, mode: str = "basic") -> dict:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    attempts = 4 if mode == "basic" else 8
    port = 443

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {
            "tool": "connectivity_check", "target": target, "data": {},
            "error": f"Could not resolve host: {e}",
        }

    results = [_tcp_ping(resolved_ip, port) for _ in range(attempts)]
    successful = [r for r in results if r is not None]

    data = {
        "resolved_ip": resolved_ip,
        "attempts": attempts,
        "successful": len(successful),
        "packet_loss_percent": round((1 - len(successful) / attempts) * 100, 1),
    }
    if successful:
        data["min_ms"] = round(min(successful), 1)
        data["max_ms"] = round(max(successful), 1)
        data["avg_ms"] = round(sum(successful) / len(successful), 1)

    return {"tool": "connectivity_check", "target": target, "data": data, "error": None}
