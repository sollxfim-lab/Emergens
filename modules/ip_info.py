"""IP & ASN info - resolves the target IP and looks up public geolocation/hosting info."""
import socket
import requests

TOOL_INFO = {
    "name": "IP & ASN Info",
    "description": "Resolves the target IP and looks up country, ISP, and hosting "
    "organisation via a public geolocation API.",
}


def run(target: str, mode: str = "basic") -> dict:
    try:
        ip = socket.gethostbyname(target)
        data = {"ip": ip}
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
            if geo.get("status") == "success":
                data.update(
                    {
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "isp": geo.get("isp"),
                        "org": geo.get("org"),
                        "as": geo.get("as"),
                    }
                )
        except Exception:
            pass
        return {"tool": "ip_info", "target": target, "data": data, "error": None}
    except Exception as e:
        return {"tool": "ip_info", "target": target, "data": {}, "error": str(e)}
