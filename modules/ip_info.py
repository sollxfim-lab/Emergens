#!/usr/bin/env python3
"""
Oxysintx - IP & ASN Info Module (v4.0.0)

Mengambil maklumat geolokasi, ISP, organisasi, ASN, dan butiran rangkaian
untuk alamat IP atau nama hos. Menyokong pelbagai penyedia API dengan
fallback automatik, caching, dan data diperkaya.

Ciri-ciri:
  - Resolusi DNS (IPv4 & IPv6)
  - Reverse DNS (PTR)
  - Geolokasi terperinci (negara, bandar, koordinat, zon masa)
  - Maklumat ISP & Organisasi
  - Maklumat ASN (nombor, nama, laluan, perihalan) melalui Team Cymru
  - Penyedia API berbilang: ipwho.is, ip-api.com, ipapi.co, ipinfo.io
  - Caching dalam memori dengan TTL untuk elak rate limit
  - CLI penuh dengan output berwarna (jika disokong)
  - Integrasi mudah dengan ScanOrchestrator

Pengarang: Yanxzyx
"""

import argparse
import json
import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Konfigurasi Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("oxysintx.ip_info")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# ---------------------------------------------------------------------------
# Metadata Alat
# ---------------------------------------------------------------------------
TOOL_INFO = {
    "name": "IP & ASN Info",
    "description": (
        "Resolusi IP/hos, geolokasi terperinci, ISP, organisasi, ASN, "
        "reverse DNS, dan maklumat rangkaian lain."
    ),
    "version": "4.0.0",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Cache Berasaskan Masa (TTL)
# ---------------------------------------------------------------------------
class TTLCache:
    """Cache ringkas dengan masa tamat (TTL)."""

    def __init__(self, ttl_seconds: int = 3600):
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self.ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            timestamp, value = self._cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        self._cache[key] = (time.time(), value)

    def clear(self) -> None:
        self._cache.clear()


# ---------------------------------------------------------------------------
# Struktur Data
# ---------------------------------------------------------------------------
@dataclass
class IPInfoResult:
    """Hasil penuh daripada carian IP."""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    utc_offset: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    asn_country: Optional[str] = None
    asn_registry: Optional[str] = None
    asn_route: Optional[str] = None
    asn_description: Optional[str] = None
    domain: Optional[str] = None
    reverse_dns: Optional[str] = None
    type: Optional[str] = None
    provider: Optional[str] = None
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    is_mobile: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Penyedia Geolokasi
# ---------------------------------------------------------------------------
class GeoProvider:
    """Kelas asas untuk penyedia geolokasi."""

    name: str = "base"
    supports_ipv6: bool = False
    requires_key: bool = False

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class IPWhoIsProvider(GeoProvider):
    """ipwho.is – percuma, tiada kunci, menyokong IPv6, data ASN lengkap."""

    name = "ipwho.is"
    supports_ipv6 = True

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(f"https://ipwho.is/{ip}", timeout=8)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success", False):
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "postal": data.get("postal"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "timezone": data.get("timezone", {}).get("id") if isinstance(data.get("timezone"), dict) else data.get("timezone"),
                    "utc_offset": data.get("timezone", {}).get("utc_offset") if isinstance(data.get("timezone"), dict) else None,
                    "isp": data.get("connection", {}).get("isp"),
                    "org": data.get("connection", {}).get("org"),
                    "asn": data.get("connection", {}).get("asn"),
                    "asn_name": data.get("connection", {}).get("asn_name"),
                    "domain": data.get("connection", {}).get("domain"),
                    "type": data.get("type"),
                    "provider": self.name,
                }
            else:
                logger.debug("ipwho.is tidak berjaya untuk %s: %s", ip, data.get("message"))
        except Exception as e:
            logger.warning("ipwho.is gagal untuk %s: %s", ip, e)
        return None


class IPApiProvider(GeoProvider):
    """ip-api.com – percuma, tiada kunci, terhad 45 req/min, HTTP sahaja."""

    name = "ip-api.com"
    supports_ipv6 = False

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            # Cuba HTTPS dahulu, fallback ke HTTP
            for scheme in ("https", "http"):
                try:
                    resp = requests.get(
                        f"{scheme}://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                        timeout=6
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "ip": ip,
                            "country": data.get("country"),
                            "country_code": data.get("countryCode"),
                            "region": data.get("regionName"),
                            "city": data.get("city"),
                            "postal": data.get("zip"),
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                            "timezone": data.get("timezone"),
                            "utc_offset": None,  # ip-api tidak beri offset
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "asn": data.get("as"),
                            "asn_name": data.get("asname"),
                            "domain": data.get("reverse"),
                            "type": "hosting" if data.get("hosting") else ("mobile" if data.get("mobile") else "isp"),
                            "is_proxy": data.get("proxy"),
                            "is_hosting": data.get("hosting"),
                            "is_mobile": data.get("mobile"),
                            "provider": self.name,
                        }
                    else:
                        logger.debug("ip-api.com tidak berjaya untuk %s: %s", ip, data.get("message"))
                        break
                except Exception:
                    continue  # cuba skim seterusnya
        except Exception as e:
            logger.warning("ip-api.com gagal untuk %s: %s", ip, e)
        return None


class IPApiCoProvider(GeoProvider):
    """ipapi.co – percuma, tiada kunci, menyokong IPv6."""

    name = "ipapi.co"
    supports_ipv6 = True

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("error"):
                return {
                    "ip": ip,
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "postal": data.get("postal"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "timezone": data.get("timezone"),
                    "utc_offset": data.get("utc_offset"),
                    "isp": data.get("org"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "asn_name": None,  # ipapi.co tidak beri nama ASN
                    "domain": data.get("hostname"),
                    "type": data.get("org_type"),
                    "provider": self.name,
                }
            else:
                logger.debug("ipapi.co ralat untuk %s: %s", ip, data.get("reason"))
        except Exception as e:
            logger.warning("ipapi.co gagal untuk %s: %s", ip, e)
        return None


class IPInfoIOProvider(GeoProvider):
    """
    ipinfo.io – memerlukan token untuk kadar lebih tinggi, tetapi tanpa token
    masih boleh berfungsi dengan had 1000 req/hari.
    """

    name = "ipinfo.io"
    supports_ipv6 = True
    requires_key = True  # token pilihan

    def __init__(self, token: Optional[str] = None):
        self.token = token

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=8)
            resp.raise_for_status()
            data = resp.json()
            if "ip" in data:
                # asn mungkin dalam bentuk "AS1234 Nama"
                asn_info = data.get("org", "")
                asn = None
                asn_name = None
                if asn_info and asn_info.startswith("AS"):
                    parts = asn_info.split(" ", 1)
                    asn = parts[0]
                    asn_name = parts[1] if len(parts) > 1 else None
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "postal": data.get("postal"),
                    "latitude": float(data["loc"].split(",")[0]) if data.get("loc") else None,
                    "longitude": float(data["loc"].split(",")[1]) if data.get("loc") else None,
                    "timezone": data.get("timezone"),
                    "utc_offset": None,
                    "isp": data.get("org"),
                    "org": data.get("org"),
                    "asn": asn,
                    "asn_name": asn_name,
                    "domain": data.get("hostname"),
                    "type": "hosting" if data.get("hosting") else "isp",
                    "provider": self.name,
                }
            else:
                logger.debug("ipinfo.io ralat untuk %s: %s", ip, data)
        except Exception as e:
            logger.warning("ipinfo.io gagal untuk %s: %s", ip, e)
        return None


# ---------------------------------------------------------------------------
# Fungsi ASN Lookup melalui Team Cymru DNS
# ---------------------------------------------------------------------------
def team_cymru_asn_lookup(ip: str) -> Dict[str, Any]:
    """
    Query ASN information using Team Cymru's public DNS service.
    Returns dict with asn, asn_name, asn_country, asn_registry, asn_route, asn_description.
    """
    result = {}
    try:
        # Reverse the IP for origin.asn.cymru.com
        if ":" in ip:  # IPv6
            # Not fully supported by Team Cymru DNS; skip
            return result
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = socket.gethostbyname_ex(query)
        if answers and answers[2]:
            # Format: "ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
            txt = answers[2][0]
            parts = txt.split(" | ")
            if len(parts) >= 7:
                result = {
                    "asn": parts[0].strip(),
                    "asn_route": parts[2].strip(),
                    "asn_country": parts[3].strip(),
                    "asn_registry": parts[4].strip(),
                    "asn_name": parts[6].strip(),
                }
                # Query AS description via asn.cymru.com
                asn_number = parts[0].strip()
                if asn_number.startswith("AS"):
                    asn_query = f"AS{asn_number[2:]}.asn.cymru.com"
                    try:
                        desc_answers = socket.gethostbyname_ex(asn_query)
                        if desc_answers and desc_answers[2]:
                            desc_txt = desc_answers[2][0]
                            desc_parts = desc_txt.split(" | ")
                            if len(desc_parts) >= 5:
                                result["asn_description"] = desc_parts[4].strip()
                    except Exception:
                        pass
    except Exception as e:
        logger.debug("Team Cymru ASN lookup failed for %s: %s", ip, e)
    return result


# ---------------------------------------------------------------------------
# Kelas Utama IPInfoLookup
# ---------------------------------------------------------------------------
class IPInfoLookup:
    """
    Pengambil maklumat IP & ASN dengan fallback dan caching.

    Args:
        providers: Senarai penyedia geolokasi (default: ipwho.is, ip-api.com, ipapi.co).
        include_ipinfo: Sertakan ipinfo.io (tanpa token) sebagai fallback terakhir.
        ipinfo_token: Token untuk ipinfo.io (pilihan).
        cache_ttl: Masa cache dalam saat (default 3600).
        timeout: Timeout untuk setiap permintaan HTTP (default 10 saat).
        include_rdns: Lakukan reverse DNS (default True).
        include_asn: Lakukan ASN lookup melalui Team Cymru (default True).
    """

    def __init__(
        self,
        providers: Optional[List[GeoProvider]] = None,
        include_ipinfo: bool = True,
        ipinfo_token: Optional[str] = None,
        cache_ttl: int = 3600,
        timeout: int = 10,
        include_rdns: bool = True,
        include_asn: bool = True,
    ):
        self.providers = providers or [
            IPWhoIsProvider(),
            IPApiProvider(),
            IPApiCoProvider(),
        ]
        if include_ipinfo:
            self.providers.append(IPInfoIOProvider(token=ipinfo_token))
        self.cache = TTLCache(ttl_seconds=cache_ttl)
        self.timeout = timeout
        self.include_rdns = include_rdns
        self.include_asn = include_asn

    def _resolve_host(self, target: str) -> Optional[str]:
        """Resolusi nama hos kepada alamat IP (IPv4/IPv6)."""
        try:
            # Cuba IPv6 dahulu, kemudian IPv4
            for family in (socket.AF_INET6, socket.AF_INET):
                try:
                    infos = socket.getaddrinfo(target, None, family)
                    if infos:
                        return infos[0][4][0]
                except socket.gaierror:
                    continue
            # Fallback kepada gethostbyname (IPv4 sahaja)
            return socket.gethostbyname(target)
        except Exception as e:
            logger.error("Gagal resolve %s: %s", target, e)
            return None

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Lakukan reverse DNS (PTR) jika dibenarkan."""
        if not self.include_rdns:
            return None
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    @staticmethod
    def _is_ip(s: str) -> bool:
        """Periksa sama ada rentetan adalah alamat IP (IPv4 atau IPv6)."""
        try:
            socket.inet_pton(socket.AF_INET, s)
            return True
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except OSError:
            pass
        return False

    def _merge_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Gabungkan hasil daripada pelbagai penyedia.
        Utamakan yang tidak None, jika konflik ambil yang pertama tidak None.
        """
        merged: Dict[str, Any] = {}
        for result in results:
            if not result:
                continue
            for key, value in result.items():
                if value is not None and key not in merged:
                    merged[key] = value
        return merged

    def lookup(self, target: str) -> Tuple[Dict[str, Any], Optional[str]]:
        """
        Dapatkan maklumat IP untuk sasaran (IP atau hos).

        Returns:
            (data_dict, error_string) – data_dict mungkin kosong jika gagal.
        """
        # Semak cache jika sasaran adalah IP
        ip = target if self._is_ip(target) else self._resolve_host(target)
        if not ip:
            return {}, f"Tidak dapat resolve hos: {target}"

        cached = self.cache.get(ip)
        if cached:
            logger.info("Menggunakan cache untuk %s", ip)
            return cached, None

        # Jalankan semua penyedia secara selari
        provider_results = []
        with ThreadPoolExecutor(max_workers=len(self.providers)) as executor:
            future_to_provider = {
                executor.submit(provider.lookup, ip): provider for provider in self.providers
            }
            for future in as_completed(future_to_provider):
                provider = future_to_provider[future]
                try:
                    result = future.result()
                    if result:
                        provider_results.append(result)
                except Exception as e:
                    logger.warning("Provider %s ralat: %s", provider.name, e)

        if not provider_results:
            # Semua penyedia gagal
            rdns = self._reverse_dns(ip) if self.include_rdns else None
            data = {"ip": ip, "domain": rdns}
            logger.error("Semua penyedia geolokasi gagal untuk %s", ip)
            return data, "Semua penyedia geolokasi gagal"

        # Gabungkan hasil
        merged = self._merge_results(provider_results)
        merged["ip"] = ip

        # Tambah reverse DNS jika belum ada
        if self.include_rdns and not merged.get("reverse_dns"):
            rdns = self._reverse_dns(ip)
            if rdns:
                merged["reverse_dns"] = rdns
                if not merged.get("domain"):
                    merged["domain"] = rdns

        # Tambah ASN lookup dari Team Cymru jika diminta dan belum ada
        if self.include_asn and not merged.get("asn_name"):
            asn_info = team_cymru_asn_lookup(ip)
            if asn_info:
                for key, value in asn_info.items():
                    if value is not None and key not in merged:
                        merged[key] = value

        # Tukar ke IPInfoResult untuk struktur yang konsisten
        final_result = IPInfoResult(**merged)

        # Simpan ke cache
        self.cache.set(ip, final_result.to_dict())
        return final_result.to_dict(), None

    def run(self, target: str, mode: str = "basic") -> Dict[str, Any]:
        """
        Antara muka serasi dengan ScanOrchestrator.

        Returns:
            dict dengan kunci: tool, target, data, error, metadata.
        """
        start_time = time.time()
        data, error = self.lookup(target)
        elapsed = time.time() - start_time

        metadata = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "elapsed_seconds": round(elapsed, 3),
            "mode": mode,
            "providers_tried": [p.name for p in self.providers],
            "resolved_ip": data.get("ip") if data else None,
        }

        return {
            "tool": "ip_info",
            "target": target,
            "data": data,
            "error": error,
            "metadata": metadata,
        }


# ---------------------------------------------------------------------------
# Fungsi Wrapper untuk Keserasian ke Belakang
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic", **kwargs) -> dict:
    """
    Wrapper ringkas yang mengekalkan API asal.
    Terima **kwargs supaya boleh dipanggil oleh orchestrator dengan parameter tambahan.
    """
    # Ambil parameter pilihan daripada kwargs jika ada
    cache_ttl = kwargs.get("cache_ttl", 3600)
    include_rdns = kwargs.get("include_rdns", True)
    include_asn = kwargs.get("include_asn", True)
    ipinfo_token = kwargs.get("ipinfo_token", None)

    lookup = IPInfoLookup(
        cache_ttl=cache_ttl,
        include_rdns=include_rdns,
        include_asn=include_asn,
        ipinfo_token=ipinfo_token,
    )
    return lookup.run(target, mode)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _colored(text: str, color: str = "") -> str:
    """Tambahkan warna ANSI jika terminal menyokong."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
    }
    if not color or not os.isatty(1):
        return text
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def main():
    parser = argparse.ArgumentParser(description="Oxysintx IP & ASN Info (v4.0)")
    parser.add_argument("target", help="Alamat IP atau nama hos untuk dianalisis")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic",
                        help="Mod operasi (default: basic)")
    parser.add_argument("--output", choices=["json", "text"], default="text",
                        help="Format output (default: text)")
    parser.add_argument("--no-rdns", action="store_true", help="Matikan reverse DNS")
    parser.add_argument("--no-asn", action="store_true", help="Matikan ASN lookup")
    parser.add_argument("--cache-ttl", type=int, default=3600,
                        help="TTL cache dalam saat (default: 3600)")
    parser.add_argument("--ipinfo-token", help="Token untuk ipinfo.io (pilihan)")
    parser.add_argument("--verbose", action="store_true", help="Logging terperinci")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    lookup = IPInfoLookup(
        cache_ttl=args.cache_ttl,
        include_rdns=not args.no_rdns,
        include_asn=not args.no_asn,
        ipinfo_token=args.ipinfo_token,
    )
    result = lookup.run(args.target, mode=args.mode)

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_colored(f"\n=== IP & ASN Info untuk {args.target} ===\n", "cyan"))
        if result["error"]:
            print(_colored(f"Ralat: {result['error']}", "red"))
        else:
            data = result["data"]
            fields = [
                ("IP", data.get("ip")),
                ("Country", data.get("country")),
                ("Country Code", data.get("country_code")),
                ("Region", data.get("region")),
                ("City", data.get("city")),
                ("Postal", data.get("postal")),
                ("Latitude", data.get("latitude")),
                ("Longitude", data.get("longitude")),
                ("Timezone", data.get("timezone")),
                ("UTC Offset", data.get("utc_offset")),
                ("ISP", data.get("isp")),
                ("Organisation", data.get("org")),
                ("ASN", data.get("asn")),
                ("ASN Name", data.get("asn_name")),
                ("ASN Country", data.get("asn_country")),
                ("ASN Registry", data.get("asn_registry")),
                ("ASN Route", data.get("asn_route")),
                ("ASN Description", data.get("asn_description")),
                ("Domain", data.get("domain")),
                ("Reverse DNS", data.get("reverse_dns")),
                ("Type", data.get("type")),
                ("Proxy", data.get("is_proxy")),
                ("Hosting", data.get("is_hosting")),
                ("Mobile", data.get("is_mobile")),
            ]
            for label, value in fields:
                if value is not None:
                    print(_colored(f"{label:20}: ", "yellow") + _colored(str(value), "white"))
            print(_colored("\nMetadata:", "yellow"))
            for key, value in result["metadata"].items():
                print(f"  {key:20}: {value}")


if __name__ == "__main__":
    main()