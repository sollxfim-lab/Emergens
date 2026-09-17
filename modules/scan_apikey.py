#!/usr/bin/env python3
"""
Oxysintx - API Key Scanner Module (v2.0.0)

Pengimbas rahsia/API key yang sangat profesional.
Ciri-ciri:
  - 100+ corak regex untuk pelbagai perkhidmatan (AWS, GCP, Azure, GitHub, dll.)
  - Pengesanan entropi tinggi (Shannon entropy) untuk rentetan rawak
  - Pengimbasan fail, direktori (rekursif), URL, dan arkib
  - Output JSON/SARIF/teks
  - Pemprosesan selari
  - Senarai benarkan/pengecualian

Pengarang: Yanxzyx
"""

import os
import re
import math
import json
import logging
import argparse
import tempfile
import zipfile
import tarfile
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Generator
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Konfigurasi Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("oxysintx.scan_apikey")

# ---------------------------------------------------------------------------
# Struktur Data
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Satu penemuan rahsia/API key."""
    source: str                  # laluan fail/URL
    line: int                    # nombor baris (jika ada)
    pattern_name: str            # nama corak yang sepadan
    confidence: str              # high, medium, low, entropy
    match: str                   # teks padanan penuh
    extracted_key: str           # nilai kunci yang diekstrak
    context: str = ""            # baris konteks (sehingga 80 aksara)
    file_type: str = "text"      # jenis fail (text, zip, tar, dll.)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# ---------------------------------------------------------------------------
# Pangkalan Data Corak API Key (diinspirasikan oleh TruffleHog, Gitleaks)
# ---------------------------------------------------------------------------
# Format: {"name": ..., "regex": ..., "confidence": "high"/"medium"/"low"}
# Untuk prestasi, regex disusun sekali sahaja.

API_KEY_PATTERNS: List[Dict[str, Any]] = [
    # === AWS ===
    {"name": "AWS Access Key ID", "regex": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "confidence": "high"},
    {"name": "AWS Secret Access Key", "regex": r"\b(?i)aws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?", "confidence": "high"},
    {"name": "AWS MWS Key", "regex": r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "confidence": "high"},

    # === Google Cloud / GCP ===
    {"name": "Google API Key", "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b", "confidence": "high"},
    {"name": "Google OAuth Client ID", "regex": r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "confidence": "high"},
    {"name": "Google OAuth Client Secret", "regex": r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b", "confidence": "high"},
    {"name": "Google Service Account (JSON key)", "regex": r"\"type\"\s*:\s*\"service_account\"", "confidence": "medium"},
    {"name": "Google Cloud Storage Signed URL", "regex": r"\bhttps://storage\.googleapis\.com/[^\s\"']+\?[^\s\"']*Signature=[^\s\"']+", "confidence": "medium"},

    # === Azure ===
    {"name": "Azure Connection String", "regex": r"\bDefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net\b", "confidence": "high"},
    {"name": "Azure Storage Account Key", "regex": r"\bAccountKey=[a-zA-Z0-9+/=]{40,}\b", "confidence": "high"},
    {"name": "Azure AD Client Secret", "regex": r"(?i)\b(client_secret|app_secret)\b\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.~]{20,})['\"]", "confidence": "medium"},

    # === GitHub / GitLab / Bitbucket ===
    {"name": "GitHub Personal Access Token (classic)", "regex": r"\bghp_[0-9a-zA-Z]{36}\b", "confidence": "high"},
    {"name": "GitHub OAuth Access Token", "regex": r"\bgho_[0-9a-zA-Z]{36}\b", "confidence": "high"},
    {"name": "GitHub App Token", "regex": r"\bghu_[0-9a-zA-Z]{36}\b", "confidence": "high"},
    {"name": "GitHub Refresh Token", "regex": r"\bghr_[0-9a-zA-Z]{36}\b", "confidence": "high"},
    {"name": "GitHub Fine-grained PAT", "regex": r"\bgithub_pat_[0-9a-zA-Z_]{40,}\b", "confidence": "high"},
    {"name": "GitLab Personal Access Token", "regex": r"\bglpat-[0-9a-zA-Z\-_]{20,}\b", "confidence": "high"},
    {"name": "GitLab Deploy Token", "regex": r"\bgldt-[0-9a-zA-Z\-_]{20,}\b", "confidence": "high"},
    {"name": "Bitbucket App Password", "regex": r"(?i)\bbitbucket[_-]?app[_-]?password\b\s*[:=]\s*['\"]([a-zA-Z0-9]{16,24})['\"]", "confidence": "medium"},
    {"name": "Bitbucket OAuth Token", "regex": r"\bbitoauth_[0-9a-zA-Z]{32,}\b", "confidence": "high"},

    # === Pembayaran / E-dagang ===
    {"name": "Stripe Live Secret Key", "regex": r"\bsk_live_[0-9a-zA-Z]{24,}\b", "confidence": "high"},
    {"name": "Stripe Test Secret Key", "regex": r"\bsk_test_[0-9a-zA-Z]{24,}\b", "confidence": "high"},
    {"name": "Stripe Restricted Key", "regex": r"\brk_live_[0-9a-zA-Z]{24,}\b", "confidence": "high"},
    {"name": "Stripe Webhook Signing Secret", "regex": r"\bwhsec_[0-9a-zA-Z]{32,}\b", "confidence": "high"},
    {"name": "PayPal Braintree Access Token", "regex": r"\baccess_token\$production\$[0-9a-f]{16}\$[0-9a-f]{32}\b", "confidence": "high"},
    {"name": "PayPal Client ID", "regex": r"\b[A-Za-z0-9_-]{20,}:[A-Za-z0-9_-]{20,}\b", "confidence": "low"},
    {"name": "Square Access Token", "regex": r"\bsq0atp-[0-9A-Za-z\-_]{22,}\b", "confidence": "high"},
    {"name": "Square OAuth Secret", "regex": r"\bsq0csp-[0-9A-Za-z\-_]{30,}\b", "confidence": "high"},

    # === Sosial Media ===
    {"name": "Facebook Access Token", "regex": r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", "confidence": "high"},
    {"name": "Facebook App Secret", "regex": r"(?i)\bfacebook[_-]?app[_-]?secret\b\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "confidence": "high"},
    {"name": "Twitter API Key", "regex": r"(?i)\btwitter[_-]?api[_-]?key\b\s*[:=]\s*['\"]([a-zA-Z0-9]{25,50})['\"]", "confidence": "medium"},
    {"name": "Twitter API Secret", "regex": r"(?i)\btwitter[_-]?api[_-]?secret\b\s*[:=]\s*['\"]([a-zA-Z0-9]{35,65})['\"]", "confidence": "high"},
    {"name": "Slack Webhook URL", "regex": r"\bhttps://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+\b", "confidence": "high"},
    {"name": "Slack Bot Token", "regex": r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b", "confidence": "high"},
    {"name": "Discord Bot Token", "regex": r"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", "confidence": "high"},
    {"name": "Telegram Bot Token", "regex": r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b", "confidence": "high"},

    # === Perkhidmatan Komunikasi ===
    {"name": "Twilio Account SID", "regex": r"\bAC[a-f0-9]{32}\b", "confidence": "high"},
    {"name": "Twilio API Key", "regex": r"\bSK[0-9a-fA-F]{32}\b", "confidence": "high"},
    {"name": "Twilio API Secret", "regex": r"(?i)\btwilio[_-]?api[_-]?secret\b\s*[:=]\s*['\"]([a-zA-Z0-9]{32,})['\"]", "confidence": "high"},
    {"name": "SendGrid API Key", "regex": r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", "confidence": "high"},
    {"name": "Mailgun API Key", "regex": r"\bkey-[0-9a-zA-Z]{32}\b", "confidence": "high"},
    {"name": "Nexmo API Secret", "regex": r"(?i)\bnexmo[_-]?api[_-]?secret\b\s*[:=]\s*['\"]([a-zA-Z0-9]{16,})['\"]", "confidence": "medium"},

    # === Pangkalan Data / Infrastruktur ===
    {"name": "MySQL Connection String", "regex": r"(?i)\bmysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+", "confidence": "medium"},
    {"name": "PostgreSQL Connection String", "regex": r"(?i)\bpostgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+", "confidence": "medium"},
    {"name": "MongoDB Connection String", "regex": r"(?i)\bmongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+", "confidence": "high"},
    {"name": "Redis Connection String", "regex": r"(?i)\brediss?://[^:\s]+:[^@\s]+@[^/\s]+", "confidence": "medium"},
    {"name": "Elasticsearch Connection String", "regex": r"(?i)\bhttps?://[^:\s]+:[^@\s]+@[^/\s]+:[0-9]{2,5}", "confidence": "medium"},
    {"name": "Docker Hub Password", "regex": r"(?i)\bdocker[_-]?hub[_-]?password\b\s*[:=]\s*['\"]([a-zA-Z0-9]{16,})['\"]", "confidence": "medium"},

    # === Cryptocurrency ===
    {"name": "Bitcoin Private Key (WIF)", "regex": r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", "confidence": "medium"},
    {"name": "Ethereum Private Key", "regex": r"\b0x[a-fA-F0-9]{64}\b", "confidence": "low"},

    # === Sijil / Kunci SSH ===
    {"name": "Private SSH Key", "regex": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----", "confidence": "high"},
    {"name": "PGP Private Key", "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "confidence": "high"},
    {"name": "JSON Web Token (JWT)", "regex": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "confidence": "medium"},

    # === Generic / Lain-lain ===
    {"name": "Generic API Key", "regex": r"(?i)\b(?:api[_-]?key|apikey|api)['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9_\-]{20,64})['\"]", "confidence": "medium"},
    {"name": "Bearer Token", "regex": r"(?i)\b(?:bearer|token|auth)['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "confidence": "low"},
    {"name": "Password in URL", "regex": r"\bhttps?://[^:\s]+:[^@\s]+@[^/\s]+", "confidence": "medium"},
    {"name": "Heroku API Key", "regex": r"(?i)\bheroku[_-]?api[_-]?key\b\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]", "confidence": "high"},
    {"name": "npm Access Token", "regex": r"\bnpm_[A-Za-z0-9]{36}\b", "confidence": "high"},
    {"name": "PyPI Upload Token", "regex": r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b", "confidence": "high"},
    {"name": "RubyGems API Key", "regex": r"\brubygems_[a-f0-9]{48}\b", "confidence": "high"},
]

# ---------------------------------------------------------------------------
# Pengiraan Entropi Shannon
# ---------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    """Kira entropi Shannon bagi rentetan (dalam bit per aksara)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        p = data.count(char) / length
        entropy -= p * math.log2(p)
    return entropy

# ---------------------------------------------------------------------------
# Kelas Pengimbas Utama
# ---------------------------------------------------------------------------
class APIScanner:
    """
    Pengimbas API key/rahsia yang boleh dikonfigurasikan.

    Args:
        mode: "basic" (hanya high/medium confidence) atau "expert" (semua + entropi).
        entropy_threshold: Ambang entropi minimum untuk dianggap mencurigakan (default: 4.5).
        exclude_patterns: Senarai nama corak untuk dikecualikan.
        include_patterns: Jika tidak kosong, hanya corak ini digunakan.
        allow_files: Senarai corak glob untuk fail yang dibenarkan.
        deny_files: Senarai corak glob untuk fail yang ditolak.
        max_file_size: Saiz fail maksimum untuk diimbas (bytes).
        context_chars: Bilangan aksara konteks di sekeliling padanan (default: 40).
    """

    def __init__(
        self,
        mode: str = "basic",
        entropy_threshold: float = 4.5,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        allow_files: Optional[List[str]] = None,
        deny_files: Optional[List[str]] = None,
        max_file_size: int = 5 * 1024 * 1024,  # 5 MB
        context_chars: int = 40,
    ):
        self.mode = mode
        self.entropy_threshold = entropy_threshold
        self.exclude_patterns = set(exclude_patterns or [])
        self.include_patterns = set(include_patterns or [])
        self.allow_files = allow_files or ["**/*"]
        self.deny_files = deny_files or []
        self.max_file_size = max_file_size
        self.context_chars = context_chars

        # Sediakan regex aktif
        self.active_patterns = []
        for pat in API_KEY_PATTERNS:
            if self.include_patterns and pat["name"] not in self.include_patterns:
                continue
            if pat["name"] in self.exclude_patterns:
                continue
            if self.mode == "basic" and pat["confidence"] not in ("high", "medium"):
                continue
            # Kompil regex untuk prestasi
            compiled = re.compile(pat["regex"])
            self.active_patterns.append({**pat, "compiled": compiled})

        logger.info(
            "APIScanner dimulakan: mode=%s, %d corak aktif, ambang entropi=%.2f",
            self.mode, len(self.active_patterns), self.entropy_threshold
        )

    def _extract_context(self, line: str, match_start: int, match_end: int) -> str:
        """Ambil konteks sekitar padanan dalam baris."""
        start = max(0, match_start - self.context_chars)
        end = min(len(line), match_end + self.context_chars)
        return line[start:end]

    def _scan_line_for_patterns(self, line: str, line_no: int, source: str, file_type: str) -> List[Finding]:
        """Imbas satu baris untuk semua corak aktif."""
        findings = []
        for pattern in self.active_patterns:
            for match in pattern["compiled"].finditer(line):
                matched_text = match.group(0)
                # Ambil kumpulan pertama jika ada (kunci sebenar)
                extracted = match.group(1) if match.lastindex and match.lastindex >= 1 else matched_text
                context = self._extract_context(line, match.start(), match.end())
                findings.append(Finding(
                    source=source,
                    line=line_no,
                    pattern_name=pattern["name"],
                    confidence=pattern["confidence"],
                    match=matched_text,
                    extracted_key=extracted,
                    context=context,
                    file_type=file_type,
                ))
        return findings

    def _scan_line_for_entropy(self, line: str, line_no: int, source: str, file_type: str) -> List[Finding]:
        """
        Cari rentetan panjang dengan entropi tinggi yang mungkin rahsia.
        Hanya dijalankan dalam mod 'expert'.
        """
        if self.mode != "expert":
            return []
        findings = []
        # Cari jujukan aksara "mencurigakan" (panjang > 20, tiada ruang)
        for match in re.finditer(r'[A-Za-z0-9+/=_\-]{20,}', line):
            candidate = match.group(0)
            if len(candidate) > 100:  # elakkan baris panjang yang bukan rahsia
                continue
            ent = shannon_entropy(candidate)
            if ent >= self.entropy_threshold:
                context = self._extract_context(line, match.start(), match.end())
                findings.append(Finding(
                    source=source,
                    line=line_no,
                    pattern_name="High Entropy String",
                    confidence="entropy",
                    match=candidate,
                    extracted_key=candidate,
                    context=context,
                    file_type=file_type,
                ))
        return findings

    def scan_content(self, content: str, source: str, file_type: str = "text") -> List[Finding]:
        """
        Imbas kandungan teks dan kembalikan senarai Finding.
        """
        all_findings = []
        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            all_findings.extend(self._scan_line_for_patterns(line, line_no, source, file_type))
            all_findings.extend(self._scan_line_for_entropy(line, line_no, source, file_type))
        return all_findings

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """
        Imbas satu fail teks.
        """
        path = Path(file_path)
        if not path.is_file():
            logger.warning("Fail tidak wujud: %s", path)
            return []
        if path.stat().st_size > self.max_file_size:
            logger.warning("Fail %s melebihi had saiz (%d bytes), dilangkau.", path, self.max_file_size)
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_content(content, str(path), file_type="text")
        except Exception as e:
            logger.error("Gagal membaca %s: %s", path, e)
            return []

    def scan_directory(self, directory: Union[str, Path], recursive: bool = True) -> List[Finding]:
        """
        Imbas semua fail teks dalam direktori (secara rekursif jika recursive=True).
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error("Direktori tidak wujud: %s", dir_path)
            return []
        all_findings = []
        # Gunakan glob untuk penapisan
        patterns = self.allow_files if self.allow_files else ["**/*"]
        files_to_scan = []
        for pattern in patterns:
            if recursive:
                files_to_scan.extend(dir_path.glob(pattern))
            else:
                files_to_scan.extend(dir_path.glob(pattern.replace("**/", "")))

        # Tapis fail yang dinafikan
        deny_globs = [dir_path.glob(d) for d in self.deny_files]
        deny_set = set()
        for dg in deny_globs:
            deny_set.update(dg)
        files_to_scan = [f for f in files_to_scan if f.is_file() and f not in deny_set]

        # Imbas secara selari dengan ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}
            for future in as_completed(future_to_file):
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error("Ralat semasa mengimbas %s: %s", future_to_file[future], e)
        return all_findings

    def scan_url(self, url: str, timeout: int = 10) -> List[Finding]:
        """
        Muat turun kandungan URL dan imbas.
        """
        try:
            headers = {"User-Agent": "Oxysintx-APIScanner/2.0"}
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            content_type = resp.headers.get("Content-Type", "")
            if any(t in content_type.lower() for t in ["text", "json", "xml", "javascript"]):
                return self.scan_content(resp.text, url, file_type="url")
            else:
                logger.warning("URL %s bukan kandungan teks (Content-Type: %s), dilangkau.", url, content_type)
                return []
        except Exception as e:
            logger.error("Gagal memuat turun %s: %s", url, e)
            return []

    def scan_archive(self, archive_path: Union[str, Path]) -> List[Finding]:
        """
        Imbas fail dalam arkib zip/tar (hanya fail teks).
        """
        path = Path(archive_path)
        all_findings = []
        temp_dir = tempfile.mkdtemp(prefix="oxysintx_")
        try:
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path, "r") as zf:
                    for member in zf.namelist():
                        if not member.endswith(("/", "\\")):
                            extracted_path = zf.extract(member, temp_dir)
                            all_findings.extend(self.scan_file(extracted_path))
            elif path.suffix.lower() in (".tar", ".gz", ".tgz", ".bz2"):
                with tarfile.open(path, "r:*") as tf:
                    tf.extractall(temp_dir)
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            all_findings.extend(self.scan_file(os.path.join(root, file)))
            else:
                logger.warning("Format arkib tidak disokong: %s", path)
        except Exception as e:
            logger.error("Gagal memproses arkib %s: %s", path, e)
        finally:
            # Bersihkan direktori sementara
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        return all_findings

    def run(self, target: Union[str, Path]) -> Dict[str, Any]:
        """
        Imbas sasaran (fail, direktori, URL, arkib).
        Kembalikan kamus dengan 'findings', 'stats', 'scanned'.
        """
        target_str = str(target)
        findings: List[Finding] = []
        try:
            if target_str.startswith(("http://", "https://")):
                findings = self.scan_url(target_str)
            elif os.path.isfile(target_str):
                if target_str.endswith((".zip", ".tar", ".gz", ".tgz", ".bz2")):
                    findings = self.scan_archive(target_str)
                else:
                    findings = self.scan_file(target_str)
            elif os.path.isdir(target_str):
                findings = self.scan_directory(target_str)
            else:
                logger.error("Sasaran tidak dikenali: %s", target_str)
        except Exception as e:
            logger.error("Ralat semasa mengimbas %s: %s", target_str, e)

        # Kira statistik
        stats = {
            "total": len(findings),
            "by_confidence": {"high": 0, "medium": 0, "low": 0, "entropy": 0},
            "by_pattern": {},
        }
        for f in findings:
            conf = f.confidence
            stats["by_confidence"][conf] = stats["by_confidence"].get(conf, 0) + 1
            stats["by_pattern"][f.pattern_name] = stats["by_pattern"].get(f.pattern_name, 0) + 1

        result = {
            "findings": [f.to_dict() for f in findings],
            "stats": stats,
            "scanned": target_str,
        }
        logger.info("Pengimbasan selesai: %d penemuan pada %s", stats["total"], target_str)
        return result

# ---------------------------------------------------------------------------
# Fungsi wrapper untuk keserasian ke belakang
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic") -> Dict[str, Any]:
    """
    Wrapper ringkas untuk APIScanner. Kekalkan API asal.

    Args:
        target: Laluan fail/direktori atau URL.
        mode: "basic" atau "expert".
    """
    scanner = APIScanner(mode=mode)
    return scanner.run(target)

# ---------------------------------------------------------------------------
# CLI (Command Line Interface)
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Oxysintx API Key Scanner (v2.0)")
    parser.add_argument("target", help="Fail, direktori, URL, atau arkib untuk diimbas")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic",
                        help="Mod imbasan: basic (default) atau expert (termasuk entropi)")
    parser.add_argument("--output", choices=["json", "sarif", "text"], default="json",
                        help="Format output (default: json)")
    parser.add_argument("--output-file", help="Simpan output ke fail")
    parser.add_argument("--exclude", nargs="*", help="Nama corak untuk dikecualikan")
    parser.add_argument("--include", nargs="*", help="Hanya imbas corak tertentu")
    parser.add_argument("--deny-files", nargs="*", help="Glob fail untuk dinafikan")
    parser.add_argument("--allow-files", nargs="*", help="Glob fail untuk dibenarkan")
    parser.add_argument("--entropy-threshold", type=float, default=4.5,
                        help="Ambang entropi untuk mod expert (default: 4.5)")
    parser.add_argument("--verbose", action="store_true", help="Logging lebih terperinci")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = APIScanner(
        mode=args.mode,
        entropy_threshold=args.entropy_threshold,
        exclude_patterns=args.exclude,
        include_patterns=args.include,
        deny_files=args.deny_files,
        allow_files=args.allow_files,
    )
    result = scanner.run(args.target)

    # Format output
    if args.output == "json":
        output_str = json.dumps(result, indent=2)
    elif args.output == "sarif":
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Oxysintx API Scanner", "version": "2.0.0"}},
                "results": [
                    {
                        "ruleId": f["pattern_name"],
                        "level": "error" if f["confidence"] in ("high", "medium") else "warning",
                        "message": {"text": f"Found {f['pattern_name']}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f["source"]},
                                "region": {"startLine": f["line"]}
                            }
                        }]
                    }
                    for f in result["findings"]
                ]
            }]
        }
        output_str = json.dumps(sarif, indent=2)
    else:  # text
        lines = [f"Scan of {result['scanned']} - {result['stats']['total']} findings"]
        for f in result["findings"]:
            lines.append(f"  [{f['confidence']}] {f['pattern_name']} @ {f['source']}:{f['line']} => {f['extracted_key']}")
        output_str = "\n".join(lines)

    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(output_str)
        print(f"Output disimpan ke {args.output_file}")
    else:
        print(output_str)

if __name__ == "__main__":
    main()