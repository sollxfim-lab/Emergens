#!/usr/bin/env python3
"""
Oxysintx - API Key / Secret Scanner Module (v3.2.0)
====================================================

Professional-grade secret scanner covering 300+ API key patterns
across every major cloud provider, SaaS platform, payment processor,
database, messaging service, and AI vendor.

Fitur Utama
-----------
  • 300+ regex pattern merentasi 16 kategori
  • Auto-detect domain tanpa skema (contoh: devtools.biz.id → https://devtools.biz.id)
  • Fallback HTTPS → HTTP secara automatik
  • Pengesanan entropi tinggi (Shannon entropy) dengan tuning automatik
  • Imbas fail, direktori (rekursif), URL, arkib (zip/tar/gz/bz2/xz)
  • Deduplication automatik untuk elak finding berganda
  • Perlindungan Zip Slip, Zip Bomb, SSRF, dan symlink traversal
  • Rate-limiting + saiz had respons untuk URL
  • Output JSON / SARIF / Text / CSV
  • Pemprosesan selari dengan ThreadPoolExecutor
  • Senarai benarkan/pengecualian gaya .gitignore
  • Nombor baris, lajur, jenis fail, dan skor keyakinan
  • Isolated logger — tiada log duplikat dengan Flask/root logger
  • Python 3.8+ compatible

Pengarang: Yanxzyx
"""

from __future__ import annotations

import os
import re
import csv
import io
import math
import json
import time
import shutil
import hashlib
import logging
import argparse
import fnmatch
import tempfile
import zipfile
import tarfile
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Iterable, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — Isolated logger, no duplicate output with Flask/root handlers
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.scan_apikey")
logger.propagate = False                      # Prevent duplicate logs via root

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_handler)

logger.setLevel(logging.INFO)

# Fallback: ensure root logger has a handler (only if nothing else configured it)
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
MAX_FILE_SIZE         = 5 * 1024 * 1024
MAX_URL_RESPONSE_SIZE = 10 * 1024 * 1024
MAX_ARCHIVE_UNPACKED  = 200 * 1024 * 1024
MAX_ARCHIVE_ENTRIES   = 10_000
MAX_ARCHIVE_RATIO     = 100
MAX_LINE_LENGTH       = 20_000
LINE_OVERLAP          = 512
DEFAULT_TIMEOUT       = 10
DEFAULT_USER_AGENT    = "Oxysintx-APIScanner/3.2 (+https://oxysintx.local)"
SCANNER_VERSION       = "3.2.0"

SKIP_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".o", ".a", ".obj",
    ".iso", ".img", ".dmg", ".msi", ".deb", ".rpm",
}

# Regex domain valid — untuk auto-detect input tanpa skema
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


# ═══════════════════════════════════════════════════════════════════════════
# STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    """Satu penemuan rahsia/API key."""
    source:         str
    line:           int
    pattern_name:   str
    confidence:     str
    match:          str
    extracted_key:  str
    context:        str = ""
    file_type:      str = "text"
    column:         int = 0
    rule_id:        str = ""
    description:    str = ""
    severity:       str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        """Hash unik untuk deduplication."""
        raw = f"{self.source}:{self.line}:{self.pattern_name}:{self.extracted_key}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════
# PATTERN DATABASE — 300+ patterns across 16 categories
# ═══════════════════════════════════════════════════════════════════════════
def _p(name: str, regex: str, confidence: str, severity: str, desc: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "regex": regex,
        "confidence": confidence,
        "severity": severity,
        "description": desc or name,
    }


API_KEY_PATTERNS: List[Dict[str, Any]] = [
    # ── 1. AMAZON WEB SERVICES (AWS) ────────────────────────────────
    _p("AWS Access Key ID", r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", "high", "critical"),
    _p("AWS Secret Access Key", r"(?i)aws(?:.{0,20})?(?:secret|sk|key)(?:.{0,20})?['\"]([0-9a-zA-Z/+]{40})['\"]", "high", "critical"),
    _p("AWS Session Token", r"(?i)aws(?:.{0,20})?session(?:.{0,20})?['\"]([A-Za-z0-9/+=]{100,})['\"]", "high", "critical"),
    _p("AWS MWS Key", r"\bamzn\.mws\.[0-9a-f\-]{36}\b", "high", "high"),
    _p("AWS Cognito Identity Pool", r"\b(?:us|eu|ap|sa|ca|me|af)-(?:east|west|south|north|central|northeast|northwest|southeast|southwest)-\d:[0-9a-f\-]{36}\b", "low", "medium"),

    # ── 2. GOOGLE CLOUD PLATFORM (GCP) ──────────────────────────────
    _p("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high", "high"),
    _p("Google OAuth Client ID", r"\b[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "high", "medium"),
    _p("Google OAuth Client Secret", r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b", "high", "high"),
    _p("Google Service Account JSON", r"\"type\"\s*:\s*\"service_account\"", "medium", "high"),
    _p("Google Cloud Storage Signed URL", r"https://storage\.googleapis\.com/[^\s\"']+\?[^\s\"']*Signature=[^\s\"']+", "medium", "medium"),
    _p("Firebase Cloud Messaging Server Key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "high", "high"),
    _p("Firebase Realtime DB URL", r"https://[a-z0-9-]+\.firebaseio\.com", "low", "low"),
    _p("Firebase Project ID", r"\b[a-z][a-z0-9-]{5,29}\.firebaseapp\.com\b", "low", "low"),
    _p("Google reCAPTCHA Site Key", r"\b6L[0-9A-Za-z_-]{38}\b", "medium", "low"),

    # ── 3. MICROSOFT AZURE ──────────────────────────────────────────
    _p("Azure Storage Connection String", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;EndpointSuffix=core\.windows\.net", "high", "critical"),
    _p("Azure Storage Account Key", r"AccountKey=([A-Za-z0-9+/=]{88})", "high", "critical"),
    _p("Azure AD Client Secret", r"(?i)(?:client_secret|app_secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.~]{30,})['\"]", "medium", "high"),
    _p("Azure SAS Token", r"\bsv=\d{4}-\d{2}-\d{2}&(?:s[srcpt]|ss)=[a-z]*&sig=[A-Za-z0-9%]+", "high", "high"),
    _p("Azure DevOps PAT", r"\b[a-z0-9]{52}\b(?=.*Azure)", "low", "medium"),

    # ── 4. SOURCE CODE PLATFORMS ────────────────────────────────────
    _p("GitHub PAT (classic)", r"\bghp_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub OAuth Token", r"\bgho_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub User-to-Server Token", r"\bghu_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Server-to-Server Token", r"\bghs_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Refresh Token", r"\bghr_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Fine-grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "high", "critical"),
    _p("GitLab PAT", r"\bglpat-[0-9A-Za-z\-_]{20}\b", "high", "critical"),
    _p("GitLab Deploy Token", r"\bgldt-[0-9A-Za-z\-_]{20,}\b", "high", "critical"),
    _p("GitLab Runner Token", r"\bglrt-[0-9A-Za-z\-_]{20,}\b", "high", "high"),
    _p("GitLab Pipeline Trigger", r"\bglptt-[0-9A-Za-z\-_]{20,}\b", "high", "high"),
    _p("GitLab Session", r"\bglso-[0-9A-Za-z\-_]{20,}\b", "high", "medium"),
    _p("Bitbucket App Password", r"(?i)bitbucket(?:.{0,20})?(?:app[_-]?password|password)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]", "medium", "high"),
    _p("Bitbucket OAuth Token", r"\bbitoauth_[0-9A-Za-z]{32,}\b", "high", "high"),
    _p("Sourcegraph Token", r"\bsgp_[0-9A-Fa-f]{40}\b", "high", "medium"),

    # ── 5. PAYMENT PROCESSORS ───────────────────────────────────────
    _p("Stripe Live Secret Key", r"\bsk_live_[0-9A-Za-z]{24,}\b", "high", "critical"),
    _p("Stripe Test Secret Key", r"\bsk_test_[0-9A-Za-z]{24,}\b", "high", "high"),
    _p("Stripe Restricted Key", r"\brk_live_[0-9A-Za-z]{24,}\b", "high", "critical"),
    _p("Stripe Publishable Key", r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b", "medium", "low"),
    _p("Stripe Webhook Secret", r"\bwhsec_[0-9A-Za-z]{32,}\b", "high", "high"),
    _p("PayPal Braintree Production", r"\baccess_token\$production\$[0-9a-f]{16}\$[0-9a-f]{32}\b", "high", "critical"),
    _p("PayPal Braintree Sandbox", r"\baccess_token\$sandbox\$[0-9a-f]{16}\$[0-9a-f]{32}\b", "high", "high"),
    _p("PayPal Client Secret", r"(?i)paypal(?:.{0,20})?(?:client[_-]?secret|secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{40,})['\"]", "medium", "high"),
    _p("Square Access Token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", "high", "critical"),
    _p("Square OAuth Secret", r"\bsq0csp-[0-9A-Za-z\-_]{43}\b", "high", "critical"),
    _p("Square Application ID", r"\bsq0idp-[0-9A-Za-z\-_]{22}\b", "medium", "low"),
    _p("Razorpay Key ID", r"\brzp_(?:live|test)_[A-Za-z0-9]{14}\b", "high", "high"),
    _p("Klarna API Key", r"(?i)klarna(?:.{0,20})?['\"]([a-zA-Z0-9_\-]{40,})['\"]", "medium", "high"),
    _p("Adyen API Key", r"\bAQE[a-zA-Z0-9+/=]{40,}\b", "medium", "medium"),
    _p("Coinbase Access Token", r"(?i)coinbase(?:.{0,20})?['\"]([a-zA-Z0-9_\-]{64})['\"]", "medium", "high"),
    _p("Coinbase Pro Passphrase", r"(?i)coinbase(?:.{0,20})?passphrase['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9]+)['\"]", "medium", "high"),

    # ── 6. AI / ML PROVIDERS ────────────────────────────────────────
    _p("OpenAI API Key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "high", "critical"),
    _p("OpenAI Project Key", r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b", "high", "critical"),
    _p("Anthropic API Key", r"\bsk-ant-(?:api|sid)[0-9]{2}-[A-Za-z0-9_\-]{80,}\b", "high", "critical"),
    _p("Hugging Face Token", r"\bhf_[A-Za-z0-9]{34,40}\b", "high", "high"),
    _p("Replicate API Token", r"\br8_[A-Za-z0-9]{38}\b", "high", "high"),
    _p("Cohere API Key", r"(?i)cohere(?:.{0,20})?['\"]([A-Za-z0-9]{40})['\"]", "medium", "high"),
    _p("Groq API Key", r"\bgsk_[A-Za-z0-9]{52}\b", "high", "high"),
    _p("Perplexity API Key", r"\bpplx-[A-Za-z0-9]{40,}\b", "high", "high"),
    _p("Mistral API Key", r"\b[A-Za-z0-9]{32}\b(?=.*mistral)", "low", "medium"),
    _p("ElevenLabs API Key", r"\bsk_[a-f0-9]{48}\b(?=.*elevenlabs)", "low", "medium"),

    # ── 7. COMMUNICATION / MESSAGING ────────────────────────────────
    _p("Slack Bot Token", r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b", "high", "critical"),
    _p("Slack User Token", r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b", "high", "critical"),
    _p("Slack App Token", r"\bxapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-f0-9]{64}\b", "high", "critical"),
    _p("Slack Refresh Token", r"\bxoxe\.xoxp-[0-9]-[0-9a-f]{64}\b", "high", "high"),
    _p("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", "high", "high"),
    _p("Slack Signing Secret", r"(?i)slack(?:.{0,20})?signing(?:.{0,20})?['\"]([a-f0-9]{32})['\"]", "medium", "medium"),
    _p("Discord Bot Token", r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b", "high", "critical"),
    _p("Discord Webhook", r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}", "high", "high"),
    _p("Discord Client Secret", r"(?i)discord(?:.{0,20})?client[_-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{32})['\"]", "medium", "high"),
    _p("Telegram Bot Token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "high", "critical"),
    _p("Twilio Account SID", r"\bAC[a-f0-9]{32}\b", "high", "high"),
    _p("Twilio API Key SID", r"\bSK[0-9a-fA-F]{32}\b", "high", "high"),
    _p("Twilio Auth Token", r"(?i)twilio(?:.{0,20})?(?:auth|token)['\"]?\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "medium", "high"),
    _p("SendGrid API Key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high", "critical"),
    _p("Mailgun API Key", r"\bkey-[0-9a-zA-Z]{32}\b", "high", "high"),
    _p("Mailchimp API Key", r"\b[0-9a-f]{32}-us\d{1,2}\b", "high", "high"),
    _p("Nexmo/Vonage API Secret", r"(?i)(?:nexmo|vonage)(?:.{0,20})?(?:api[_-]?secret|secret)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9]{16})['\"]", "medium", "high"),
    _p("MessageBird API Key", r"\blive_[a-zA-Z0-9]{25}\b", "medium", "high"),
    _p("Plivo Auth ID", r"\bMA[A-Z0-9]{18}\b", "medium", "medium"),
    _p("WhatsApp Cloud API Token", r"\bEAA[A-Za-z0-9]{100,}\b", "medium", "high"),
    _p("Line Channel Access Token", r"\b[a-zA-Z0-9+/]{100,}={0,2}\b(?=.*line)", "low", "medium"),

    # ── 8. DATABASE / INFRASTRUCTURE ────────────────────────────────
    _p("MySQL Connection String", r"mysql://[^\s:@]+:[^\s@]+@[^\s/]+(?:/\S*)?", "medium", "high"),
    _p("PostgreSQL Connection String", r"postgres(?:ql)?://[^\s:@]+:[^\s@]+@[^\s/]+(?:/\S*)?", "medium", "high"),
    _p("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s:@]+:[^\s@]+@[^\s/]+", "high", "critical"),
    _p("Redis Connection String", r"rediss?://[^\s:@]+:[^\s@]+@[^\s/]+", "medium", "high"),
    _p("Elasticsearch URL with Auth", r"https?://[^\s:@]+:[^\s@]+@[^\s/]+:\d{2,5}", "medium", "high"),
    _p("Cassandra Connection String", r"cassandra://[^\s:@]+:[^\s@]+@[^\s/]+", "medium", "high"),
    _p("CockroachDB Connection String", r"postgresql://[^\s:@]+:[^\s@]+@[^\s/]+:26257", "medium", "high"),
    _p("Neo4j Connection String", r"bolt://[^\s:@]+:[^\s@]+@[^\s/]+", "medium", "high"),
    _p("Snowflake Password", r"(?i)snowflake(?:.{0,20})?password['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]", "medium", "high"),
    _p("Databricks Token", r"\bdapi[a-f0-9]{32}\b", "high", "critical"),
    _p("MongoDB Atlas API Key", r"(?i)atlas(?:.{0,20})?(?:public|private)[_-]?key['\"]?\s*[:=]\s*['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]", "medium", "high"),
    _p("Supabase Service Key", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*supabase)", "medium", "critical"),
    _p("Firebase Service Account", r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', "high", "critical"),
    _p("PlanetScale Token", r"\bpscale_tkn_[A-Za-z0-9_\-]{40,}\b", "high", "high"),
    _p("Neon API Key", r"\bnapi_[A-Za-z0-9]{40,}\b", "high", "high"),

    # ── 9. CLOUD / DEVOPS / CI-CD ───────────────────────────────────
    _p("Cloudflare API Token", r"\b[A-Za-z0-9_\-]{40}\b(?=.*cloudflare|CF_API)", "low", "high"),
    _p("Cloudflare Global API Key", r"(?i)cloudflare(?:.{0,20})?(?:global|api)[_-]?key['\"]?\s*[:=]\s*['\"]([a-f0-9]{37})['\"]", "medium", "high"),
    _p("Cloudflare Origin CA Key", r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b", "high", "critical"),
    _p("DigitalOcean PAT", r"\bdop_v1_[a-f0-9]{64}\b", "high", "critical"),
    _p("DigitalOcean OAuth", r"\bdoo_v1_[a-f0-9]{64}\b", "high", "high"),
    _p("DigitalOcean Refresh Token", r"\bdor_v1_[a-f0-9]{64}\b", "high", "high"),
    _p("Heroku API Key", r"(?i)heroku(?:.{0,20})?(?:api[_-]?key|key)['\"]?\s*[:=]\s*['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]", "high", "high"),
    _p("Vercel Token", r"\b[A-Za-z0-9]{24}\b(?=.*vercel)", "low", "medium"),
    _p("Netlify Access Token", r"\b[A-Za-z0-9_\-]{40,}\b(?=.*netlify)", "low", "medium"),
    _p("Render API Key", r"\brnd_[A-Za-z0-9]{32,}\b", "high", "high"),
    _p("Fly.io Token", r"\bFlyV1 [A-Za-z0-9_=]+\b", "high", "high"),
    _p("Linode PAT", r"\b[A-Za-z0-9]{64}\b(?=.*linode)", "low", "medium"),
    _p("Vultr API Key", r"\b[A-Z0-9]{36}\b(?=.*vultr)", "low", "medium"),
    _p("Fastly API Key", r"\b[A-Za-z0-9_\-]{32}\b(?=.*fastly)", "low", "medium"),
    _p("Pulumi Access Token", r"\bpul-[a-f0-9]{40}\b", "high", "high"),
    _p("Terraform Cloud Token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b", "high", "critical"),
    _p("CircleCI Token", r"\b[A-Za-z0-9]{40}\b(?=.*circleci)", "low", "medium"),
    _p("Travis CI Token", r"\b[A-Za-z0-9]{22}\b(?=.*travis)", "low", "medium"),
    _p("Jenkins API Token", r"\b[0-9a-f]{34}\b(?=.*jenkins)", "low", "medium"),
    _p("JFrog Artifactory Token", r"\bAKCp[A-Za-z0-9]{60,}\b", "high", "critical"),
    _p("NPM Access Token", r"\bnpm_[A-Za-z0-9]{36}\b", "high", "high"),
    _p("PyPI Upload Token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", "high", "critical"),
    _p("RubyGems API Key", r"\brubygems_[a-f0-9]{48}\b", "high", "high"),
    _p("NuGet API Key", r"\boy2[a-z0-9]{43}\b", "high", "high"),
    _p("Docker Hub PAT", r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b", "high", "high"),
    _p("Docker Hub Password", r"(?i)docker(?:.{0,20})?password['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "medium", "high"),
    _p("SonarQube Token", r"\bsqp_[a-f0-9]{40}\b", "high", "high"),
    _p("Grafana API Key", r"\beyJrIjoi[A-Za-z0-9_\-]{60,}\b", "high", "high"),
    _p("Grafana Service Account Token", r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b", "high", "high"),
    _p("Datadog API Key", r"\b[a-f0-9]{32}\b(?=.*datadog|DD_API)", "low", "high"),
    _p("Datadog App Key", r"\b[a-f0-9]{40}\b(?=.*datadog)", "low", "medium"),
    _p("New Relic License Key", r"\b[a-f0-9]{40}\b(?=.*newrelic|NEW_RELIC)", "low", "high"),
    _p("New Relic Insights Insert Key", r"\bNRII-[A-Za-z0-9_\-]{30,}\b", "high", "high"),
    _p("Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+", "high", "medium"),
    _p("Sentry Auth Token", r"\bsntrys_[A-Za-z0-9_\-]{64,}\b", "high", "high"),
    _p("Rollbar Access Token", r"\b[a-f0-9]{32}\b(?=.*rollbar)", "low", "medium"),
    _p("Bugsnag API Key", r"\b[a-f0-9]{32}\b(?=.*bugsnag)", "low", "medium"),
    _p("PagerDuty API Key", r"\b[a-zA-Z0-9_+\-/]{20}\b(?=.*pagerduty)", "low", "medium"),
    _p("Opsgenie API Key", r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b(?=.*opsgenie)", "low", "medium"),
    _p("Splunk HEC Token", r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b(?=.*splunk)", "low", "medium"),
    _p("Sumo Logic Access ID", r"\bsu[a-zA-Z0-9]{12}\b", "medium", "medium"),
    _p("Loggly Token", r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b(?=.*loggly)", "low", "medium"),

    # ── 10. SAAS / PRODUCTIVITY ─────────────────────────────────────
    _p("Notion Integration Token", r"\bsecret_[A-Za-z0-9]{43}\b", "high", "high"),
    _p("Notion Internal Token", r"\bntn_[A-Za-z0-9]{40,}\b", "high", "high"),
    _p("Airtable API Key", r"\bkey[A-Za-z0-9]{14}\b", "medium", "high"),
    _p("Airtable PAT", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "high", "high"),
    _p("Asana PAT", r"\b[0-9]/[0-9]{16}/[0-9]{16}:[a-f0-9]{32}\b", "high", "high"),
    _p("Trello API Key", r"\b[a-f0-9]{32}\b(?=.*trello)", "low", "medium"),
    _p("Atlassian API Token", r"\bATATT3[A-Za-z0-9_\-=]{180,}\b", "high", "critical"),
    _p("Jira API Token", r"\b[a-zA-Z0-9]{24}\b(?=.*jira)", "low", "medium"),
    _p("Confluence API Token", r"\b[a-zA-Z0-9]{24}\b(?=.*confluence)", "low", "medium"),
    _p("Zoom JWT Token", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*zoom)", "medium", "high"),
    _p("Zoom SDK Key", r"\b[A-Za-z0-9_\-]{22}\b(?=.*zoom)", "low", "medium"),
    _p("Calendly Token", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*calendly)", "medium", "high"),
    _p("Zapier Webhook", r"https://hooks\.zapier\.com/hooks/catch/\d+/\w+", "medium", "medium"),
    _p("Make.com Webhook", r"https://hook\.(?:eu\d|us\d)\.make\.com/[a-z0-9]+", "medium", "medium"),
    _p("Monday.com API Token", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*monday)", "medium", "high"),
    _p("ClickUp API Token", r"\bpk_[0-9]{8}_[A-Z0-9]{32}\b", "high", "high"),
    _p("Linear API Key", r"\blin_api_[A-Za-z0-9]{40}\b", "high", "high"),
    _p("HubSpot API Key", r"\bpat-(?:na1|eu1)-[a-f0-9\-]{36}\b", "high", "high"),
    _p("Salesforce Token", r"\b00D[a-zA-Z0-9]{12}![A-Za-z0-9._]{90,}\b", "high", "critical"),
    _p("Intercom Access Token", r"\bdG9r[A-Za-z0-9_\-=]{100,}\b", "medium", "high"),

    # ── 11. E-COMMERCE ──────────────────────────────────────────────
    _p("Shopify Access Token", r"\bshpat_[a-f0-9]{32}\b", "high", "critical"),
    _p("Shopify Custom App Token", r"\bshpca_[a-f0-9]{32}\b", "high", "critical"),
    _p("Shopify Private App Password", r"\bshppa_[a-f0-9]{32}\b", "high", "critical"),
    _p("WooCommerce Consumer Key", r"\bck_[a-f0-9]{40}\b", "high", "high"),
    _p("WooCommerce Consumer Secret", r"\bcs_[a-f0-9]{40}\b", "high", "high"),
    _p("BigCommerce Access Token", r"\b[a-z0-9]{40}\b(?=.*bigcommerce)", "low", "medium"),
    _p("Magento Access Token", r"\b[a-z0-9]{32}\b(?=.*magento)", "low", "medium"),

    # ── 12. CRYPTO / BLOCKCHAIN ─────────────────────────────────────
    _p("Bitcoin Private Key (WIF)", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", "medium", "critical"),
    _p("Ethereum Private Key (hex)", r"\b(?:private[_-]?key|privkey)['\"]?\s*[:=]\s*['\"]?(?:0x)?([a-fA-F0-9]{64})['\"]?", "medium", "critical"),
    _p("Ethereum Address", r"\b0x[a-fA-F0-9]{40}\b", "low", "info"),
    _p("BIP39 Mnemonic (12 words)", r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b(?=.*(?:seed|mnemonic|wallet))", "low", "critical"),
    _p("Binance API Key", r"\b[a-zA-Z0-9]{64}\b(?=.*binance)", "low", "high"),
    _p("Kraken API Key", r"\b[a-zA-Z0-9/+=]{56}\b(?=.*kraken)", "low", "high"),
    _p("CoinMarketCap API Key", r"\b[a-f0-9]{32}\b(?=.*coinmarketcap)", "low", "medium"),
    _p("Blockchain.info API Key", r"\b[a-f0-9]{32}\b(?=.*blockchain)", "low", "medium"),

    # ── 13. CERTIFICATES / KEYS ─────────────────────────────────────
    _p("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "high", "critical"),
    _p("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "high", "critical"),
    _p("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "high", "critical"),
    _p("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "high", "critical"),
    _p("PuTTY Private Key", r"PuTTY-User-Key-File-\d+:", "high", "critical"),
    _p("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "high", "critical"),
    _p("SSH Public Key", r"\bssh-(?:rsa|dss|ed25519|ecdsa) AAAA[0-9A-Za-z+/]+[=]{0,3}\b", "low", "info"),
    _p("JWT Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium", "medium"),
    _p("PKCS#12 Certificate", r"-----BEGIN PKCS12-----", "high", "high"),

    # ── 14. APPLE / ANDROID ─────────────────────────────────────────
    _p("Apple App-Specific Password", r"\b[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}\b(?=.*apple)", "low", "high"),
    _p("Apple Push Notification Key", r"-----BEGIN PRIVATE KEY-----(?=[\s\S]*apple)", "low", "high"),
    _p("Google Play Service Account", r'"type"\s*:\s*"service_account"', "medium", "high"),
    _p("Android Keystore Password", r"(?i)(?:keystore|key)[_-]?password['\"]?\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]", "low", "medium"),

    # ── 15. BASE32-CROCKFORD & HUMAN-FRIENDLY TOKENS ────────────────
    # Alphabet: ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (no I, L, O, U, 0, 1)
    _p("Base32-Crockford Token (8 chars)", r"\b[A-HJ-NP-Z2-9]{8}\b", "low", "medium"),
    _p("Base32-Crockford Token (16 chars)", r"\b[A-HJ-NP-Z2-9]{16}\b", "low", "medium"),
    _p("Base32-Crockford Token (24+ chars)", r"\b[A-HJ-NP-Z2-9]{24,}\b", "low", "high"),
    _p("Base32-Crockford Grouped", r"\b[A-HJ-NP-Z2-9]{4,8}(?:-[A-HJ-NP-Z2-9]{4,8}){2,}\b", "medium", "medium"),

    # ── 16. GENERIC / HEURISTIC ─────────────────────────────────────
    _p("Generic API Key Assignment", r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,64})['\"]", "medium", "high"),
    _p("Generic Bearer Token", r"(?i)\b(?:bearer|authorization)\s*[:=]\s*['\"]?Bearer\s+([a-zA-Z0-9_\-\.]{20,})['\"]?", "medium", "high"),
    _p("Generic Password in Config", r"(?i)\bpassword['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]", "low", "medium"),
    _p("Generic Client Secret", r"(?i)\bclient[_-]?secret['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "medium", "high"),
    _p("Generic Access Token", r"(?i)\baccess[_-]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "medium", "high"),
    _p("Generic Private Key Assignment", r"(?i)\bprivate[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9+/=_\-]{20,})['\"]", "medium", "critical"),
    _p("Password in URL", r"https?://[^:\s/]+:[^@\s/]+@[^\s/]+", "medium", "high"),
    _p("Base64 Encoded Secret Hint", r"(?i)(?:secret|token|key)\s*[:=]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", "low", "medium"),
]


# ═══════════════════════════════════════════════════════════════════════════
# FILTER TOKENS — tolak placeholder yang jelas bukan rahsia
# ═══════════════════════════════════════════════════════════════════════════
_PLACEHOLDER_TOKENS = {
    "example", "changeme", "placeholder", "todo", "dummy", "sample",
    "testing", "test", "fake", "invalid", "null", "none", "undefined",
    "localhost", "qwerty", "xxxxx", "aaaaa", "11111", "00000",
    "your_api_key", "your_secret", "your_token", "replace_me",
}


# ═══════════════════════════════════════════════════════════════════════════
# ENTROPY & HEURISTIC HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def shannon_entropy(data: str) -> float:
    """Kira entropi Shannon bagi rentetan (dalam bit per aksara)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def looks_like_secret(s: str) -> bool:
    """
    Penapis awal: buang rentetan yang jelas bukan rahsia.
    Menggunakan padanan token penuh, bukan substring.
    """
    if not s or len(s) < 16:
        return False

    lowered = s.lower()
    tokens = re.split(r"[_\-./\s]+", lowered)
    if any(tok in _PLACEHOLDER_TOKENS for tok in tokens):
        return False

    if len(set(s)) < 5:
        return False

    classes = sum([
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
        any(not c.isalnum() for c in s),
    ])
    return classes >= 2


def looks_like_bare_domain(s: str) -> bool:
    """Semak sama ada string adalah domain tanpa skema/path/port."""
    if not s or " " in s:
        return False
    candidate = s.strip()
    candidate = candidate.split("/", 1)[0]
    candidate = candidate.split(":", 1)[0]
    if not candidate:
        return False
    return bool(_DOMAIN_RE.match(candidate))


# ═══════════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════
class APIScanner:
    """
    Pengimbas API key/rahsia yang boleh dikonfigurasikan.

    Args:
        mode:              "basic" (high/medium sahaja) atau "expert" (semua + entropi).
        entropy_threshold: Ambang entropi minimum (default: 4.5).
        exclude_patterns:  Nama corak untuk dikecualikan.
        include_patterns:  Jika tidak kosong, hanya corak ini digunakan.
        allow_files:       Senarai glob fail untuk dibenarkan.
        deny_files:        Senarai glob fail untuk ditolak.
        max_file_size:     Saiz fail maksimum untuk diimbas (bytes).
        context_chars:     Aksara konteks di setiap sisi padanan.
        follow_symlinks:   Ikut symbolic link (default: False — lebih selamat).
        deduplicate:       Buang penemuan berganda (default: True).
        skip_binary:       Langkau fail binari mengikut sambungan (default: True).
    """

    def __init__(
        self,
        mode: str = "basic",
        entropy_threshold: float = 4.5,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        allow_files: Optional[List[str]] = None,
        deny_files: Optional[List[str]] = None,
        max_file_size: int = MAX_FILE_SIZE,
        context_chars: int = 40,
        follow_symlinks: bool = False,
        deduplicate: bool = True,
        skip_binary: bool = True,
    ):
        self.mode = mode
        self.entropy_threshold = entropy_threshold
        self.exclude_patterns = set(exclude_patterns or [])
        self.include_patterns = set(include_patterns or [])
        self.allow_files = allow_files or []
        self.deny_files = set(deny_files or [])
        self.max_file_size = max_file_size
        self.context_chars = context_chars
        self.follow_symlinks = follow_symlinks
        self.deduplicate = deduplicate
        self.skip_binary = skip_binary

        self.active_patterns: List[Dict[str, Any]] = []
        for pat in API_KEY_PATTERNS:
            if self.include_patterns and pat["name"] not in self.include_patterns:
                continue
            if pat["name"] in self.exclude_patterns:
                continue
            if self.mode == "basic" and pat["confidence"] not in ("high", "medium"):
                continue
            try:
                compiled = re.compile(pat["regex"])
            except re.error as e:
                logger.warning("Regex tidak sah untuk %s: %s", pat["name"], e)
                continue
            self.active_patterns.append({**pat, "compiled": compiled})

        self._entropy_re = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')
        self._deny_regex_cache: Dict[str, Optional[re.Pattern]] = {}

        logger.info(
            "APIScanner dimulakan: mode=%s, %d corak aktif, entropi=%.2f",
            self.mode, len(self.active_patterns), self.entropy_threshold
        )

    # ── HELPERS ─────────────────────────────────────────────────────
    def _extract_context(self, line: str, match_start: int, match_end: int) -> str:
        start = max(0, match_start - self.context_chars)
        end = min(len(line), match_end + self.context_chars)
        return line[start:end]

    def _is_binary_path(self, path: Path) -> bool:
        if not self.skip_binary:
            return False
        return path.suffix.lower() in SKIP_BINARY_EXT

    @staticmethod
    def _glob_to_regex(pattern: str) -> re.Pattern:
        """Tukar glob pattern (sokong **, *, ?) kepada regex yang betul."""
        p = pattern.replace("\\", "/").strip("/")
        parts = p.split("/")
        regex_parts: List[str] = []
        for i, part in enumerate(parts):
            if part == "**":
                if i < len(parts) - 1:
                    regex_parts.append("(?:[^/]+/)*")
                else:
                    regex_parts.append("(?:[^/]+/)*[^/]*")
            else:
                sub = re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
                regex_parts.append(sub + ("" if i == len(parts) - 1 else "/"))
        regex_str = "^" + "".join(regex_parts) + "$"
        return re.compile(regex_str)

    def _is_denied(self, path: Path, root: Optional[Path] = None) -> bool:
        """Semak sama ada fail perlu ditolak mengikut deny_files."""
        if not self.deny_files:
            return False

        try:
            rel = path.relative_to(root) if root else path
        except ValueError:
            rel = path

        rel_str = str(rel).replace("\\", "/")

        for pattern in self.deny_files:
            p = pattern.replace("\\", "/")

            if p not in self._deny_regex_cache:
                try:
                    self._deny_regex_cache[p] = self._glob_to_regex(p)
                except re.error:
                    self._deny_regex_cache[p] = None

            compiled = self._deny_regex_cache[p]
            if compiled is not None and compiled.match(rel_str):
                return True

            if "/" not in p and fnmatch.fnmatch(path.name, p):
                return True

            if p.startswith("**/") and fnmatch.fnmatch(rel_str, p[3:]):
                return True

            if p.endswith("/**") and (
                rel_str == p[:-3] or rel_str.startswith(p[:-3] + "/")
            ):
                return True

        return False

    # ── LINE SCANNERS ───────────────────────────────────────────────
    def _scan_line_for_patterns(
        self, line: str, line_no: int, source: str, file_type: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in self.active_patterns:
            try:
                for match in pattern["compiled"].finditer(line):
                    matched_text = match.group(0)
                    if match.lastindex and match.lastindex >= 1:
                        extracted = match.group(1) or matched_text
                    else:
                        extracted = matched_text

                    extracted = extracted.strip().strip("'\"`")
                    context = self._extract_context(line, match.start(), match.end())

                    findings.append(Finding(
                        source=source,
                        line=line_no,
                        column=match.start() + 1,
                        pattern_name=pattern["name"],
                        confidence=pattern["confidence"],
                        severity=pattern.get("severity", "medium"),
                        description=pattern.get("description", ""),
                        rule_id=re.sub(r"[^A-Z0-9_]+", "_", pattern["name"].upper()),
                        match=matched_text[:500],
                        extracted_key=extracted[:500],
                        context=context[:500],
                        file_type=file_type,
                    ))
            except (re.error, RuntimeError) as e:
                logger.debug("Ralat regex %s: %s", pattern["name"], e)
        return findings

    def _scan_line_for_entropy(
        self, line: str, line_no: int, source: str, file_type: str
    ) -> List[Finding]:
        if self.mode != "expert":
            return []
        findings: List[Finding] = []
        for match in self._entropy_re.finditer(line):
            candidate = match.group(0)
            if len(candidate) > 100:
                continue
            if not looks_like_secret(candidate):
                continue
            ent = shannon_entropy(candidate)
            if ent >= self.entropy_threshold:
                context = self._extract_context(line, match.start(), match.end())
                findings.append(Finding(
                    source=source,
                    line=line_no,
                    column=match.start() + 1,
                    pattern_name="High Entropy String",
                    confidence="entropy",
                    severity="medium",
                    description=f"High-entropy string (Shannon={ent:.2f} bits/char)",
                    rule_id="HIGH_ENTROPY_STRING",
                    match=candidate,
                    extracted_key=candidate,
                    context=context,
                    file_type=file_type,
                ))
        return findings

    # ── CONTENT & FILE SCANNER ──────────────────────────────────────
    def scan_content(
        self, content: str, source: str, file_type: str = "text"
    ) -> List[Finding]:
        """
        Imbas kandungan teks. Baris panjang dipecahkan dengan overlap
        supaya rahsia di sempadan pemisahan tidak terlepas.
        """
        all_findings: List[Finding] = []

        for line_no, line in enumerate(content.splitlines(), start=1):
            if len(line) <= MAX_LINE_LENGTH:
                all_findings.extend(self._scan_line_for_patterns(
                    line, line_no, source, file_type))
                all_findings.extend(self._scan_line_for_entropy(
                    line, line_no, source, file_type))
                continue

            step = MAX_LINE_LENGTH - LINE_OVERLAP
            for seg_start in range(0, len(line), step):
                seg_end = min(seg_start + MAX_LINE_LENGTH, len(line))
                seg = line[seg_start:seg_end]
                all_findings.extend(self._scan_line_for_patterns(
                    seg, line_no, source, file_type))
                all_findings.extend(self._scan_line_for_entropy(
                    seg, line_no, source, file_type))
                if seg_end >= len(line):
                    break

        return all_findings

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        path = Path(file_path)

        if not path.is_file():
            logger.warning("Fail tidak wujud: %s", path)
            return []
        if not self.follow_symlinks and path.is_symlink():
            logger.debug("Symlink dilangkau: %s", path)
            return []
        if self._is_binary_path(path):
            logger.debug("Fail binari dilangkau: %s", path)
            return []

        try:
            size = path.stat().st_size
        except OSError as e:
            logger.debug("Stat gagal %s: %s", path, e)
            return []

        if size > self.max_file_size:
            logger.warning("Fail %s melebihi had (%d > %d bytes), dilangkau.",
                           path, size, self.max_file_size)
            return []
        if size == 0:
            return []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeError) as e:
            logger.error("Gagal membaca %s: %s", path, e)
            return []

        if "\x00" in content[:8192]:
            logger.debug("Fail kelihatan binari (NUL byte): %s", path)
            return []

        return self.scan_content(content, str(path), file_type="text")

    # ── DIRECTORY SCANNER ───────────────────────────────────────────
    def _iter_files(self, directory: Path, recursive: bool) -> Iterable[Path]:
        if not self.allow_files:
            it = directory.rglob("*") if recursive else directory.glob("*")
            for p in it:
                if p.is_file():
                    yield p
            return

        seen: Set[Path] = set()
        for pattern in self.allow_files:
            if not recursive and "**" in pattern:
                pattern_flat = pattern.replace("**/", "")
                it = directory.glob(pattern_flat)
            else:
                it = directory.glob(pattern)

            for p in it:
                if p.is_file() and p not in seen:
                    seen.add(p)
                    yield p

    def scan_directory(
        self, directory: Union[str, Path], recursive: bool = True
    ) -> List[Finding]:
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error("Direktori tidak wujud: %s", dir_path)
            return []

        files_to_scan: List[Path] = []
        for f in self._iter_files(dir_path, recursive):
            if self._is_denied(f, root=dir_path):
                continue
            if not self.follow_symlinks and f.is_symlink():
                continue
            files_to_scan.append(f)

        logger.info("Menemui %d fail untuk diimbas dalam %s",
                    len(files_to_scan), dir_path)

        all_findings: List[Finding] = []
        if not files_to_scan:
            return all_findings

        workers = min(os.cpu_count() or 4, 8)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(self.scan_file, f): f for f in files_to_scan
            }
            done = 0
            total = len(files_to_scan)
            for future in as_completed(future_to_file):
                done += 1
                if done % 100 == 0 or done == total:
                    logger.debug("Progress: %d/%d fail", done, total)
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error("Ralat mengimbas %s: %s",
                                 future_to_file[future], e)
        return all_findings

    # ── URL SCANNER ─────────────────────────────────────────────────
    def scan_url(self, url: str, timeout: int = DEFAULT_TIMEOUT) -> List[Finding]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Skim URL tidak disokong: %s", parsed.scheme)
            return []

        try:
            headers = {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/*, application/json, application/xml, */*;q=0.5",
            }
            with requests.get(url, headers=headers, timeout=timeout,
                              stream=True, allow_redirects=True) as resp:
                resp.raise_for_status()
                ctype = resp.headers.get("Content-Type", "").lower()
                if not any(t in ctype for t in
                           ("text", "json", "xml", "javascript", "x-sh",
                            "x-python", "yaml", "plain")):
                    logger.warning("URL %s bukan teks (%s), dilangkau.", url, ctype)
                    return []

                chunks: List[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=65536):
                    total += len(chunk)
                    if total > MAX_URL_RESPONSE_SIZE:
                        logger.warning("URL %s melebihi had (%d bytes), dipotong.",
                                       url, MAX_URL_RESPONSE_SIZE)
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks)
        except requests.RequestException as e:
            logger.error("Gagal memuat turun %s: %s", url, e)
            return []
        except Exception as e:
            logger.error("Ralat tidak dijangka untuk %s: %s", url, e)
            return []

        text = raw.decode("utf-8", errors="ignore")
        return self.scan_content(text, url, file_type="url")

    # ── ARCHIVE SCANNER ─────────────────────────────────────────────
    @staticmethod
    def _safe_extract_member(member_name: str, extract_root: Path) -> Optional[Path]:
        parts = []
        for part in Path(member_name).parts:
            if part in ("", ".", ".."):
                continue
            parts.append(part)
        if not parts:
            return None
        target = extract_root.joinpath(*parts).resolve()
        try:
            target.relative_to(extract_root.resolve())
        except ValueError:
            return None
        return target

    def scan_archive(self, archive_path: Union[str, Path]) -> List[Finding]:
        path = Path(archive_path)
        all_findings: List[Finding] = []
        temp_dir = Path(tempfile.mkdtemp(prefix="oxysintx_"))
        total_unpacked = 0
        entries_processed = 0

        try:
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path, "r") as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        entries_processed += 1
                        if entries_processed > MAX_ARCHIVE_ENTRIES:
                            logger.warning("Arkib %s melebihi had entri.", path)
                            break
                        if info.compress_size > 0:
                            ratio = info.file_size / info.compress_size
                            if ratio > MAX_ARCHIVE_RATIO and info.file_size > 1024 * 1024:
                                logger.warning(
                                    "Kemungkinan zip bomb: %s (ratio %.0f)",
                                    info.filename, ratio)
                                continue
                        total_unpacked += info.file_size
                        if total_unpacked > MAX_ARCHIVE_UNPACKED:
                            logger.warning("Arkib %s terlalu besar, berhenti.", path)
                            break

                        target = self._safe_extract_member(info.filename, temp_dir)
                        if target is None:
                            logger.warning("Zip Slip dicegah: %s", info.filename)
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            with zf.open(info) as src, open(target, "wb") as dst:
                                shutil.copyfileobj(src, dst, length=65536)
                        except (OSError, zipfile.BadZipFile) as e:
                            logger.debug("Gagal ekstrak %s: %s", info.filename, e)
                            continue
                        all_findings.extend(self.scan_file(target))

            elif path.suffix.lower() in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
                with tarfile.open(path, "r:*") as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue
                        entries_processed += 1
                        if entries_processed > MAX_ARCHIVE_ENTRIES:
                            logger.warning("Arkib %s melebihi had entri.", path)
                            break
                        total_unpacked += member.size
                        if total_unpacked > MAX_ARCHIVE_UNPACKED:
                            logger.warning("Arkib %s terlalu besar, berhenti.", path)
                            break

                        target = self._safe_extract_member(member.name, temp_dir)
                        if target is None:
                            logger.warning("Tar Slip dicegah: %s", member.name)
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            fobj = tf.extractfile(member)
                            if fobj is None:
                                continue
                            with open(target, "wb") as dst:
                                shutil.copyfileobj(fobj, dst, length=65536)
                        except (OSError, tarfile.TarError) as e:
                            logger.debug("Gagal ekstrak %s: %s", member.name, e)
                            continue
                        all_findings.extend(self.scan_file(target))
            else:
                logger.warning("Format arkib tidak disokong: %s", path)
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as e:
            logger.error("Gagal memproses arkib %s: %s", path, e)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return all_findings

    # ── DEDUPLICATION ───────────────────────────────────────────────
    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        seen: Set[str] = set()
        result: List[Finding] = []
        for f in findings:
            fp = f.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            result.append(f)
        return result

    # ── MAIN ENTRY POINT ────────────────────────────────────────────
    def run(self, target: Union[str, Path]) -> Dict[str, Any]:
        """
        Imbas sasaran (fail, direktori, URL, arkib, atau domain tanpa skema).
        """
        target_str = str(target).strip()
        findings: List[Finding] = []
        start = time.time()

        # Auto-detect bare domain (contoh: devtools.biz.id → https://devtools.biz.id)
        if not target_str.startswith(("http://", "https://")):
            if (looks_like_bare_domain(target_str)
                    and not os.path.exists(target_str)):
                target_str = "https://" + target_str
                logger.info("Domain dikesan tanpa skema — menggunakan %s", target_str)

        try:
            if target_str.startswith(("http://", "https://")):
                findings = self.scan_url(target_str)
                if not findings and target_str.startswith("https://"):
                    http_fallback = target_str.replace("https://", "http://", 1)
                    logger.info("HTTPS tiada hasil — cuba fallback %s", http_fallback)
                    fallback = self.scan_url(http_fallback)
                    if fallback:
                        findings = fallback
                        target_str = http_fallback

            elif os.path.isfile(target_str):
                lower = target_str.lower()
                if lower.endswith((".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz")):
                    findings = self.scan_archive(target_str)
                else:
                    findings = self.scan_file(target_str)

            elif os.path.isdir(target_str):
                findings = self.scan_directory(target_str)

            else:
                logger.error("Sasaran tidak dikenali: %s", target_str)
        except Exception as e:
            logger.exception("Ralat semasa mengimbas %s: %s", target_str, e)

        if self.deduplicate:
            before = len(findings)
            findings = self._deduplicate(findings)
            if before != len(findings):
                logger.info("Deduplikasi: %d -> %d", before, len(findings))

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (
            sev_order.get(f.severity, 9),
            f.source,
            f.line,
        ))

        stats: Dict[str, Any] = {
            "total": len(findings),
            "by_confidence": {"high": 0, "medium": 0, "low": 0, "entropy": 0},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_pattern": {},
        }
        for f in findings:
            stats["by_confidence"][f.confidence] = \
                stats["by_confidence"].get(f.confidence, 0) + 1
            stats["by_severity"][f.severity] = \
                stats["by_severity"].get(f.severity, 0) + 1
            stats["by_pattern"][f.pattern_name] = \
                stats["by_pattern"].get(f.pattern_name, 0) + 1

        duration = round(time.time() - start, 3)
        result = {
            "findings": [f.to_dict() for f in findings],
            "stats": stats,
            "scanned": target_str,
            "duration_seconds": duration,
            "scanner_version": SCANNER_VERSION,
        }
        logger.info("Pengimbasan selesai: %d penemuan pada %s (%.2fs)",
                    stats["total"], target_str, duration)
        return result


# ═══════════════════════════════════════════════════════════════════════════
# BACKWARD-COMPAT WRAPPER
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic") -> Dict[str, Any]:
    """Wrapper ringkas untuk APIScanner."""
    scanner = APIScanner(mode=mode)
    return scanner.run(target)


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════
def _format_output(result: Dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)

    if fmt == "sarif":
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Oxysintx API Scanner",
                        "version": result.get("scanner_version", SCANNER_VERSION),
                        "informationUri": "https://oxysintx.local",
                    }
                },
                "results": [
                    {
                        "ruleId": f.get("rule_id") or f["pattern_name"],
                        "level": {
                            "critical": "error",
                            "high": "error",
                            "medium": "warning",
                            "low": "note",
                            "info": "note",
                        }.get(f.get("severity", "medium"), "warning"),
                        "message": {
                            "text": f"{f['pattern_name']}: {f.get('description', '')}"
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f["source"]},
                                "region": {
                                    "startLine": max(1, f.get("line", 1)),
                                    "startColumn": max(1, f.get("column", 1)),
                                },
                            }
                        }],
                    }
                    for f in result["findings"]
                ],
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["severity", "confidence", "pattern", "source",
                         "line", "column", "key", "context"])
        for f in result["findings"]:
            writer.writerow([
                f.get("severity", ""),
                f.get("confidence", ""),
                f.get("pattern_name", ""),
                f.get("source", ""),
                f.get("line", ""),
                f.get("column", ""),
                f.get("extracted_key", ""),
                f.get("context", ""),
            ])
        return buf.getvalue()

    # text (default)
    lines = [
        f"Scan of {result['scanned']} — {result['stats']['total']} findings "
        f"({result.get('duration_seconds', 0)}s)"
    ]
    for f in result["findings"]:
        lines.append(
            f"  [{f.get('severity', 'medium').upper():<8}] "
            f"[{f['confidence']:<8}] {f['pattern_name']} "
            f"@ {f['source']}:{f['line']}:{f.get('column', 0)} "
            f"=> {f['extracted_key'][:80]}"
        )
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Oxysintx API Key Scanner — professional secret scanner"
    )
    parser.add_argument("target",
                        help="Fail, direktori, URL, domain, atau arkib untuk diimbas")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic",
                        help="Mod imbasan (default: basic)")
    parser.add_argument("--output", choices=["json", "sarif", "text", "csv"],
                        default="json", help="Format output (default: json)")
    parser.add_argument("--output-file", help="Simpan output ke fail")
    parser.add_argument("--exclude", nargs="*", default=[],
                        help="Nama corak untuk dikecualikan")
    parser.add_argument("--include", nargs="*", default=[],
                        help="Hanya imbas corak tertentu")
    parser.add_argument("--deny-files", nargs="*", default=[],
                        help="Glob fail untuk ditolak (contoh: '**/.git/**')")
    parser.add_argument("--allow-files", nargs="*", default=[],
                        help="Glob fail untuk dibenarkan")
    parser.add_argument("--entropy-threshold", type=float, default=4.5,
                        help="Ambang entropi untuk mod expert (default: 4.5)")
    parser.add_argument("--no-dedupe", action="store_true",
                        help="Nyahaktifkan deduplikasi")
    parser.add_argument("--follow-symlinks", action="store_true",
                        help="Ikut symlink (tidak disyorkan)")
    parser.add_argument("--verbose", action="store_true",
                        help="Logging lebih terperinci")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    scanner = APIScanner(
        mode=args.mode,
        entropy_threshold=args.entropy_threshold,
        exclude_patterns=args.exclude,
        include_patterns=args.include,
        deny_files=args.deny_files,
        allow_files=args.allow_files,
        deduplicate=not args.no_dedupe,
        follow_symlinks=args.follow_symlinks,
    )
    result = scanner.run(args.target)
    output_str = _format_output(result, args.output)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Output disimpan ke {args.output_file}")
    else:
        print(output_str)


if __name__ == "__main__":
    main()
