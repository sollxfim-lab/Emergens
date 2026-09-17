#!/usr/bin/env python3
"""
sql_map.py – Production-Grade SQL Injection Scanner
Oxysintx Framework

Architecture:
    sql_map.py
    ├── Configuration          (ScanConfig, RequestConfig, default_config)
    ├── Models                 (Payload, ScanFinding, BaselineSignature, TimingSample)
    ├── Payload Registry       (categorized error/boolean/time/union payloads)
    ├── HTTP Transport         (HTTPClient with sessions, retry, rate limiting, timeout)
    ├── Baseline Engine        (BaselineEngine with multiple samples + normalization)
    ├── Parameter Discovery    (extract query params + POST data handling)
    ├── Detection Engines      (ErrorDetector, BooleanDetector, TimeDetector, UnionDetector)
    ├── Confidence Scoring     (ConfidenceEngine with weighted signals)
    ├── Finding Validator      (status classification: confirmed/probable/possible/inconclusive)
    ├── Deduplication          (normalized finding fingerprints)
    ├── Scan Pipeline          (adaptive scanning flow with early stopping + budget control)
    ├── Reporter               (structured dict/JSON output)
    └── CLI                    (professional CLI with full options)

Detection techniques:
    - Error-based:    categorized database signatures with weighted matching
    - Boolean-based:  multi-signal comparison with normalization + similarity delta
    - Time-based:     statistical timing analysis using repeated measurements
    - Union-based:    safe structural detection without data dumping

Author: Yanxzyx
Version: 2.0.0
"""

import argparse
import hashlib
import json
import logging
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------
__version__ = "2.0.0"
__author__ = "Yanxzyx"
__framework__ = "Oxysintx"

logger = logging.getLogger("oxysintx.sqli")

# ---------------------------------------------------------------------------
# Tool metadata (consumed by the scan orchestrator + Security Testing UI)
# ---------------------------------------------------------------------------
TOOL_INFO = {
    "name": "SQLMap (SQL Injection)",
    "version": __version__,
    "description": (
        "Multi-technique SQL injection scanner. Basic: error-based + boolean-blind "
        "on the URL's query parameters. Expert: adds time-blind (statistical timing) "
        "and union-based structural detection. Safe by design — never dumps data."
    ),
    "category": "Web Vulnerability",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Constants & regex definitions
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_THREADS = 10
DEFAULT_MAX_REQUESTS = 200
DEFAULT_REQUEST_DELAY = 0.0  # seconds between requests (0 = disabled)
DEFAULT_MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB
DEFAULT_RETRIES = 2
DEFAULT_RETRY_DELAY = 1.0
DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD = 0.85
DEFAULT_TIME_TRIGGER = 2.0  # seconds
DEFAULT_BASELINE_SAMPLES = 2
DEFAULT_CONFIDENCE_THRESHOLD = 0.45

# Sensitive headers to redact from findings
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-id",
}

# Token patterns to strip during normalization (CSRF, timestamp, etc.)
DYNAMIC_TOKEN_PATTERNS = [
    re.compile(r'name=["\']csrf[^"\']*["\'][^>]*value=["\'][^"\']*["\']', re.IGNORECASE),
    re.compile(r'name=["\']_token["\'][^>]*value=["\'][^"\']*["\']', re.IGNORECASE),
    re.compile(r'name=["\']__RequestVerificationToken["\'][^>]*value=["\'][^"\']*["\']', re.IGNORECASE),
    re.compile(r'\b(nonce|token|csrf|request_id|timestamp|time|random|uid|uuid)["\']?\s*[:=]\s*["\'][0-9a-fA-F\-]{4,}["\']', re.IGNORECASE),
    re.compile(r'\b\d{10,13}\b'),  # timestamps
]


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact sensitive header values from a headers dict."""
    if not headers:
        return headers
    redacted = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def sanitize_payload_for_log(payload: str, max_len: int = 60) -> str:
    """Truncate payload for safe logging."""
    if not payload:
        return ""
    if len(payload) <= max_len:
        return payload
    return payload[:max_len] + "..."


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class ScanConfig:
    """Top-level scan configuration."""
    timeout: float = DEFAULT_TIMEOUT
    max_threads: int = DEFAULT_MAX_THREADS
    verify_ssl: bool = True
    follow_redirects: bool = False
    max_requests: int = DEFAULT_MAX_REQUESTS
    request_delay: float = DEFAULT_REQUEST_DELAY  # seconds
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE
    retries: int = DEFAULT_RETRIES
    retry_delay: float = DEFAULT_RETRY_DELAY
    baseline_samples: int = DEFAULT_BASELINE_SAMPLES
    boolean_similarity_threshold: float = DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD
    time_trigger: float = DEFAULT_TIME_TRIGGER
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    continue_after_detection: bool = True
    test_error: bool = True
    test_boolean: bool = True
    test_time: bool = True
    test_union: bool = True
    stop_event: Optional[Any] = None  # threading.Event or similar

    def validate(self) -> None:
        """Validate configuration values."""
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.max_threads < 1:
            raise ValueError("max_threads must be >= 1")
        if self.max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if self.request_delay < 0:
            raise ValueError("request_delay must be >= 0")
        if self.max_response_size < 1024:
            raise ValueError("max_response_size must be >= 1024")
        if self.retries < 0:
            raise ValueError("retries must be >= 0")
        if self.baseline_samples < 1:
            raise ValueError("baseline_samples must be >= 1")
        if self.boolean_similarity_threshold < 0 or self.boolean_similarity_threshold > 1:
            raise ValueError("boolean_similarity_threshold must be between 0 and 1")
        if self.confidence_threshold < 0 or self.confidence_threshold > 1:
            raise ValueError("confidence_threshold must be between 0 and 1")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Payload:
    """A single SQL injection payload."""
    value: str
    technique: str  # error, boolean, time, union
    database: Optional[str] = None  # mysql, postgresql, mssql, oracle, sqlite, None=generic
    risk: str = "low"  # low, medium, high
    expected_behavior: str = ""


@dataclass
class BaselineSignature:
    """Normalized signature of a baseline response."""
    status_code: int = 0
    response_length: int = 0
    content_type: str = ""
    title: str = ""
    normalized_body_hash: str = ""
    normalized_body_preview: str = ""
    timestamp: float = 0.0


@dataclass
class TimingSample:
    """Timing measurement for statistical analysis."""
    values: List[float] = field(default_factory=list)

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def median(self) -> float:
        if not self.values:
            return 0.0
        sorted_vals = sorted(self.values)
        n = len(sorted_vals)
        if n % 2 == 0:
            return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2
        return sorted_vals[n // 2]

    def std_dev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        m = self.mean()
        variance = sum((v - m) ** 2 for v in self.values) / (len(self.values) - 1)
        return variance ** 0.5


@dataclass
class ScanFinding:
    """Represents a detected SQL injection vulnerability."""
    parameter: str
    technique: str
    confidence: float
    severity: str
    status: str  # confirmed, probable, possible, inconclusive, blocked
    database_type: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    matched_error: Optional[str] = None
    payload: str = ""
    response_status: Optional[int] = None
    baseline_length: Optional[int] = None
    response_length: Optional[int] = None
    similarity: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Payload Registry
# ---------------------------------------------------------------------------
class PayloadRegistry:
    """Structured SQL injection payload registry with category and DB targeting."""

    ERROR_MYSQL = [
        Payload("'", "error", "mysql", "low", "quote break"),
        Payload("''", "error", "mysql", "low", "double quote"),
        Payload("' OR '1'='1", "error", "mysql", "medium", "always true"),
        Payload("1' ORDER BY 10--", "error", "mysql", "medium", "column count overflow"),
        Payload("1' UNION SELECT NULL,NULL,NULL--", "error", "mysql", "high", "union test"),
    ]

    ERROR_POSTGRESQL = [
        Payload("'; SELECT * FROM pg_catalog.pg_tables--", "error", "postgresql", "high", "pg_catalog probe"),
        Payload("' OR 1=1--", "error", "postgresql", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "postgresql", "medium", "column overflow"),
    ]

    ERROR_MSSQL = [
        Payload("'; WAITFOR DELAY '0:0:0'--", "error", "mssql", "medium", "mssql syntax check"),
        Payload("' OR 1=1--", "error", "mssql", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "mssql", "medium", "column overflow"),
    ]

    ERROR_ORACLE = [
        Payload("' OR 1=1--", "error", "oracle", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "oracle", "medium", "column overflow"),
    ]

    ERROR_SQLITE = [
        Payload("' OR 1=1--", "error", "sqlite", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "sqlite", "medium", "column overflow"),
    ]

    ERROR_GENERIC = [
        Payload("'", "error", None, "low", "single quote"),
        Payload('"', "error", None, "low", "double quote"),
        Payload("' OR '1'='1", "error", None, "medium", "always true"),
        Payload("1' AND 1=1--", "error", None, "medium", "true condition"),
        Payload("1' AND 1=2--", "error", None, "medium", "false condition"),
        Payload("1' ORDER BY 1--", "error", None, "medium", "order by test"),
        Payload("1' ORDER BY 100--", "error", None, "medium", "order overflow"),
    ]

    BOOLEAN_TRUE = [
        Payload("' AND '1'='1", "boolean", None, "medium", "boolean true"),
        Payload("' AND 1=1--", "boolean", None, "medium", "boolean true"),
        Payload("1 AND 1=1", "boolean", None, "medium", "boolean true"),
        Payload("1' AND 1=1--", "boolean", None, "medium", "boolean true"),
    ]

    BOOLEAN_FALSE = [
        Payload("' AND '1'='2", "boolean", None, "medium", "boolean false"),
        Payload("' AND 1=2--", "boolean", None, "medium", "boolean false"),
        Payload("1 AND 1=2", "boolean", None, "medium", "boolean false"),
        Payload("1' AND 1=2--", "boolean", None, "medium", "boolean false"),
    ]

    TIME_MYSQL = [
        Payload("' OR SLEEP(1)--", "time", "mysql", "medium", "sleep"),
        Payload("1' AND SLEEP(2)--", "time", "mysql", "medium", "sleep"),
    ]

    TIME_POSTGRESQL = [
        Payload("' OR pg_sleep(1)--", "time", "postgresql", "medium", "pg_sleep"),
    ]

    TIME_MSSQL = [
        Payload("'; WAITFOR DELAY '0:0:2'--", "time", "mssql", "medium", "waitfor delay"),
    ]

    TIME_ORACLE = [
        Payload("' OR 1=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--", "time", "oracle", "medium", "dbms_pipe"),
    ]

    TIME_SQLITE = [
        Payload("' OR 1=1 AND 1=randomblob(1000000)--", "time", "sqlite", "medium", "randomblob"),
    ]

    TIME_GENERIC = [
        Payload("' OR SLEEP(1)--", "time", None, "medium", "sleep"),
        Payload("1' AND SLEEP(1)--", "time", None, "medium", "sleep"),
    ]

    UNION_GENERIC = [
        Payload("' UNION SELECT NULL--", "union", None, "medium", "single column union"),
        Payload("' UNION SELECT NULL,NULL--", "union", None, "medium", "two column union"),
        Payload("' UNION SELECT NULL,NULL,NULL--", "union", None, "medium", "three column union"),
        Payload("1' UNION SELECT 1,2,3--", "union", None, "medium", "numeric union"),
    ]

    @classmethod
    def get_error_payloads(cls, db: Optional[str] = None) -> List[Payload]:
        """Get error payloads, optionally filtered by database."""
        if db is None:
            return cls.ERROR_GENERIC.copy()
        db_payloads = getattr(cls, f"ERROR_{db.upper()}", None)
        if db_payloads:
            return db_payloads.copy()
        return cls.ERROR_GENERIC.copy()

    @classmethod
    def get_boolean_payloads(cls) -> Tuple[List[Payload], List[Payload]]:
        """Return (true_payloads, false_payloads)."""
        return cls.BOOLEAN_TRUE.copy(), cls.BOOLEAN_FALSE.copy()

    @classmethod
    def get_time_payloads(cls, db: Optional[str] = None) -> List[Payload]:
        """Get time-based payloads, optionally filtered by database."""
        if db is None:
            return cls.TIME_GENERIC.copy()
        db_payloads = getattr(cls, f"TIME_{db.upper()}", None)
        if db_payloads:
            return db_payloads.copy()
        return cls.TIME_GENERIC.copy()

    @classmethod
    def get_union_payloads(cls) -> List[Payload]:
        """Get union payloads."""
        return cls.UNION_GENERIC.copy()


# ---------------------------------------------------------------------------
# Response Normalization
# ---------------------------------------------------------------------------
class ResponseNormalizer:
    """Normalize HTML responses to remove dynamic content."""

    @staticmethod
    def normalize(html: str) -> str:
        """Remove volatile tokens and normalize whitespace."""
        if not html:
            return ""

        text = html

        # Strip script and style blocks (they rarely affect SQLi detection)
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.IGNORECASE | re.DOTALL)

        # Remove dynamic tokens
        for pattern in DYNAMIC_TOKEN_PATTERNS:
            text = pattern.sub("", text)

        # Normalize whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def hash_normalized(text: str) -> str:
        """Return a stable hash of normalized text."""
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def similarity(text1: str, text2: str) -> float:
        """
        Compute similarity between two normalized texts.
        Uses character bigram similarity (Jaccard-like approximation).
        Returns 0.0 (completely different) to 1.0 (identical).
        """
        if text1 == text2:
            return 1.0
        if not text1 or not text2:
            return 0.0

        def bigrams(s: str) -> set:
            s = s.lower()
            return {s[i:i + 2] for i in range(max(len(s) - 1, 0))} if len(s) > 1 else {s}

        bg1 = bigrams(text1)
        bg2 = bigrams(text2)
        if not bg1 or not bg2:
            return 0.0

        intersection = len(bg1 & bg2)
        union = len(bg1 | bg2)
        if union == 0:
            return 1.0
        return intersection / union


# ---------------------------------------------------------------------------
# HTTP Transport Layer
# ---------------------------------------------------------------------------
class HTTPClient:
    """
    Thread-safe HTTP transport layer with session reuse, retry, rate limiting,
    and response size limiting.
    """

    def __init__(self, config: ScanConfig, headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.config = config
        self.headers = headers or {"User-Agent": f"Oxysintx-SQLi-Scanner/{__version__}"}
        self.cookies = cookies
        self.proxies = proxies
        self._session: Optional[requests.Session] = None
        self._last_request_time = 0.0
        self._request_count = 0
        self._lock = None  # Will be initialized when needed

    def _get_lock(self):
        """Lazily create a thread lock."""
        if self._lock is None:
            import threading
            self._lock = threading.Lock()
        return self._lock

    def _get_session(self) -> requests.Session:
        """Get or create the requests session (thread-safe)."""
        lock = self._get_lock()
        with lock:
            if self._session is None:
                session = requests.Session()
                session.headers.update(self.headers)
                if self.cookies:
                    session.cookies.update(self.cookies)
                if self.proxies:
                    session.proxies.update(self.proxies)
                session.verify = self.config.verify_ssl
                self._session = session
            return self._session

    def _check_budget(self) -> bool:
        """Check if request budget has been exhausted."""
        return self._request_count >= self.config.max_requests

    def _apply_rate_limit(self):
        """Apply rate limiting if configured."""
        if self.config.request_delay > 0:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.config.request_delay:
                time.sleep(self.config.request_delay - elapsed)
            self._last_request_time = time.time()

    def _check_stop(self) -> bool:
        """Check if cancellation was requested."""
        if self.config.stop_event is not None:
            return self.config.stop_event.is_set()
        return False

    def request(self, method: str, url: str, params: Optional[Dict] = None,
                data: Optional[Dict] = None, measure_time: bool = False) -> Optional[Union[requests.Response, Tuple[requests.Response, float]]]:
        """
        Send an HTTP request with retry and rate limiting.
        Returns Response or (Response, elapsed_time) if measure_time=True.
        Returns None if request fails or budget exhausted.
        """
        lock = self._get_lock()
        with lock:
            if self._check_budget() or self._check_stop():
                return None
            self._apply_rate_limit()
            self._request_count += 1

        session = self._get_session()
        method = method.upper()

        for attempt in range(self.config.retries + 1):
            if self._check_stop():
                return None
            try:
                start = time.time()
                if method == "GET":
                    response = session.get(
                        url,
                        params=params,
                        timeout=self.config.timeout,
                        allow_redirects=self.config.follow_redirects,
                    )
                elif method == "POST":
                    response = session.post(
                        url,
                        data=data,
                        timeout=self.config.timeout,
                        allow_redirects=self.config.follow_redirects,
                    )
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                elapsed = time.time() - start

                # Enforce response size limit
                if response.headers.get("Content-Length"):
                    try:
                        content_length = int(response.headers["Content-Length"])
                        if content_length > self.config.max_response_size:
                            logger.warning(
                                f"Response too large ({content_length} bytes), truncating."
                            )
                            # We can't easily truncate streaming; return as is but warn
                    except (ValueError, TypeError):
                        pass

                if measure_time:
                    return response, elapsed
                return response

            except RequestException as e:
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.config.retries + 1}): {e}"
                )
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_delay)
                else:
                    return None
        return None


# ---------------------------------------------------------------------------
# Baseline Engine
# ---------------------------------------------------------------------------
class BaselineEngine:
    """Collect and analyze baseline responses for comparison."""

    def __init__(self, http_client: HTTPClient, normalizer: ResponseNormalizer, config: ScanConfig):
        self.http_client = http_client
        self.normalizer = normalizer
        self.config = config

    def collect_baseline(self, url: str, method: str, params: Optional[Dict] = None,
                         data: Optional[Dict] = None) -> BaselineSignature:
        """Collect a baseline signature from the target."""
        response = self.http_client.request(method, url, params=params, data=data)
        if response is None:
            return BaselineSignature()

        text = response.text[:self.config.max_response_size]
        normalized = self.normalizer.normalize(text)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""

        return BaselineSignature(
            status_code=response.status_code,
            response_length=len(response.text),
            content_type=response.headers.get("Content-Type", ""),
            title=title,
            normalized_body_hash=self.normalizer.hash_normalized(normalized),
            normalized_body_preview=normalized[:200],
            timestamp=time.time(),
        )

    def collect_multiple_baselines(self, url: str, method: str, params: Optional[Dict] = None,
                                   data: Optional[Dict] = None) -> List[BaselineSignature]:
        """Collect multiple baseline samples for stability analysis."""
        baselines = []
        for _ in range(self.config.baseline_samples):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                break
            sig = self.collect_baseline(url, method, params, data)
            if sig.status_code > 0:
                baselines.append(sig)
            else:
                break
        return baselines

    @staticmethod
    def is_stable(baselines: List[BaselineSignature]) -> bool:
        """Check if baseline samples are stable (low variance)."""
        if not baselines:
            return False
        if len(baselines) == 1:
            return True

        hashes = [b.normalized_body_hash for b in baselines if b.normalized_body_hash]
        if not hashes:
            return False

        # Check if all hashes are identical
        return len(set(hashes)) == 1


# ---------------------------------------------------------------------------
# Detection Engines
# ---------------------------------------------------------------------------
class ErrorDetector:
    """Error-based SQL injection detection using categorized signatures."""

    # Compiled regex patterns with weights
    # Format: (regex, database_type, weight)
    ERROR_PATTERNS = [
        # MySQL
        (re.compile(r"you have an error in your sql syntax", re.IGNORECASE), "mysql", 0.95),
        (re.compile(r"mysql_fetch_(array|row|assoc|object)", re.IGNORECASE), "mysql", 0.90),
        (re.compile(r"warning:\s+mysql_", re.IGNORECASE), "mysql", 0.85),
        (re.compile(r"mysqli::query\(\)", re.IGNORECASE), "mysql", 0.90),
        (re.compile(r"mysql_num_rows", re.IGNORECASE), "mysql", 0.85),
        # PostgreSQL
        (re.compile(r"pg_query\(\)", re.IGNORECASE), "postgresql", 0.90),
        (re.compile(r"postgresql.*error", re.IGNORECASE), "postgresql", 0.85),
        (re.compile(r"psql:.*syntax error", re.IGNORECASE), "postgresql", 0.90),
        (re.compile(r"syntax error at or near", re.IGNORECASE), "postgresql", 0.85),
        # MSSQL
        (re.compile(r"microsoft ole db provider for odbc drivers", re.IGNORECASE), "mssql", 0.90),
        (re.compile(r"odbc microsoft access driver", re.IGNORECASE), "mssql", 0.85),
        (re.compile(r"sql server.*error", re.IGNORECASE), "mssql", 0.85),
        (re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE), "mssql", 0.90),
        # Oracle
        (re.compile(r"ora-\d{4,5}", re.IGNORECASE), "oracle", 0.90),
        (re.compile(r"oracle.*error", re.IGNORECASE), "oracle", 0.80),
        (re.compile(r"quoted string not properly terminated", re.IGNORECASE), "oracle", 0.85),
        # SQLite
        (re.compile(r"sqlite3\.operationalerror", re.IGNORECASE), "sqlite", 0.90),
        (re.compile(r"sqlite3\.warning", re.IGNORECASE), "sqlite", 0.85),
        (re.compile(r"near \".*\": syntax error", re.IGNORECASE), "sqlite", 0.85),
        # Generic
        (re.compile(r"sql command not properly ended", re.IGNORECASE), None, 0.80),
        (re.compile(r"pdoexception", re.IGNORECASE), None, 0.75),
        (re.compile(r"sqlstate\[", re.IGNORECASE), None, 0.80),
        (re.compile(r"unterminated quoted string", re.IGNORECASE), None, 0.80),
    ]

    @classmethod
    def detect(cls, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Detect error-based SQL injection.
        Returns dict with database_type, matched_error, confidence, or None.
        """
        if not response_text:
            return None

        best_match = None
        best_weight = 0.0

        for regex, db_type, weight in cls.ERROR_PATTERNS:
            if regex.search(response_text):
                if weight > best_weight:
                    best_weight = weight
                    best_match = {
                        "database_type": db_type,
                        "matched_error": regex.pattern,
                        "confidence": weight,
                    }

        if best_match:
            return best_match
        return None


class BooleanDetector:
    """Boolean-based SQL injection detection using multi-signal comparison."""

    def __init__(self, config: ScanConfig, normalizer: ResponseNormalizer):
        self.config = config
        self.normalizer = normalizer

    def compare(self, baseline: BaselineSignature, true_response: requests.Response,
                false_response: requests.Response) -> Optional[Dict[str, Any]]:
        """
        Compare true/false responses to detect boolean-based injection.
        Returns dict with confidence, similarity_delta, status or None.
        """
        if true_response is None or false_response is None:
            return None

        # Get normalized texts
        true_text = self.normalizer.normalize(true_response.text[:self.config.max_response_size])
        false_text = self.normalizer.normalize(false_response.text[:self.config.max_response_size])
        baseline_text = baseline.normalized_body_preview

        # Compute similarities
        sim_true = self.normalizer.similarity(true_text, baseline_text) if baseline_text else 0.0
        sim_false = self.normalizer.similarity(false_text, baseline_text) if baseline_text else 0.0
        sim_true_false = self.normalizer.similarity(true_text, false_text)

        # Multi-signal analysis
        signals = []

        # Status code difference
        status_diff = abs(true_response.status_code - false_response.status_code)
        if status_diff > 0:
            signals.append(0.8)  # strong signal
        else:
            signals.append(0.2)

        # Length difference
        len_true = len(true_response.text)
        len_false = len(false_response.text)
        if max(len_true, len_false, 1) > 0:
            length_delta = abs(len_true - len_false) / max(len_true, len_false, 1)
            if length_delta > 0.1:
                signals.append(0.7)
            elif length_delta > 0.05:
                signals.append(0.5)
            else:
                signals.append(0.1)
        else:
            signals.append(0.1)

        # Similarity between true and false responses
        if sim_true_false < 0.9:  # They should differ significantly
            signals.append(0.7)
        else:
            signals.append(0.1)

        # Title difference
        title_true = re.search(r"<title[^>]*>(.*?)</title>", true_response.text, re.IGNORECASE | re.DOTALL)
        title_false = re.search(r"<title[^>]*>(.*?)</title>", false_response.text, re.IGNORECASE | re.DOTALL)
        if title_true and title_false:
            if title_true.group(1).strip() != title_false.group(1).strip():
                signals.append(0.6)
            else:
                signals.append(0.1)
        else:
            signals.append(0.2)

        # Calculate average signal
        confidence = sum(signals) / len(signals)

        # Only consider if confidence is high enough
        if confidence < self.config.confidence_threshold:
            return None

        return {
            "confidence": confidence,
            "similarity_true_baseline": sim_true,
            "similarity_false_baseline": sim_false,
            "similarity_true_false": sim_true_false,
            "length_delta": length_delta if 'length_delta' in locals() else 0.0,
            "status_diff": status_diff,
            "signal_count": len(signals),
            "signals": signals,
        }


class TimeDetector:
    """Time-based SQL injection detection using statistical analysis."""

    def __init__(self, config: ScanConfig, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client

    def detect(self, url: str, method: str, payload: str, param_name: str,
               static_params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Detect time-based injection by comparing baseline and injection timing.
        Uses multiple measurements to reduce false positives from network jitter.
        """
        baseline_times = []
        inject_times = []

        # Collect baseline timing samples (use a safe value)
        safe_payload = "1"
        for _ in range(max(2, self.config.baseline_samples)):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            if method.upper() == "GET":
                params = static_params.copy() if static_params else {}
                params[param_name] = safe_payload
                result = self.http_client.request(method, url, params=params, measure_time=True)
            else:
                data = static_params.copy() if static_params else {}
                data[param_name] = safe_payload
                result = self.http_client.request(method, url, data=data, measure_time=True)
            if result is not None:
                _, elapsed = result
                baseline_times.append(elapsed)

        # Collect injection timing samples
        for _ in range(2):  # 2 injection samples minimum
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            if method.upper() == "GET":
                params = static_params.copy() if static_params else {}
                params[param_name] = payload
                result = self.http_client.request(method, url, params=params, measure_time=True)
            else:
                data = static_params.copy() if static_params else {}
                data[param_name] = payload
                result = self.http_client.request(method, url, data=data, measure_time=True)
            if result is not None:
                _, elapsed = result
                inject_times.append(elapsed)

        if not baseline_times or not inject_times:
            return None

        # Statistical analysis
        baseline_sample = TimingSample(baseline_times)
        inject_sample = TimingSample(inject_times)

        baseline_mean = baseline_sample.mean()
        baseline_std = baseline_sample.std_dev()
        inject_mean = inject_sample.mean()
        inject_std = inject_sample.std_dev()

        delta = inject_mean - baseline_mean
        jitter = baseline_std + inject_std

        # Trigger condition: delta > threshold AND jitter is not too high
        if delta < self.config.time_trigger:
            return None

        # Compute confidence based on delta and consistency
        if jitter > 0:
            consistency = 1.0 - min(jitter / delta, 1.0)
        else:
            consistency = 1.0

        # Scale confidence: higher delta = higher confidence
        delta_factor = min(delta / (self.config.time_trigger * 2), 1.0)
        confidence = 0.5 + 0.5 * delta_factor * consistency

        if confidence < self.config.confidence_threshold:
            return None

        return {
            "baseline_mean": baseline_mean,
            "baseline_std": baseline_std,
            "inject_mean": inject_mean,
            "inject_std": inject_std,
            "delta": delta,
            "jitter": jitter,
            "consistency": consistency,
            "confidence": confidence,
        }


class UnionDetector:
    """Union-based SQL injection detection (safe, no data dumping)."""

    def __init__(self, config: ScanConfig, normalizer: ResponseNormalizer):
        self.config = config
        self.normalizer = normalizer

    def detect(self, baseline: BaselineSignature, response: requests.Response,
               payload: str) -> Optional[Dict[str, Any]]:
        """
        Detect union-based injection by analyzing structural changes in response.
        No data extraction; only confirms the vulnerability.
        """
        if response is None:
            return None

        text = self.normalizer.normalize(response.text[:self.config.max_response_size])
        baseline_text = baseline.normalized_body_preview

        # Compute similarity between baseline and injected response
        similarity = self.normalizer.similarity(text, baseline_text) if baseline_text else 0.0

        # Union injection should cause a moderate change (columns changed)
        # But not a complete change (page still loads)
        signals = []

        # Status code should be 200 (successful union)
        if response.status_code == 200:
            signals.append(0.5)
        else:
            signals.append(0.1)

        # Length difference
        len_diff = abs(len(response.text) - baseline.response_length)
        len_ratio = len_diff / max(baseline.response_length, 1)
        if len_ratio > 0.05:
            signals.append(0.6)
        else:
            signals.append(0.2)

        # Similarity: not too similar (change occurred), not too different (not error page)
        if 0.3 <= similarity <= 0.85:
            signals.append(0.7)
        else:
            signals.append(0.2)

        confidence = sum(signals) / len(signals)

        if confidence < self.config.confidence_threshold:
            return None

        return {
            "similarity": similarity,
            "length_diff": len_diff,
            "length_ratio": len_ratio,
            "confidence": confidence,
        }


# ---------------------------------------------------------------------------
# Confidence Engine
# ---------------------------------------------------------------------------
class ConfidenceEngine:
    """Calculate confidence scores from detection evidence."""

    @staticmethod
    def classify(confidence: float) -> str:
        """Classify confidence level."""
        if confidence >= 0.95:
            return "critical"
        if confidence >= 0.80:
            return "high"
        if confidence >= 0.60:
            return "medium"
        if confidence >= 0.30:
            return "low"
        return "informational"

    @staticmethod
    def severity_from_confidence_and_technique(confidence: float, technique: str) -> str:
        """Determine severity based on confidence and technique."""
        if technique == "error-based":
            base_severity = 0.8
        elif technique == "boolean-based":
            base_severity = 0.7
        elif technique == "time-based":
            base_severity = 0.6
        elif technique == "union-based":
            base_severity = 0.65
        else:
            base_severity = 0.5

        score = base_severity * confidence
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        return "informational"


# ---------------------------------------------------------------------------
# Finding Validator
# ---------------------------------------------------------------------------
class FindingValidator:
    """Classify findings based on evidence quality."""

    @staticmethod
    def classify_status(confidence: float, technique: str, evidence: Dict[str, Any]) -> str:
        """Determine validation status based on evidence quality."""
        if confidence >= 0.85:
            return "confirmed"
        elif confidence >= 0.60:
            return "probable"
        elif confidence >= 0.40:
            return "possible"
        elif confidence >= 0.25:
            return "inconclusive"
        else:
            return "blocked"  # likely false positive or blocked by WAF


# ---------------------------------------------------------------------------
# Scan Result Models
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    """Top-level scan result containing all metadata and findings."""
    url: str = ""
    method: str = "GET"
    parameters_tested: List[str] = field(default_factory=list)
    payloads_tested: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    vulnerable: bool = False
    status: str = "unknown"
    scan_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration: float = 0.0
    requests_sent: int = 0
    errors: int = 0
    warnings: List[str] = field(default_factory=list)
    techniques_tested: List[str] = field(default_factory=list)
    database_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            # Original required keys
            "url": self.url,
            "method": self.method,
            "parameters_tested": self.parameters_tested,
            "payloads_tested": self.payloads_tested,
            "findings": [f.to_dict() for f in self.findings],
            "vulnerable": self.vulnerable,
            # Additional metadata
            "status": self.status,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
            "requests_sent": self.requests_sent,
            "errors": self.errors,
            "warnings": self.warnings,
            "techniques_tested": self.techniques_tested,
            "database_hint": self.database_hint,
        }


# ---------------------------------------------------------------------------
# SQLi Scanner (Main Class)
# ---------------------------------------------------------------------------
class SQLiScanner:
    """Production-grade SQL injection scanner with adaptive pipeline."""

    def __init__(self, config: Optional[ScanConfig] = None,
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.config = config or ScanConfig()
        self.config.validate()
        self.headers = headers
        self.cookies = cookies
        self.proxies = proxies
        self.normalizer = ResponseNormalizer()
        self.http_client = HTTPClient(
            self.config,
            headers=self.headers,
            cookies=self.cookies,
            proxies=self.proxies,
        )
        self.baseline_engine = BaselineEngine(self.http_client, self.normalizer, self.config)
        self.error_detector = ErrorDetector()
        self.boolean_detector = BooleanDetector(self.config, self.normalizer)
        self.time_detector = TimeDetector(self.config, self.http_client)
        self.union_detector = UnionDetector(self.config, self.normalizer)
        self.confidence_engine = ConfidenceEngine()
        self.validator = FindingValidator()
        self._findings_fingerprints = set()
        self.errors = 0  # count of transport/detection errors encountered

    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params = {}
        for key, values in query_params.items():
            if values:
                params[key] = values[0]
            else:
                params[key] = ""
        return params

    def _should_stop(self) -> bool:
        """Check if scan should stop (cancellation or budget)."""
        if self.config.stop_event is not None and self.config.stop_event.is_set():
            return True
        if self.http_client._request_count >= self.config.max_requests:
            return True
        return False

    def _deduplicate_finding(self, finding: ScanFinding) -> bool:
        """Check if finding is duplicate. Returns True if new (not duplicate)."""
        fingerprint = (
            finding.parameter,
            finding.technique,
            finding.database_type or "",
            finding.status,
        )
        if fingerprint in self._findings_fingerprints:
            return False
        self._findings_fingerprints.add(fingerprint)
        return True

    def _scan_error_based(self, url: str, method: str, param_name: str,
                          static_params: Dict[str, str], payloads: List[Payload]) -> List[ScanFinding]:
        """Scan for error-based SQL injection."""
        findings = []
        for payload in payloads:
            if self._should_stop():
                break

            if method.upper() == "GET":
                params = static_params.copy() if static_params else {}
                params[param_name] = payload.value
                response = self.http_client.request(method, url, params=params)
            else:
                data = static_params.copy() if static_params else {}
                data[param_name] = payload.value
                response = self.http_client.request(method, url, data=data)

            if response is None:
                self.errors += 1
                continue

            detection = self.error_detector.detect(response.text)
            if detection:
                confidence = detection["confidence"]
                status = self.validator.classify_status(confidence, "error-based", detection)
                finding = ScanFinding(
                    parameter=param_name,
                    technique="error-based",
                    confidence=confidence,
                    severity=self.confidence_engine.severity_from_confidence_and_technique(confidence, "error-based"),
                    status=status,
                    database_type=detection["database_type"],
                    evidence={
                        "status_code": response.status_code,
                        "matched_error": detection["matched_error"],
                    },
                    matched_error=detection["matched_error"],
                    payload=payload.value,
                    response_status=response.status_code,
                )
                if self._deduplicate_finding(finding):
                    findings.append(finding)
                    # Early stopping on high confidence
                    if not self.config.continue_after_detection and confidence >= 0.8:
                        break
        return findings

    def _scan_boolean_based(self, url: str, method: str, param_name: str,
                            static_params: Dict[str, str], baseline: BaselineSignature) -> List[ScanFinding]:
        """Scan for boolean-based SQL injection."""
        findings = []
        true_payloads, false_payloads = PayloadRegistry.get_boolean_payloads()

        for true_p, false_p in zip(true_payloads, false_payloads):
            if self._should_stop():
                break

            # Send true condition
            if method.upper() == "GET":
                params_true = static_params.copy() if static_params else {}
                params_true[param_name] = true_p.value
                response_true = self.http_client.request(method, url, params=params_true)
            else:
                data_true = static_params.copy() if static_params else {}
                data_true[param_name] = true_p.value
                response_true = self.http_client.request(method, url, data=data_true)

            if response_true is None:
                self.errors += 1
                continue

            # Send false condition
            if method.upper() == "GET":
                params_false = static_params.copy() if static_params else {}
                params_false[param_name] = false_p.value
                response_false = self.http_client.request(method, url, params=params_false)
            else:
                data_false = static_params.copy() if static_params else {}
                data_false[param_name] = false_p.value
                response_false = self.http_client.request(method, url, data=data_false)

            if response_false is None:
                self.errors += 1
                continue

            detection = self.boolean_detector.compare(baseline, response_true, response_false)
            if detection:
                confidence = detection["confidence"]
                status = self.validator.classify_status(confidence, "boolean-based", detection)
                finding = ScanFinding(
                    parameter=param_name,
                    technique="boolean-based",
                    confidence=confidence,
                    severity=self.confidence_engine.severity_from_confidence_and_technique(confidence, "boolean-based"),
                    status=status,
                    database_type=None,
                    evidence=detection,
                    payload=true_p.value,
                    response_status=response_true.status_code,
                    baseline_length=baseline.response_length,
                    response_length=len(response_true.text),
                    similarity=detection.get("similarity_true_false"),
                )
                if self._deduplicate_finding(finding):
                    findings.append(finding)
                    if not self.config.continue_after_detection and confidence >= 0.8:
                        break
        return findings

    def _scan_time_based(self, url: str, method: str, param_name: str,
                         static_params: Dict[str, str], payloads: List[Payload]) -> List[ScanFinding]:
        """Scan for time-based SQL injection."""
        findings = []
        for payload in payloads:
            if self._should_stop():
                break

            detection = self.time_detector.detect(
                url, method, payload.value, param_name, static_params
            )
            if detection:
                confidence = detection["confidence"]
                status = self.validator.classify_status(confidence, "time-based", detection)
                finding = ScanFinding(
                    parameter=param_name,
                    technique="time-based",
                    confidence=confidence,
                    severity=self.confidence_engine.severity_from_confidence_and_technique(confidence, "time-based"),
                    status=status,
                    database_type=payload.database,
                    evidence=detection,
                    payload=payload.value,
                )
                if self._deduplicate_finding(finding):
                    findings.append(finding)
                    if not self.config.continue_after_detection and confidence >= 0.8:
                        break
        return findings

    def _scan_union_based(self, url: str, method: str, param_name: str,
                          static_params: Dict[str, str], baseline: BaselineSignature,
                          payloads: List[Payload]) -> List[ScanFinding]:
        """Scan for union-based SQL injection."""
        findings = []
        for payload in payloads:
            if self._should_stop():
                break

            if method.upper() == "GET":
                params = static_params.copy() if static_params else {}
                params[param_name] = payload.value
                response = self.http_client.request(method, url, params=params)
            else:
                data = static_params.copy() if static_params else {}
                data[param_name] = payload.value
                response = self.http_client.request(method, url, data=data)

            if response is None:
                self.errors += 1
                continue

            detection = self.union_detector.detect(baseline, response, payload.value)
            if detection:
                confidence = detection["confidence"]
                status = self.validator.classify_status(confidence, "union-based", detection)
                finding = ScanFinding(
                    parameter=param_name,
                    technique="union-based",
                    confidence=confidence,
                    severity=self.confidence_engine.severity_from_confidence_and_technique(confidence, "union-based"),
                    status=status,
                    database_type=None,
                    evidence=detection,
                    payload=payload.value,
                    response_status=response.status_code,
                    baseline_length=baseline.response_length,
                    response_length=len(response.text),
                    similarity=detection.get("similarity"),
                )
                if self._deduplicate_finding(finding):
                    findings.append(finding)
                    if not self.config.continue_after_detection and confidence >= 0.8:
                        break
        return findings

    def scan(self, url: str, method: str = "GET",
             params: Optional[Dict[str, str]] = None,
             payloads: Optional[List[str]] = None) -> ScanResult:
        """
        Run SQL injection scan with adaptive pipeline.

        Args:
            url: Target URL.
            method: HTTP method (GET or POST).
            params: Parameters to test. If None, extract from URL query.
            payloads: Custom payload list. If None, use default registry.

        Returns:
            ScanResult object (also .to_dict() available for JSON).
        """
        scan_id = uuid.uuid4().hex[:12]
        started_at = datetime.now(timezone.utc).isoformat()
        scan_start_perf = time.time()

        # Initialize result
        result = ScanResult()
        result.scan_id = scan_id
        result.started_at = started_at
        result.url = url
        result.method = method
        result.status = "running"

        # Validate URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            result.status = "error"
            result.warnings.append("Invalid URL")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        # Discover parameters
        if params is None:
            params = self.extract_parameters(url)
            if not params:
                params = {"q": ""}
        if not params:
            params = {"q": ""}

        result.parameters_tested = list(params.keys())

        # Determine techniques to test
        techniques = []
        if self.config.test_error:
            techniques.append("error")
        if self.config.test_boolean:
            techniques.append("boolean")
        if self.config.test_time:
            techniques.append("time")
        if self.config.test_union:
            techniques.append("union")
        result.techniques_tested = techniques

        # Collect baseline
        baseline_samples = self.baseline_engine.collect_multiple_baselines(
            url, method,
            params=params if method.upper() == "GET" else None,
            data=params if method.upper() == "POST" else None,
        )
        if not baseline_samples:
            result.status = "error"
            result.warnings.append("Failed to collect baseline")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        baseline = baseline_samples[0]  # Use first (or most stable)
        baseline_stable = self.baseline_engine.is_stable(baseline_samples)
        if not baseline_stable:
            result.warnings.append("Baseline is unstable; results may be less reliable")

        # Track payloads count
        total_payloads = 0

        # Scan each parameter
        for param_name, param_value in params.items():
            if self._should_stop():
                break

            static_params = {k: v for k, v in params.items() if k != param_name}

            # Build payload list (respect custom payloads or use registry)
            if payloads:
                error_payloads = [Payload(p, "error", None, "low", "") for p in payloads]
                time_payloads = [Payload(p, "time", None, "low", "") for p in payloads if "sleep" in p.lower() or "waitfor" in p.lower() or "pg_sleep" in p.lower()]
                union_payloads = [Payload(p, "union", None, "low", "") for p in payloads if "union" in p.lower()]
                boolean_payloads = True  # use default boolean pairs
            else:
                error_payloads = PayloadRegistry.get_error_payloads(None)  # Start with generic
                time_payloads = PayloadRegistry.get_time_payloads(None)
                union_payloads = PayloadRegistry.get_union_payloads()
                boolean_payloads = True

            # Run error-based detection
            if self.config.test_error and error_payloads:
                total_payloads += len(error_payloads)
                findings = self._scan_error_based(
                    url, method, param_name, static_params, error_payloads
                )
                for f in findings:
                    result.findings.append(f)

            # Run boolean-based detection
            if self.config.test_boolean and boolean_payloads:
                total_payloads += 2 * len(PayloadRegistry.BOOLEAN_TRUE)  # pairs
                findings = self._scan_boolean_based(
                    url, method, param_name, static_params, baseline
                )
                for f in findings:
                    result.findings.append(f)

            # Run time-based detection
            if self.config.test_time and time_payloads:
                total_payloads += len(time_payloads)
                findings = self._scan_time_based(
                    url, method, param_name, static_params, time_payloads
                )
                for f in findings:
                    result.findings.append(f)

            # Run union-based detection
            if self.config.test_union and union_payloads:
                total_payloads += len(union_payloads)
                findings = self._scan_union_based(
                    url, method, param_name, static_params, baseline, union_payloads
                )
                for f in findings:
                    result.findings.append(f)

            # Early stopping check
            if self.http_client._request_count >= self.config.max_requests:
                result.status = "request_budget_exhausted"
                break

        # Finalize result
        result.payloads_tested = total_payloads
        result.requests_sent = self.http_client._request_count
        result.errors = self.errors
        result.vulnerable = len(result.findings) > 0
        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.duration = round(time.time() - scan_start_perf, 3)
        result.status = "completed"

        # Database hint from most confident finding
        if result.findings:
            confident_db = [f.database_type for f in result.findings if f.database_type and f.confidence >= 0.5]
            if confident_db:
                result.database_hint = max(set(confident_db), key=confident_db.count)

        return result


# ---------------------------------------------------------------------------
# Integration Adapter
# ---------------------------------------------------------------------------
def run_sql_injection_scan(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_threads: int = DEFAULT_MAX_THREADS,
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
    test_boolean: bool = True,
    test_error: bool = True,
    test_time: bool = True,
    test_union: bool = True,
    time_based_trigger: float = DEFAULT_TIME_TRIGGER,
    boolean_threshold: float = DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD,
    **kwargs,
) -> Dict:
    """
    Backward-compatible entry point for AnalyticDataManager integration.

    Returns a dictionary containing all original keys plus additional metadata.
    """
    config = ScanConfig(
        timeout=timeout,
        max_threads=max_threads,
        verify_ssl=verify_ssl,
        test_boolean=test_boolean,
        test_error=test_error,
        test_time=test_time,
        test_union=test_union,
        time_trigger=time_based_trigger,
        boolean_similarity_threshold=boolean_threshold,
    )

    # Apply any additional kwargs to config if they match
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    scanner = SQLiScanner(
        config=config,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
    )
    result = scanner.scan(url, method, params, payloads)
    return result.to_dict()


def _normalize_url(target: str) -> str:
    """Ensure the target has a scheme so the scanner can validate + reach it."""
    t = (target or "").strip()
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t


def run(target: str, mode: str = "basic", **kwargs) -> dict:
    """Scan orchestrator entry point.

    Basic  : error-based + boolean-blind (fast, low request budget).
    Expert : all four techniques (error / boolean / time / union).

    Returns the framework's standard envelope with a ``scan_type`` marker and a
    ``severity`` derived from the strongest finding so the dashboard can colour it.
    """
    url = _normalize_url(target)

    if mode == "expert":
        techniques = dict(test_error=True, test_boolean=True, test_time=True, test_union=True)
        max_threads = int(kwargs.get("max_threads", 10))
    else:
        techniques = dict(test_error=True, test_boolean=True, test_time=False, test_union=False)
        max_threads = int(kwargs.get("max_threads", 8))

    try:
        result = run_sql_injection_scan(
            url=url,
            method=str(kwargs.get("method", "GET")),
            params=kwargs.get("params"),
            timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
            max_threads=max_threads,
            verify_ssl=bool(kwargs.get("verify_ssl", False)),
            **techniques,
        )

        vulnerable = bool(result.get("vulnerable"))
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_sev, top_rank = "safe", 0
        for finding in result.get("findings", []):
            sev = str(finding.get("severity", "")).lower()
            if sev_rank.get(sev, 0) > top_rank:
                top_rank, top_sev = sev_rank[sev], sev

        result["scan_type"] = "sqli"
        result["mode"] = mode
        result["severity"] = top_sev if vulnerable else "safe"
        result["summary"] = (
            f"{len(result.get('findings', []))} SQL injection point(s) found"
            if vulnerable else "No SQL injection detected"
        )
        return {
            "tool": "sql_map",
            "version": __version__,
            "target": target,
            "data": result,
            "error": None,
        }
    except Exception as e:
        logger.error("SQLi run() failed for %s: %s", url, e, exc_info=True)
        return {
            "tool": "sql_map",
            "version": __version__,
            "target": target,
            "data": {"url": url, "scan_type": "sqli", "vulnerable": False, "findings": []},
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    """Command-line interface for the SQLi scanner."""
    parser = argparse.ArgumentParser(
        description="Oxysintx SQL Injection Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-p", "--param", action="append", help="Parameter to test (name=value)")
    parser.add_argument("--data", help="POST data as query string")
    parser.add_argument("--header", action="append", help="Custom header (Key: Value)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout")
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_THREADS, help="Max threads")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS, help="Max requests")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Request delay (seconds)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry count")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--technique", action="append", choices=["error", "boolean", "time", "union"], help="Technique to test")
    parser.add_argument("--dbms", choices=["mysql", "postgresql", "mssql", "oracle", "sqlite"], help="Target database type")
    parser.add_argument("--confidence-threshold", type=float, default=DEFAULT_CONFIDENCE_THRESHOLD, help="Confidence threshold")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--pretty-json", action="store_true", help="Pretty print JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Build headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()

    # Build cookies
    cookies = None
    if args.cookie:
        cookies = {}
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    # Build proxies
    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    # Parse params
    params = {}
    if args.param:
        for p in args.param:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
            else:
                params[p] = ""
    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v

    # Build config
    config = ScanConfig(
        timeout=args.timeout,
        max_threads=args.threads,
        verify_ssl=args.verify_ssl,
        follow_redirects=args.follow_redirects,
        max_requests=args.max_requests,
        request_delay=args.rate_limit,
        retries=args.retries,
        confidence_threshold=args.confidence_threshold,
    )

    # Apply technique filters
    if args.technique:
        config.test_error = "error" in args.technique
        config.test_boolean = "boolean" in args.technique
        config.test_time = "time" in args.technique
        config.test_union = "union" in args.technique

    # Run scan
    scanner = SQLiScanner(
        config=config,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
    )
    result = scanner.scan(args.url, args.method, params if params else None)

    # Prepare output
    if args.json or args.pretty_json:
        output_data = result.to_dict()
        if args.pretty_json:
            output_str = json.dumps(output_data, indent=2)
        else:
            output_str = json.dumps(output_data)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_str)
        if not args.quiet:
            print(output_str)
    else:
        # Human-readable output
        lines = []
        lines.append("Oxysintx SQL Injection Scanner")
        lines.append("─" * 36)
        lines.append(f"Target       : {result.url}")
        lines.append(f"Method       : {result.method}")
        lines.append(f"Parameters   : {', '.join(result.parameters_tested) or 'none'}")
        lines.append(f"Techniques   : {', '.join(result.techniques_tested)}")
        lines.append("")
        lines.append(f"Scan status  : {result.status}")
        lines.append(f"Requests     : {result.requests_sent}")
        lines.append(f"Duration     : {result.duration:.2f}s")
        lines.append("")
        if result.findings:
            lines.append("Findings")
            lines.append("─" * 36)
            for f in result.findings:
                confidence_label = ConfidenceEngine.classify(f.confidence)
                lines.append(f"[{confidence_label.upper()}] {f.parameter}")
                lines.append(f"  Technique   : {f.technique}")
                lines.append(f"  Confidence  : {f.confidence:.2f}")
                lines.append(f"  DBMS        : {f.database_type or 'unknown'}")
                lines.append(f"  Status      : {f.status}")
                lines.append("")
        else:
            lines.append("No vulnerabilities detected.")
        output_str = "\n".join(lines)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_str)
        if not args.quiet:
            print(output_str)


if __name__ == "__main__":
    main()
