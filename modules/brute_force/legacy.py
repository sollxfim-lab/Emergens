# modules/brute_force/legacy.py
"""v1 compatibility layer for AnalyticDataManager and any other legacy caller.

Keeps the old BruteForceAttack surface alive while the engine internals
are the v2 package. Delete this file once every caller has migrated to
BruteForceEngine / AttackConfig / run().
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .engine import BruteForceEngine
from .models import AttackConfig, Credential
from .wordlist import WordlistProvider

logger = logging.getLogger("oxysintx.brute_force.legacy")

_DEFAULT_WORDLIST_DIR = Path(__file__).resolve().parent.parent.parent / "brute-force-text"

# v1 default when the caller does not pass anything.
_V1_DEFAULT_TIMEOUT = 2.0
_V1_MAX_WORKERS = 600
_V1_MAX_FILES = 10

# v1 protocol -> port map (matches old port_map in run_full_attack).
_V1_PORT_MAP = {
    "http": 80, "https": 443, "ftp": 21, "ssh": 22,
    "mysql": 3306, "postgresql": 5432, "redis": 6379,
    "smb": 445, "rdp": 3389, "telnet": 23,
}


class _LegacyWordlistMixin:
    """Re-implements v1's 'data1.txt -> data1.txt .. dataN.txt' loader."""

    @staticmethod
    def _legacy_load(file_pattern: str, max_files: int = _V1_MAX_FILES) -> List[str]:
        base, _, ext = file_pattern.partition(".") or (file_pattern, "", "txt")
        if not ext:
            ext = "txt"

        entries: List[str] = []
        seen: set[str] = set()
        for index in range(1, max_files + 1):
            filename = file_pattern if index == 1 else f"{base}{index}.{ext}"
            path = _DEFAULT_WORDLIST_DIR / filename
            if not path.exists():
                logger.info("Legacy wordlist %s not found, stopping scan", filename)
                break
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    for raw in handle:
                        line = raw.strip()
                        if line and not line.startswith("#") and line not in seen:
                            seen.add(line)
                            entries.append(line)
            except OSError as exc:
                logger.error("Failed to read %s: %s", path, exc)
                break
        return entries


class BruteForceAttack(_LegacyWordlistMixin):
    """v1-compatible facade over BruteForceEngine.

    Drop-in replacement for the old ``modules.brute_force.BruteForceAttack``
    class so that ``AnalyticDataManager`` keeps working without changes.
    """

    def __init__(self, max_workers: int = _V1_MAX_WORKERS) -> None:
        self.max_workers = max_workers
        self._engine: Optional[BruteForceEngine] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        # v1 attribute; still populated by run_full_attack so old callers
        # that read `attack.results` keep working.
        self.results: List[Dict[str, Any]] = []

    # -- lifecycle -----------------------------------------------------
    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            if self._engine is not None:
                self._engine.stop()

    # -- wordlists -----------------------------------------------------
    def load_wordlist(self, file_pattern: str = "data1.txt", max_files: int = _V1_MAX_FILES) -> List[str]:
        return self._legacy_load(file_pattern, max_files)

    # -- run -----------------------------------------------------------
    def run_full_attack(
        self,
        target: str,
        protocols: Optional[List[str]] = None,
        username_file: str = "data1.txt",
        password_file: str = "data1.txt",
    ) -> Dict[str, Any]:
        """v1 return shape preserved exactly.

        {
          "target": ...,
          "protocols_tested": [...],
          "results": {proto: {"successful": int, "credentials": [...]}},
          "total_successful": int,
        }
        """
        protocols = protocols or ["http", "ftp", "ssh"]

        usernames = self.load_wordlist(username_file)
        passwords = self.load_wordlist(password_file)
        if not usernames or not passwords:
            return {
                "error": "Wordlist empty",
                "target": target,
                "protocols_tested": protocols,
                "results": {},
                "total_successful": 0,
            }

        config = AttackConfig(
            max_workers=self.max_workers,
            attempt_timeout=_V1_DEFAULT_TIMEOUT,
            connect_timeout=_V1_DEFAULT_TIMEOUT,
            max_attempts_per_protocol=0,          # v1 had no cap
            stop_on_first_success=False,          # v1 kept going
            wordlist_dir=_DEFAULT_WORDLIST_DIR,
        )

        engine = BruteForceEngine(
            config,
            wordlists=WordlistProvider(_DEFAULT_WORDLIST_DIR),
        )
        with self._lock:
            self._engine = engine

        # Honour a stop() issued before the engine existed.
        if self._stop_event.is_set():
            engine.stop()

        report = engine.attack(
            target,
            protocols=protocols,
            username_source=username_file,
            password_source=password_file,
            ports={p: _V1_PORT_MAP[p] for p in protocols if p in _V1_PORT_MAP},
        )

        # Translate v2 AttackReport -> v1 dict.
        v1_results: Dict[str, Dict[str, Any]] = {}
        for name, proto_report in report.protocols.items():
            credentials = [
                {"username": c.username, "password": c.password, "status": "success"}
                for c in proto_report.successes
            ]
            v1_results[name] = {
                "successful": len(credentials),
                "credentials": credentials,
            }

        # Mirror into self.results for any legacy reader.
        self.results = [
            {"type": f"{p}_login", "target": target, "port": _V1_PORT_MAP.get(p, 0),
             "username": c["username"], "password": c["password"]}
            for p, block in v1_results.items()
            for c in block["credentials"]
        ]

        return {
            "target": target,
            "protocols_tested": protocols,
            "results": v1_results,
            "total_successful": report.total_successes,
        }

    # -- per-protocol helpers (kept for callers that used them directly) ----
    def brute_http_login(self, target, port, username_list, password_list,
                         login_url="/login", method="POST",
                         username_field="username", password_field="password"):
        return self._run_single("http", target, port, username_list, password_list,
                                port_map_override=port)

    def brute_ftp_login(self, target, username_list, password_list, port=21):
        return self._run_single("ftp", target, port, username_list, password_list)

    def brute_ssh_login(self, target, username_list, password_list, port=22):
        return self._run_single("ssh", target, port, username_list, password_list)

    def brute_mysql_login(self, target, username_list, password_list, port=3306):
        return self._run_single("mysql", target, port, username_list, password_list)

    def brute_postgresql_login(self, target, username_list, password_list, port=5432):
        return self._run_single("postgresql", target, port, username_list, password_list)

    def brute_redis_login(self, target, password_list, port=6379):
        return self._run_single("redis", target, port, None, password_list)

    def brute_smb_login(self, target, username_list, password_list):
        return self._run_single("smb", target, 445, username_list, password_list)

    # -- internals -----------------------------------------------------
    def _run_single(self, protocol, target, port, usernames, passwords, **_) -> List[Dict[str, Any]]:
        """Executes one protocol with an inline wordlist and returns v1 rows."""
        config = AttackConfig(
            max_workers=min(self.max_workers, max(1, (len(usernames or [""])) * len(passwords))),
            attempt_timeout=_V1_DEFAULT_TIMEOUT,
            connect_timeout=_V1_DEFAULT_TIMEOUT,
            max_attempts_per_protocol=0,
            stop_on_first_success=False,
            wordlist_dir=_DEFAULT_WORDLIST_DIR,
        )
        engine = BruteForceEngine(config, wordlists=WordlistProvider(_DEFAULT_WORDLIST_DIR))
        report = engine.attack(
            target,
            protocols=[protocol],
            username_source=list(usernames or [""]),
            password_source=list(passwords),
            ports={protocol: port},
        )
        block = report.protocols.get(protocol)
        if block is None:
            return []
        return [
            {"username": c.username, "password": c.password, "status": "success"}
            for c in block.successes
        ]
