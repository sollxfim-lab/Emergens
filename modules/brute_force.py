# modules/brute_force/__init__.py
"""
Oxysintx brute-force engine — package entry point.

Two consumers:

1. scan_orchestrator.py  →  calls run(target, mode, **tool_options)
2. analytic_manager / direct imports
                         →  uses BruteForceEngine, AttackConfig, ...

Contract with scan_orchestrator.py
----------------------------------
    run(target: str, mode: str, **kwargs) -> dict
        -> {"tool": "brute_force", "target": ..., "data": {...}, "error": None|str}

    TOOL_INFO = {"name": ..., "version": ..., "description": ..., ...}

Any kwarg not recognised is ignored so that the orchestrator can safely
forward its global `tool_options` dict to every tool.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .engine import BruteForceEngine, RateLimiter
from .models import (
    AttackConfig,
    AttackReport,
    AttemptResult,
    Credential,
    Outcome,
    ProtocolReport,
)
from .wordlist import WordlistError, WordlistProvider

__version__ = "2.0.0"

logger = logging.getLogger("oxysintx.brute_force")

# The orchestrator lives in modules/scan_orchestrator.py, so the project
# root is two levels above this package's directory.
_DEFAULT_WORDLIST_DIR = Path(__file__).resolve().parent.parent.parent / "brute-force-text"

# Protocol sets per mode. Anything not present here is still selectable
# explicitly via tool_options["protocols"].
_BASIC_PROTOCOLS: List[str] = ["ssh", "ftp"]
_EXPERT_PROTOCOLS: List[str] = [
    "http",
    "ftp",
    "ssh",
    "mysql",
    "postgresql",
    "redis",
    "smb",
]

# Per-mode scope. Basic mode is deliberately shallow so it can run inside
# an orchestrator job without generating lockout-inducing traffic.
_BASIC_MAX_ATTEMPTS = 50
_EXPERT_MAX_ATTEMPTS = 2000


# ---------------------------------------------------------------------------
# Orchestrator contract
# ---------------------------------------------------------------------------
TOOL_INFO: Dict[str, Any] = {
    "name": "brute_force",
    "display_name": "Brute Force Engine",
    "version": __version__,
    "description": (
        "Multi-protocol credential testing (HTTP, FTP, SSH, MySQL, "
        "PostgreSQL, Redis, SMB)."
    ),
    "modes": ["basic", "expert"],
    "mode_defaults": {
        "basic": {
            "protocols": _BASIC_PROTOCOLS,
            "max_attempts_per_protocol": _BASIC_MAX_ATTEMPTS,
            "stop_on_first_success": True,
        },
        "expert": {
            "protocols": _EXPERT_PROTOCOLS,
            "max_attempts_per_protocol": _EXPERT_MAX_ATTEMPTS,
            "stop_on_first_success": False,
        },
    },
    "supports_cancel_event": True,
    "options": {
        "protocols": "list[str] — override the protocol set",
        "ports": "dict[str, int] — protocol -> port overrides",
        "usernames": "list[str] | str — inline list or wordlist filename",
        "passwords": "list[str] | str — inline list or wordlist filename",
        "wordlist_dir": "str — directory holding wordlist files",
        "workers": "int — max concurrent workers",
        "rate": "float — global attempts per second",
        "jitter": "float — 0.0-1.0 randomisation of the rate interval",
        "timeout": "float — per-attempt timeout (seconds)",
        "connect_timeout": "float — connection timeout (seconds)",
        "max_attempts": "int — cap on attempts per protocol (0 = unlimited)",
        "stop_on_success": "bool — stop a protocol after first valid credential",
        "verify_tls": "bool — verify TLS certificates (default True)",
        "cancel_event": "threading.Event — cooperative cancellation",
    },
}


def run(target: str, mode: str = "basic", **kwargs: Any) -> Dict[str, Any]:
    """Entry point used by ``scan_orchestrator.ScanOrchestrator``.

    Parameters
    ----------
    target:
        Hostname or IP address to test.
    mode:
        ``"basic"`` or ``"expert"``. Unknown values fall back to ``"basic"``.
    **kwargs:
        Arbitrary tool options. Unknown keys are ignored so the orchestrator
        can forward its global ``tool_options`` dict unchanged.

    Returns
    -------
    dict
        ``{"tool": "brute_force", "target": target, "data": {...}, "error": None|str}``
    """
    started = time.time()
    mode = (mode or "basic").lower()
    if mode not in ("basic", "expert"):
        logger.warning("Unknown mode %r, falling back to 'basic'", mode)
        mode = "basic"

    try:
        config = _build_config(mode, kwargs)
        protocols = _resolve_protocols(mode, kwargs)
        ports = _resolve_ports(kwargs)
        username_source, password_source = _resolve_wordlists(kwargs)

        engine = BruteForceEngine(
            config,
            wordlists=WordlistProvider(config.wordlist_dir),
        )

        _wire_cancellation(engine, kwargs.get("cancel_event"))
        _wire_success_logging(engine)

        logger.info(
            "brute_force: target=%s mode=%s protocols=%s",
            target, mode, protocols,
        )

        report: AttackReport = engine.attack(
            target,
            protocols=protocols,
            username_source=username_source,
            password_source=password_source,
            ports=ports,
        )

        data = report.to_dict()
        data["mode"] = mode
        data["started_at"] = started
        data["finished_at"] = time.time()

        return {
            "tool": TOOL_INFO["name"],
            "target": target,
            "data": data,
            "error": None,
        }

    except (WordlistError, ValueError, KeyError) as exc:
        # Expected configuration / scope problems — surface cleanly.
        logger.error("brute_force: %s", exc)
        return _error_response(target, str(exc), started)
    except Exception as exc:  # noqa: BLE001 — orchestrator contract
        logger.exception("brute_force: unexpected failure")
        return _error_response(target, f"{type(exc).__name__}: {exc}", started)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_config(mode: str, kwargs: Dict[str, Any]) -> AttackConfig:
    """Translate orchestrator kwargs into an AttackConfig.

    All keys are optional. Missing keys fall back to mode-appropriate defaults.
    """
    defaults = TOOL_INFO["mode_defaults"][mode]

    wordlist_dir = Path(kwargs.get("wordlist_dir", _DEFAULT_WORDLIST_DIR))

    # Accept either the CLI-style key names or the shorter module-style names.
    workers = kwargs.get("workers") or kwargs.get("max_workers") or 32
    max_attempts = kwargs.get(
        "max_attempts",
        defaults["max_attempts_per_protocol"],
    )
    stop_on_success = kwargs.get(
        "stop_on_success",
        defaults["stop_on_first_success"],
    )

    protocol_options: Dict[str, Dict[str, Any]] = {}
    if "http_options" in kwargs and isinstance(kwargs["http_options"], dict):
        protocol_options["http"] = dict(kwargs["http_options"])
    if "smb_options" in kwargs and isinstance(kwargs["smb_options"], dict):
        protocol_options["smb"] = dict(kwargs["smb_options"])

    return AttackConfig(
        max_workers=int(workers),
        rate_limit=kwargs.get("rate"),
        jitter=float(kwargs.get("jitter", 0.0)),
        attempt_timeout=float(kwargs.get("timeout", 3.0)),
        connect_timeout=float(kwargs.get("connect_timeout", 5.0)),
        max_attempts_per_protocol=int(max_attempts),
        stop_on_first_success=bool(stop_on_success),
        verify_tls=bool(kwargs.get("verify_tls", True)),
        wordlist_dir=wordlist_dir,
        protocol_options=protocol_options,
    )


def _resolve_protocols(mode: str, kwargs: Dict[str, Any]) -> List[str]:
    requested = kwargs.get("protocols")
    if requested is None:
        return list(TOOL_INFO["mode_defaults"][mode]["protocols"])
    if isinstance(requested, str):
        return [p.strip().lower() for p in requested.split(",") if p.strip()]
    return [str(p).strip().lower() for p in requested if str(p).strip()]


def _resolve_ports(kwargs: Dict[str, Any]) -> Dict[str, int]:
    raw = kwargs.get("ports") or {}
    if not isinstance(raw, dict):
        return {}
    resolved: Dict[str, int] = {}
    for name, value in raw.items():
        try:
            resolved[str(name).lower()] = int(value)
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid port override %s=%r", name, value)
    return resolved


def _resolve_wordlists(kwargs: Dict[str, Any]) -> tuple[Any, Any]:
    """Return (username_source, password_source).

    Values may be an inline list of strings or a wordlist filename/glob
    resolved against ``AttackConfig.wordlist_dir``.
    """
    usernames = kwargs.get("usernames", kwargs.get("username_source", "usernames.txt"))
    passwords = kwargs.get("passwords", kwargs.get("password_source", "passwords.txt"))

    if isinstance(usernames, (list, tuple)):
        usernames = [str(u) for u in usernames]
    if isinstance(passwords, (list, tuple)):
        passwords = [str(p) for p in passwords]

    return usernames, passwords


def _wire_cancellation(engine: BruteForceEngine, cancel_event: Any) -> None:
    """If the caller supplied a threading.Event, mirror it onto the engine.

    The orchestrator currently checks its cancel flag only between tools,
    so this bridge lets callers who *do* pass ``cancel_event`` abort a
    long-running brute-force job mid-protocol.
    """
    if not isinstance(cancel_event, threading.Event):
        return

    def _watch() -> None:
        cancel_event.wait()
        logger.warning("brute_force: cancel_event set, stopping engine")
        engine.stop()

    threading.Thread(
        target=_watch,
        daemon=True,
        name="bf-cancel-bridge",
    ).start()


def _wire_success_logging(engine: BruteForceEngine) -> None:
    """Emit a single log line per credential so operators see hits live."""
    def _on_hit(protocol: str, target: str, port: int, credential: Credential) -> None:
        logger.warning(
            "[+] brute_force %s %s:%d valid credential -> %s",
            protocol, target, port, credential,
        )

    engine.on_success(_on_hit)


def _error_response(target: str, message: str, started: float) -> Dict[str, Any]:
    return {
        "tool": TOOL_INFO["name"],
        "target": target,
        "data": {
            "mode": None,
            "duration_s": round(time.time() - started, 3),
            "protocols": {},
            "total_attempts": 0,
            "total_successes": 0,
        },
        "error": message,
    }


__all__ = [
    # Orchestrator contract
    "run",
    "TOOL_INFO",
    # Public API for analytic_manager / direct imports
    "AttackConfig",
    "AttackReport",
    "AttemptResult",
    "BruteForceEngine",
    "Credential",
    "Outcome",
    "ProtocolReport",
    "RateLimiter",
    "WordlistError",
    "WordlistProvider",
    "__version__",
]
