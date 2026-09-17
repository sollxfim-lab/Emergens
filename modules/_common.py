"""
Shared helpers for recon modules.

Note: this project intentionally does NOT include a proxy scraper/rotator.
Harvesting public proxy lists to rotate source IPs is an evasion technique
commonly used to dodge rate-limits/IP-bans while hammering third-party
sites at scale - that's a different (and much riskier) thing than "not
looking like a robotic script". For the latter, a rotating User-Agent list
is all that's actually needed, so that's all this provides.
"""
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


def get_random_ua() -> str:
    return random.choice(USER_AGENTS)


def default_headers() -> dict:
    return {"User-Agent": get_random_ua()}
