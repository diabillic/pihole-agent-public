"""Is an adlist still alive? Downloads it the way gravity would and looks for real entries.

The container's DNS is the Pi-holes themselves, so a failed lookup can just mean Pi-hole blocks the
list's host. Network failures are therefore checked against public DNS (over HTTPS, so it can't be
answered locally) before they count against a list.
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)

ALIVE, DEAD, UNKNOWN = "alive", "dead", "unknown"  # unknown never counts for or against a list
TIMEOUT = (15, 60)  # connect, read
SAMPLE = 1_000_000  # bytes looked through for entries: plenty to get past any header
MAX_BYTES = 200_000_000  # bytes hashed from each list
HEADERS = {"User-Agent": "Pi-hole/6 (pihole-agent list check)"}
DOH = "https://1.1.1.1/dns-query"
GITHUB_COMMITS = "https://api.github.com/repos/{repo}/commits"
BLOCKED_ANSWERS = {"0.0.0.0", "::"}
EARLIEST_DATE = 946684800  # 2000: some servers send the epoch when they don't know

_HOST = r"(?:[a-z0-9_*-]+\.)+[a-z0-9_*-]+"
_ENTRY = re.compile(
    rf"^(?:(?:0\.0\.0\.0|127\.0\.0\.1|::1?)(?:\s+{_HOST})+"  # hosts file
    rf"|{_HOST}"  # one domain per line
    r"|@?@?\|\|[a-z0-9_*.-]+\^\S*)"  # adblock style; a whole TLD such as ||zip^ is valid
    r"\s*(?:#.*)?$",
    re.I,
)


@dataclass
class Result:
    verdict: str
    reason: str = ""
    fingerprint: str = ""  # a hash of the whole file, when it could be read
    published: float | None = None  # when its source says it last changed, if it says


def has_entries(text: str) -> bool:
    return any(_ENTRY.match(line.strip()) for line in text.splitlines())


def http_date(headers) -> float | None:
    try:
        stamp = parsedate_to_datetime(headers.get("Last-Modified", "")).timestamp()
    except (TypeError, ValueError):
        return None
    return stamp if stamp > EARLIEST_DATE else None


def github_source(url: str) -> tuple[str, str, str] | None:
    """(owner/repo, ref or "" for the default branch, path) for a file served from GitHub."""
    parts = urlsplit(url)
    bits = parts.path.strip("/").split("/")
    if parts.hostname == "raw.githubusercontent.com" and len(bits) >= 4:
        rest = bits[4:] if bits[2] == "refs" else bits[2:]
        if len(rest) >= 2:
            return f"{bits[0]}/{bits[1]}", rest[0], "/".join(rest[1:])
    if parts.hostname == "cdn.jsdelivr.net" and len(bits) >= 4 and bits[0] == "gh":
        repo, _, ref = bits[2].partition("@")
        return f"{bits[1]}/{repo}", "" if ref == "latest" else ref, "/".join(bits[3:])
    return None


def github_updated(url: str) -> float | None:
    """The last commit to touch the file. GitHub and its CDNs don't send Last-Modified."""
    source = github_source(url)
    if not source:
        return None
    repo, ref, path = source
    params = {"path": path, "per_page": 1, **({"sha": ref} if ref else {})}
    try:
        r = requests.get(GITHUB_COMMITS.format(repo=repo), params=params, timeout=15,
                         headers={**HEADERS, "Accept": "application/vnd.github+json"})
        r.raise_for_status()
        date = r.json()[0]["commit"]["committer"]["date"]
        return datetime.fromisoformat(date.replace("Z", "+00:00")).timestamp()
    except (requests.RequestException, ValueError, LookupError, TypeError):
        return None  # rate limited, or a ref this can't work out: the file's hash still tells


def public_dns(host: str) -> str | None:
    """"exists", "nxdomain" or "noaddress"; None when public DNS can't give an answer."""
    try:
        r = requests.get(DOH, params={"name": host, "type": "A"}, headers={"Accept": "application/dns-json"}, timeout=15)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError):
        return None
    if data.get("Status") == 3:
        return "nxdomain"
    if data.get("Status") != 0:
        return None
    return "exists" if data.get("Answer") else "noaddress"


def locally_blocked(host: str) -> bool:
    try:
        answers = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return True  # public DNS knows it and we don't
    return all(info[4][0] in BLOCKED_ANSWERS for info in answers)


def _unreachable(host: str, reason: str) -> Result:
    public = public_dns(host)
    if public is None:
        return Result(UNKNOWN, f"{reason}; public DNS couldn't be asked, so this may be our own connection")
    if public == "nxdomain":
        return Result(DEAD, "its domain no longer exists")
    if public == "noaddress":
        return Result(DEAD, "its domain has no address")
    if locally_blocked(host):
        return Result(UNKNOWN, f"{reason}; Pi-hole seems to block {host}")
    return Result(DEAD, reason)


def _fetch(url: str) -> Result:
    host = urlsplit(url).hostname or ""
    try:
        with requests.get(url, stream=True, timeout=TIMEOUT, headers=HEADERS) as r:
            if r.status_code == 429:
                return Result(UNKNOWN, "rate limited (HTTP 429)")
            if r.status_code >= 400:
                return Result(DEAD, f"HTTP {r.status_code}")
            digest, sample, size = hashlib.sha256(), b"", 0
            for chunk in r.iter_content(65536):
                digest.update(chunk)
                size += len(chunk)
                if len(sample) < SAMPLE:
                    sample += chunk
                if size >= MAX_BYTES:
                    break
            modified, final_url = http_date(r.headers), r.url
    except requests.exceptions.SSLError:
        return _unreachable(host, "TLS failed")
    except requests.exceptions.Timeout:
        return _unreachable(host, "timed out")
    except requests.exceptions.ConnectionError:
        return _unreachable(host, "couldn't connect")
    except requests.RequestException as exc:
        return Result(DEAD, type(exc).__name__)
    if not has_entries(sample.decode("utf-8", "replace")):
        return Result(DEAD, "the response has no domains in it")
    dates = [d for d in (modified, github_updated(final_url)) if d]
    return Result(ALIVE, fingerprint=digest.hexdigest(), published=max(dates, default=None))


def check(url: str, attempts: int = 3, wait: float = 30) -> Result:
    """One day's verdict on a list. Only the last of several tries counts unless one succeeds."""
    if urlsplit(url).scheme not in ("http", "https"):
        return Result(UNKNOWN, "not a web address, so it can't be checked from here")
    result = Result(UNKNOWN)
    for attempt in range(attempts):
        if attempt:
            time.sleep(wait)
        result = _fetch(url)
        if result.verdict == ALIVE:
            break
    return result
