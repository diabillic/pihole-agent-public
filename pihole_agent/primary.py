"""The primary Pi-hole's REST API: read the adlists, remove one, rebuild gravity."""

from __future__ import annotations

from urllib.parse import quote

import requests

TIMEOUT = 30
GRAVITY_TIMEOUT = 900  # gravity reports as it goes, so this is the longest silence


class PrimaryError(Exception):
    pass


class Primary:
    """A logged-in session, closed on exit since Pi-hole only allows a few at a time."""

    def __init__(self, url: str, password: str):
        self.url, self.password = url, password
        self.http = requests.Session()

    def __enter__(self) -> "Primary":
        r = self._call("POST", "/api/auth", json={"password": self.password})
        session = r.json().get("session", {})
        if not session.get("valid"):
            raise PrimaryError("login refused")
        if session.get("sid"):
            self.http.headers["X-FTL-SID"] = session["sid"]
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.http.delete(f"{self.url}/api/auth", timeout=TIMEOUT)
        except requests.RequestException:
            pass  # it expires by itself

    def _call(self, method: str, path: str, ok=(200,), **kw) -> requests.Response:
        try:
            r = self.http.request(method, f"{self.url}{path}", timeout=kw.pop("timeout", TIMEOUT), **kw)
        except requests.RequestException as exc:
            raise PrimaryError(f"{method} {path}: {type(exc).__name__}") from None
        if r.status_code not in ok:
            raise PrimaryError(f"{method} {path}: HTTP {r.status_code}")
        return r

    def lists(self) -> list[dict]:
        return self._call("GET", "/api/lists").json().get("lists", [])

    def remove(self, item: dict) -> bool:
        """False if it was already gone."""
        path = f"/api/lists/{quote(item['address'], safe='')}"
        return self._call("DELETE", path, ok=(204, 404), params={"type": item["type"]}).status_code == 204

    def gravity(self) -> None:
        """Rebuilds the blocklist, so a removed list's domains stop being blocked. Waits until it's done."""
        r = self._call("POST", "/api/action/gravity", stream=True, timeout=GRAVITY_TIMEOUT)
        try:
            for _ in r.iter_content(4096):
                pass
        except requests.RequestException as exc:
            raise PrimaryError(f"gravity: {type(exc).__name__}") from None
