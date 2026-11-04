"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        raise SystemExit(f"{name} must be a whole number, got {raw!r}") from None


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


@dataclass
class Config:
    primary_url: str  # where the adlists are checked and removed
    primary_password: str  # an app password for the primary's API
    secondary_host: str  # where Pi-hole updates are applied
    secondary_host_key: str  # its SSH host key, e.g. "ssh-ed25519 AAAA..."
    notify_urls: list[str] = field(default_factory=list)
    check_hour: int = 9  # when the daily run starts, in the container's time zone
    dead_after_days: int = 3  # days in a row a list must fail before it's removed
    abandoned_after_days: int = 180  # no sign of a change for this long counts as failing; 0 turns it off
    state_dir: str = "/var/lib/pihole-agent"

    @property
    def state_path(self) -> str:
        return os.path.join(self.state_dir, "state.json")

    @property
    def key_path(self) -> str:
        return os.path.join(self.state_dir, "id_ed25519")

    @property
    def known_hosts_path(self) -> str:
        return os.path.join(self.state_dir, "known_hosts")

    @property
    def run_now_path(self) -> str:
        return os.path.join(self.state_dir, "run-now")

    @classmethod
    def from_env(cls) -> "Config":
        hour = _int("CHECK_HOUR", 9)
        if not 0 <= hour <= 23:
            raise SystemExit(f"CHECK_HOUR must be from 0 to 23, got {hour}")
        urls = os.environ.get("NOTIFY_URLS", "").replace("\n", ",").split(",")
        return cls(
            primary_url=_required("PRIMARY_URL").rstrip("/"),
            primary_password=_required("PIHOLE_PASSWORD"),
            secondary_host=_required("SECONDARY_HOST"),
            secondary_host_key=_required("SECONDARY_HOST_KEY"),
            notify_urls=[u.strip() for u in urls if u.strip()],
            check_hour=hour,
            dead_after_days=max(1, _int("DEAD_AFTER_DAYS", 3)),
            abandoned_after_days=max(0, _int("ABANDONED_AFTER_DAYS", 180)),
            state_dir=os.environ.get("STATE_DIR", "").strip() or "/var/lib/pihole-agent",
        )
