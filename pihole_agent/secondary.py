"""The secondary Pi-hole, over SSH. Its authorized_keys entry only allows deploy/secondary/pihole-agent-cmd."""

from __future__ import annotations

import os
import re
import subprocess

VERSION = re.compile(r"^(\w+) version is (\S+) \(Latest: (\S+)\)", re.M)
NO_VERSION = {"null", "N/A", "-1", ""}


class SecondaryError(Exception):
    pass


def ensure_ssh(key_path: str, known_hosts_path: str, host: str, host_key: str) -> None:
    """The agent's key is made here, once, and never leaves its volume."""
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    if not os.path.exists(key_path):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "pihole-agent", "-f", key_path],
                       check=True, timeout=30)
    with open(known_hosts_path, "w", encoding="utf-8") as fh:
        fh.write(f"{host} {host_key}\n")


def parse_versions(text: str) -> dict[str, list[str]]:
    """{"Core": [installed, latest], ...} from `pihole -v`."""
    found = {name: [current, latest] for name, current, latest in VERSION.findall(text)}
    if not found:
        raise SecondaryError("couldn't read the versions from `pihole -v`")
    return found


def outdated(versions: dict[str, list[str]]) -> dict[str, list[str]]:
    return {name: v for name, v in versions.items() if v[1] not in NO_VERSION and v[0] != v[1]}


class Secondary:
    def __init__(self, host: str, key_path: str, known_hosts_path: str):
        self.host, self.key_path, self.known_hosts_path = host, key_path, known_hosts_path

    def _run(self, verb: str, timeout: float = 120) -> str:
        command = ["ssh", "-i", self.key_path, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts_path}",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", f"root@{self.host}", verb]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SecondaryError(f"`{verb}` timed out") from None
        if done.returncode:
            raise SecondaryError(f"`{verb}` failed: {done.stderr.strip()[-300:] or f'exit {done.returncode}'}")
        return done.stdout

    def versions(self) -> dict[str, list[str]]:
        return parse_versions(self._run("versions"))

    def start_update(self) -> None:
        self._run("update-start")

    def update_status(self) -> tuple[str, str]:
        """("running" | "0" | another exit code | "unknown", the end of the update's output)."""
        first, _, rest = self._run("update-status").partition("\n")
        return first.strip(), rest.strip()

    def dns_works(self) -> bool:
        try:
            return bool(self._run("dns-check").strip())
        except SecondaryError:
            return False
