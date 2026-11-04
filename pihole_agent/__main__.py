"""Entry point: python -m pihole_agent [check]

Once a day: removes dead adlists from the primary Pi-hole, and runs `pihole -up` on the secondary if
it's behind. `check` shows what a run would find without changing anything.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from datetime import datetime

from . import health, lists
from .config import Config
from .notice import ICONS, Message, Outbox, Section
from .primary import Primary, PrimaryError
from .secondary import Secondary, SecondaryError, ensure_ssh, outdated
from .state import State

log = logging.getLogger("pihole_agent")

TICK = 60
LOOP_WITHIN = 3600  # a run with slow lists and a gravity rebuild can take a while
UPDATE_LIMIT = 1800  # an update still going after this long is reported
DNS_TRIES, DNS_WAIT = 4, 15  # Pi-hole's DNS can take a moment to come back after an update
AUTHOR = "Pi-hole agent"
AVATAR = ICONS.format("pi-hole")
KEEP = "[keep]"  # in a list's comment in Pi-hole: never treat it as abandoned


def list_key(item: dict) -> str:
    return f"{item['type']} {item['address']}"


def day_of(stamp: float) -> str:
    return datetime.fromtimestamp(stamp).date().isoformat()


def _text(value: str) -> str:
    return re.sub(r"[`*_~|\[\]]", "", " ".join(str(value).split()))[:80]


def describe(item: dict) -> str:
    comment = f" ({_text(item['comment'])})" if item.get("comment") else ""
    return f"`{item['address']}`{comment}"


def code_block(text: str) -> str:
    return "```\n" + text.replace("```", "'''")[-1500:] + "\n```"


class Agent:
    def __init__(self, cfg: Config, state: State, outbox: Outbox, secondary: Secondary, primary=None, check=lists.check):
        self.cfg, self.state, self.outbox, self.secondary = cfg, state, outbox, secondary
        self.primary = primary or (lambda: Primary(cfg.primary_url, cfg.primary_password))
        self.check = check

    @property
    def run_state(self) -> dict:
        return self.state["run"]

    # --- Telling people. Messages are saved first, so a Discord outage can't lose one. ---

    def say(self, title: str, level: str, sections: list[Section]) -> None:
        self.state["pending"].setdefault("messages", []).append(
            {"title": title, "level": level,
             "sections": [{"heading": s.heading, "lines": s.lines, "note": s.note, "bullets": s.bullets} for s in sections]})
        self.state.save()

    def flush(self) -> None:
        queue = self.state["pending"].get("messages", [])
        while queue:
            m = queue[0]
            if not self.outbox.send(Message(m["title"], m["level"], [Section(**s) for s in m["sections"]], AUTHOR)):
                return
            queue.pop(0)
            self.state.save()

    def problem(self, key: str, title: str, lines: list[str]) -> None:
        """Said once, while the problem stays the same, however many days it lasts."""
        known = self.state["problems"]
        if known.get(key) != title:
            known[key] = title
            self.say(f"❌ {title}", "error", [Section("", lines, bullets=False)])

    def clear(self, key: str, announce: bool = True) -> None:
        title = self.state["problems"].pop(key, None)
        if title and announce:
            self.say(f"✅ Resolved: {title}", "ok", [])

    # --- Adlists on the primary ---

    def last_sign_of_life(self, key: str, result: lists.Result, now: float) -> float:
        """The latest evidence of a change: a change seen here, or a date from the list's source. With
        neither yet, it's when the list was first seen. The later one wins, since abandoned has to mean
        there's no sign of life at all, and a small list can go a long time with few changes."""
        known = self.state["content"].setdefault(key, {"hash": result.fingerprint, "first_seen": now})
        if known["hash"] != result.fingerprint:
            known["hash"], known["changed"] = result.fingerprint, now
        if result.published:  # kept, so a day GitHub won't answer doesn't lose it
            known["published"] = result.published
        signs = [known[s] for s in ("changed", "published") if s in known]
        return max(signs, default=known["first_seen"])

    def judge(self, item: dict, now: float) -> lists.Result:
        result = self.check(item["address"])
        if result.verdict != lists.ALIVE:
            return result
        since = self.last_sign_of_life(list_key(item), result, now)
        limit = self.cfg.abandoned_after_days
        if limit and now - since > limit * 86400 and KEEP not in (item.get("comment") or ""):
            return lists.Result(lists.DEAD, f"abandoned, no changes since {day_of(since)}")
        return result

    def strike(self, results: list[tuple[dict, lists.Result]], today: str) -> list[tuple[dict, dict]]:
        """Records today's results; returns the lists that have now failed for long enough."""
        strikes, current, due = self.state["strikes"], set(), []
        for item, result in results:
            key = list_key(item)
            current.add(key)
            if result.verdict == lists.ALIVE:
                strikes.pop(key, None)
            elif result.verdict == lists.DEAD:
                entry = strikes.setdefault(key, {"count": 0, "since": today, "day": ""})
                if entry["day"] != today:  # a second run on the same day isn't a second day of failing
                    entry["count"] += 1
                entry["day"], entry["reason"] = today, result.reason
                log.warning("%s failed (%d/%d): %s", item["address"], entry["count"], self.cfg.dead_after_days, result.reason)
                if entry["count"] >= self.cfg.dead_after_days:
                    due.append((item, entry))
            else:
                log.info("%s not judged: %s", item["address"], result.reason)
        for section in (strikes, self.state["content"]):
            for key in set(section) - current:  # gone from Pi-hole
                del section[key]
        self.state.save()
        return due

    def check_lists(self, today: str, now: float) -> None:
        with self.primary() as api:
            items = api.lists()
        self.clear("primary")
        due = self.strike([(item, self.judge(item, now)) for item in items], today)
        if len(due) > len(items) / 2:
            # Most of these lists can share one host, so this looks more like an outage than dead lists.
            self.problem("too-many", f"{len(due)} of {len(items)} adlists look dead or abandoned, so none were removed",
                         [describe(item) + f": {entry['reason']}" for item, entry in due]
                         + ["That many at once is more likely an outage. Remove them by hand if they really are dead."])
            return
        self.clear("too-many")
        if due:
            self.remove_dead(due)

    def remove_dead(self, due: list[tuple[dict, dict]]) -> None:
        removed, failed = [], []
        with self.primary() as api:
            for item, entry in due:
                try:
                    if api.remove(item):
                        removed.append(f"{describe(item)}: {entry['reason']}, flagged since {entry['since']}")
                    del self.state["strikes"][list_key(item)]
                except PrimaryError as exc:  # stays struck, so it's tried again tomorrow
                    failed.append(f"{describe(item)}: {exc}")
            if failed:
                self.problem("remove", "Couldn't remove dead adlists from the primary Pi-hole", failed)
            else:
                self.clear("remove")
            if not removed:
                return
            count = f"{len(removed)} dead or abandoned adlist{'s' if len(removed) > 1 else ''}"
            self.say(f"🗑️ Removed {count} from the primary Pi-hole", "warning",
                     [Section("Removed", removed,
                              note=f"To restore one, add its address back under Adlists in Pi-hole, with {KEEP} in the "
                                   "comment if it was abandoned. nebula-sync copies this to the secondary within the hour.")])
            try:
                api.gravity()
                self.clear("gravity")
            except PrimaryError as exc:
                self.problem("gravity", "Removed dead adlists, but gravity didn't finish on the primary",
                             [f"{exc}. The removed lists' domains stay blocked until gravity next runs."])

    # --- Updates on the secondary ---

    def check_update(self, now: float) -> None:
        if self.run_state.get("update"):
            return
        behind = outdated(self.secondary.versions())
        self.clear("secondary")
        if not behind:
            self.clear("update")
            return
        log.info("Updating the secondary: %s", behind)
        self.secondary.start_update()
        self.run_state["update"] = {"behind": behind, "started": now}
        self.state.save()

    def follow_update(self, now: float) -> None:
        update = self.run_state["update"]
        try:
            status, output = self.secondary.update_status()
        except SecondaryError as exc:
            log.warning("Couldn't read the update's status: %s", exc)
            status, output = "running", ""
        if status == "running":
            if now - update["started"] > UPDATE_LIMIT:
                del self.run_state["update"]
                self.problem("update", "The secondary Pi-hole's update hasn't finished after 30 minutes",
                             ["Check the unit pihole-agent-update on the secondary."])
                self.state.save()
            return
        del self.run_state["update"]
        changes = [f"{name}: {v[0]} → {v[1]}" for name, v in update["behind"].items()]
        if status != "0":
            self.problem("update", "`pihole -up` failed on the secondary Pi-hole",
                         [f"Exit code {status}, while updating:", *changes, code_block(output)])
            self.state.save()
            return
        self.finish_update(changes, output)

    def finish_update(self, changes: list[str], output: str) -> None:
        trouble = []
        try:
            still = outdated(self.secondary.versions())
            if still:
                trouble.append("Still behind: " + ", ".join(f"{name} {v[0]}, latest {v[1]}" for name, v in still.items()))
        except SecondaryError as exc:
            trouble.append(f"Couldn't read its versions afterwards: {exc}")
        for attempt in range(DNS_TRIES):
            if self.secondary.dns_works():
                break
            if attempt + 1 == DNS_TRIES:
                trouble.append("It isn't answering DNS queries.")
            else:
                time.sleep(DNS_WAIT)
        if trouble:
            self.problem("update", "The secondary Pi-hole isn't right after `pihole -up`", [*trouble, code_block(output)])
        else:
            self.clear("update", announce=False)  # this message says it
            self.say("⬆️ Secondary Pi-hole updated", "ok", [Section("", changes)])
        self.state.save()

    # --- The day ---

    def daily(self, today: str, now: float) -> None:
        try:
            self.check_lists(today, now)
        except PrimaryError as exc:
            self.problem("primary", "Can't use the primary Pi-hole's API, so adlists weren't checked", [str(exc)])
        except Exception as exc:  # the update below shouldn't depend on this
            log.exception("Adlist check failed")
            self.problem("primary", "The adlist check failed", [type(exc).__name__])
        try:
            self.check_update(now)
        except SecondaryError as exc:
            self.problem("secondary", "Can't check the secondary Pi-hole for updates", [str(exc)])
        except Exception as exc:
            log.exception("Update check failed")
            self.problem("secondary", "The update check failed", [type(exc).__name__])

    def asked_to_run(self) -> bool:
        """`touch run-now` in the state folder starts a run at the next tick, whatever the hour."""
        try:
            os.unlink(self.cfg.run_now_path)
            return True
        except OSError:
            return False

    def start(self, now: float) -> None:
        """A new deployment waits for the next run rather than updating DNS at a random hour."""
        local = datetime.fromtimestamp(now)
        if "ran" not in self.run_state and local.hour >= self.cfg.check_hour:
            self.run_state["ran"] = local.date().isoformat()
            self.state.save()

    def tick(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self.flush()
        if self.run_state.get("update"):
            self.follow_update(now)
        local = datetime.fromtimestamp(now)
        today = local.date().isoformat()
        due = local.hour >= self.cfg.check_hour and self.run_state.get("ran") != today
        if self.asked_to_run() or due:
            self.run_state["ran"] = today
            self.state.save()
            self.daily(today, now)
            self.state.save()
        self.flush()

    def run(self) -> None:
        self.start(time.time())
        while True:
            health.beat("daily", LOOP_WITHIN)
            try:
                self.tick()
            except Exception:  # keep the daemon alive; next tick may succeed
                log.exception("Tick failed")
            time.sleep(TICK)


def show(cfg: Config, secondary: Secondary) -> None:
    """Changes nothing here: prints each list's verdict and the secondary's versions."""
    with Primary(cfg.primary_url, cfg.primary_password) as api:
        items = api.lists()
    for item in items:
        result = lists.check(item["address"], attempts=1)
        published = f"last published {day_of(result.published)}" if result.published else ""
        print(f"{result.verdict:8} {item['type']:6} {item['address']} {result.reason}{published}")
    versions = secondary.versions()
    for name, (current, latest) in versions.items():
        print(f"{name}: {current}, latest {latest}")
    print("Would update the secondary" if outdated(versions) else "The secondary is up to date")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    cfg = Config.from_env()
    ensure_ssh(cfg.key_path, cfg.known_hosts_path, cfg.secondary_host, cfg.secondary_host_key)
    secondary = Secondary(cfg.secondary_host, cfg.key_path, cfg.known_hosts_path)
    if sys.argv[1:] == ["check"]:
        show(cfg, secondary)
        return
    health.reset()
    outbox = Outbox(cfg.notify_urls, avatar=AVATAR)
    log.info("Starting: daily run at %02d:00, lists removed after %d days of failing, abandoned after %d days",
             cfg.check_hour, cfg.dead_after_days, cfg.abandoned_after_days)
    Agent(cfg, State(cfg.state_path), outbox, secondary).run()


if __name__ == "__main__":
    main()
