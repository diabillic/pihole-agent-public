from datetime import datetime

import pytest
import requests

from pihole_agent import lists
from pihole_agent.__main__ import Agent
from pihole_agent.config import Config
from pihole_agent.primary import Primary, PrimaryError
from pihole_agent.secondary import SecondaryError, outdated, parse_versions
from pihole_agent.state import State

ALIVE = lists.Result(lists.ALIVE)
DEAD = lists.Result(lists.DEAD, "HTTP 404")
UNKNOWN = lists.Result(lists.UNKNOWN, "public DNS couldn't be asked")
BEHIND = {"Core": ["v6.4.3", "v6.5"], "FTL": ["v6.7.1", "v6.8"]}
CURRENT = {"Core": ["v6.5", "v6.5"], "FTL": ["v6.8", "v6.8"]}


def ts(text):
    return datetime.fromisoformat(text).timestamp()


def adlist(name, kind="block"):
    return {"address": f"https://lists.example/{name}.txt", "type": kind, "comment": name}


# --- Fakes ---

class FakeApi:
    def __init__(self, items):
        self.items, self.removed, self.gravity_runs, self.fail_remove, self.fail_gravity = items, [], 0, False, False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def lists(self):
        return list(self.items)

    def remove(self, item):
        if self.fail_remove:
            raise PrimaryError("HTTP 500")
        self.items.remove(item)
        self.removed.append(item["address"])
        return True

    def gravity(self):
        self.gravity_runs += 1
        if self.fail_gravity:
            raise PrimaryError("gravity: Timeout")


class FakeSecondary:
    def __init__(self, versions=CURRENT):
        self.current, self.started, self.status, self.output, self.dns, self.error = versions, 0, "running", "", True, None

    def versions(self):
        if self.error:
            raise SecondaryError(self.error)
        return self.current

    def start_update(self):
        self.started += 1

    def update_status(self):
        return self.status, self.output

    def dns_works(self):
        return self.dns


class FakeOutbox:
    def __init__(self):
        self.sent, self.working = [], True

    def send(self, message):
        if self.working:
            self.sent.append(message)
        return self.working


class Rig:
    def __init__(self, tmp_path, items=(), verdicts=None, versions=CURRENT, **cfg):
        self.api, self.secondary, self.outbox = FakeApi(list(items)), FakeSecondary(versions), FakeOutbox()
        self.verdicts = verdicts or {}
        self.cfg = Config("http://primary", "pw", "secondary", "key", state_dir=str(tmp_path), **cfg)
        self.state = State(self.cfg.state_path)
        self.agent = Agent(self.cfg, self.state, self.outbox, self.secondary, primary=lambda: self.api,
                           check=lambda url: self.verdicts.get(url, ALIVE))

    def titles(self):
        return [m.title for m in self.outbox.sent]

    def day(self, n):
        self.agent.tick(ts(f"2026-11-{n:02d}T10:00:00"))


# --- What counts as a list ---

@pytest.mark.parametrize("text", [
    "# comment\n0.0.0.0 ads.example.com\n",
    "127.0.0.1 localhost\n127.0.0.1 ads.example.com # note\n",
    "! Title\n||ads.example.com^\n",
    "||zip^\n||mov^\n",  # a list of whole TLDs
    "ads.example.com\n",
    "0.0.0.0 a.example.com b.example.com\n",
    "@@||good.example.com^\n",
])
def test_recognises_lists(text):
    assert lists.has_entries(text)


@pytest.mark.parametrize("text", [
    "", "# only comments\n! and more\n", "<!DOCTYPE html>\n<html><body>This domain is for sale</body></html>\n",
    "404: Not Found", "Service unavailable.\n", "127.0.0.1 localhost\n",
])
def test_rejects_other_content(text):
    assert not lists.has_entries(text)


# --- Checking a list ---

class Response:
    def __init__(self, status=200, body=b"||ads.example.com^\n", headers=None, url="https://lists.example/a.txt"):
        self.status_code, self.body, self.headers, self.url = status, body, headers or {}, url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def iter_content(self, _size):
        yield self.body


@pytest.fixture
def web(monkeypatch):
    """Answers the list's address with `web.list`, and public DNS with `web.dns`."""
    class Web:
        list, dns = Response(), "exists"
        tries = 0
    def get(url, **_):
        Web.tries += 1
        if Web.list.__class__ is type and issubclass(Web.list, Exception):
            raise Web.list()
        return Web.list
    monkeypatch.setattr(lists.requests, "get", get)
    monkeypatch.setattr(lists, "public_dns", lambda host: Web.dns)
    monkeypatch.setattr(lists, "locally_blocked", lambda host: False)
    monkeypatch.setattr(lists, "github_updated", lambda url: None)
    monkeypatch.setattr(lists.time, "sleep", lambda _: None)
    return Web


def test_a_good_list_is_alive_first_time(web):
    assert lists.check("https://lists.example/a.txt").verdict == lists.ALIVE
    assert web.tries == 1


@pytest.mark.parametrize("status", [401, 403, 404, 410, 500, 503])
def test_http_errors_count_after_retries(web, status):
    web.list = Response(status)
    result = lists.check("https://lists.example/a.txt")
    assert result.verdict == lists.DEAD and str(status) in result.reason and web.tries == 3


def test_rate_limiting_says_nothing_about_the_list(web):
    web.list = Response(429)
    assert lists.check("https://lists.example/a.txt").verdict == lists.UNKNOWN


def test_a_parked_page_is_dead(web):
    web.list = Response(200, b"<html>This domain is for sale</html>")
    assert lists.check("https://lists.example/a.txt").verdict == lists.DEAD


def test_a_vanished_domain_is_dead(web):
    web.list, web.dns = requests.exceptions.ConnectionError, "nxdomain"
    result = lists.check("https://lists.example/a.txt")
    assert result.verdict == lists.DEAD and "no longer exists" in result.reason


def test_our_own_outage_says_nothing_about_the_list(web):
    web.list, web.dns = requests.exceptions.ConnectionError, None
    assert lists.check("https://lists.example/a.txt").verdict == lists.UNKNOWN


def test_a_host_blocked_by_pihole_isnt_dead(web, monkeypatch):
    web.list = requests.exceptions.ConnectionError
    monkeypatch.setattr(lists, "locally_blocked", lambda host: True)
    result = lists.check("https://lists.example/a.txt")
    assert result.verdict == lists.UNKNOWN and "block" in result.reason


def test_a_server_that_refuses_connections_is_dead(web):
    web.list = requests.exceptions.ConnectionError
    assert lists.check("https://lists.example/a.txt").verdict == lists.DEAD


def test_a_local_file_cant_be_judged(web):
    assert lists.check("file:///etc/pihole/local.list").verdict == lists.UNKNOWN


def test_public_dns_answers(monkeypatch):
    class Answer:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self.data
    def get(data):
        return lambda *a, **k: Answer(data)
    monkeypatch.setattr(lists.requests, "get", get({"Status": 3}))
    assert lists.public_dns("x.example") == "nxdomain"
    monkeypatch.setattr(lists.requests, "get", get({"Status": 0, "Answer": [{"data": "1.2.3.4"}]}))
    assert lists.public_dns("x.example") == "exists"
    monkeypatch.setattr(lists.requests, "get", get({"Status": 0}))
    assert lists.public_dns("x.example") == "noaddress"
    monkeypatch.setattr(lists.requests, "get", get({"Status": 2}))  # SERVFAIL isn't an answer
    assert lists.public_dns("x.example") is None


# --- Removing dead lists ---

def test_removes_only_after_days_in_a_row(tmp_path):
    bad, good = adlist("bad"), adlist("good")
    rig = Rig(tmp_path, [bad, good, adlist("other")], {bad["address"]: DEAD})
    rig.day(1), rig.day(2)
    assert rig.api.removed == [] and rig.titles() == []
    rig.day(3)
    assert rig.api.removed == [bad["address"]] and rig.api.gravity_runs == 1
    assert rig.titles() == ["🗑️ Removed 1 dead or abandoned adlist from the primary Pi-hole"]
    removed = rig.outbox.sent[0].sections[0].lines[0]
    assert bad["address"] in removed and "HTTP 404" in removed and "2026-11-01" in removed
    assert rig.state["strikes"] == {}


def test_recovering_starts_the_count_again(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD})
    rig.day(1), rig.day(2)
    rig.verdicts.clear()
    rig.day(3)
    rig.verdicts[bad["address"]] = DEAD
    rig.day(4), rig.day(5)
    assert rig.api.removed == []
    rig.day(6)
    assert rig.api.removed == [bad["address"]]


def test_a_day_we_cant_judge_neither_counts_nor_resets(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD})
    rig.day(1), rig.day(2)
    rig.verdicts[bad["address"]] = UNKNOWN
    rig.day(3)
    assert rig.api.removed == [] and rig.state["strikes"][f"block {bad['address']}"]["count"] == 2
    rig.verdicts[bad["address"]] = DEAD
    rig.day(4)
    assert rig.api.removed == [bad["address"]]


def test_a_second_run_in_a_day_isnt_another_day(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD})
    rig.day(1)
    open(rig.cfg.run_now_path, "w").close()
    rig.agent.tick(ts("2026-11-01T11:00:00"))
    assert rig.state["strikes"][f"block {bad['address']}"]["count"] == 1


def test_most_lists_failing_at_once_is_an_outage(tmp_path):
    items = [adlist("a"), adlist("b"), adlist("c")]
    rig = Rig(tmp_path, items, {i["address"]: DEAD for i in items[:2]})
    rig.day(1), rig.day(2), rig.day(3), rig.day(4)
    assert rig.api.removed == []
    assert rig.titles() == ["❌ 2 of 3 adlists look dead or abandoned, so none were removed"]  # said once
    rig.verdicts.clear()
    rig.day(5)
    assert rig.titles()[-1].startswith("✅ Resolved") and rig.state["strikes"] == {}


def test_every_list_failing_never_empties_pihole(tmp_path):
    only = adlist("only")
    rig = Rig(tmp_path, [only], {only["address"]: DEAD}, dead_after_days=1)
    rig.day(1)
    assert rig.api.removed == []


def test_allow_lists_are_checked_too(tmp_path):
    allow = adlist("allow", kind="allow")
    rig = Rig(tmp_path, [allow, adlist("a"), adlist("b")], {allow["address"]: DEAD}, dead_after_days=1)
    rig.day(1)
    assert rig.api.removed == [allow["address"]]


def test_a_failed_removal_is_tried_again(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD}, dead_after_days=1)
    rig.api.fail_remove = True
    rig.day(1)
    assert rig.api.gravity_runs == 0 and rig.titles() == ["❌ Couldn't remove dead adlists from the primary Pi-hole"]
    rig.api.fail_remove = False
    rig.day(2)
    assert rig.api.removed == [bad["address"]]
    assert "✅ Resolved: Couldn't remove dead adlists from the primary Pi-hole" in rig.titles()


def test_a_failed_gravity_still_reports_the_removal(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD}, dead_after_days=1)
    rig.api.fail_gravity = True
    rig.day(1)
    assert rig.titles() == ["🗑️ Removed 1 dead or abandoned adlist from the primary Pi-hole",
                            "❌ Removed dead adlists, but gravity didn't finish on the primary"]


def test_an_unreachable_primary_is_said_once_and_cleared(tmp_path):
    rig = Rig(tmp_path, [adlist("a")])
    def refuse():
        raise PrimaryError("POST /api/auth: ConnectionError")
    good, rig.agent.primary = rig.agent.primary, refuse
    rig.day(1), rig.day(2)
    assert rig.titles() == ["❌ Can't use the primary Pi-hole's API, so adlists weren't checked"]
    rig.agent.primary = good
    rig.day(3)
    assert rig.titles()[-1].startswith("✅ Resolved")


def test_the_update_still_runs_when_the_primary_is_down(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    def refuse():
        raise PrimaryError("nope")
    rig.agent.primary = refuse
    rig.day(1)
    assert rig.secondary.started == 1


def test_a_list_removed_by_hand_is_forgotten(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD})
    rig.day(1)
    rig.api.items.remove(bad)
    rig.day(2)
    assert rig.state["strikes"] == {}


# --- What a list's source says about its age ---

def test_a_good_list_reports_its_hash_and_date(web):
    web.list = Response(headers={"Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"})
    result = lists.check("https://lists.example/a.txt")
    assert result.published == ts("2024-01-01T00:00:00+00:00") and len(result.fingerprint) == 64


def test_the_hash_covers_the_whole_file_not_just_the_sample(web, monkeypatch):
    monkeypatch.setattr(lists, "SAMPLE", 4)
    web.list = Response(body=b"||ads.example.com^\n" + b"x" * 10)
    first = lists.check("https://lists.example/a.txt")
    web.list = Response(body=b"||ads.example.com^\n" + b"y" * 10)
    assert first.fingerprint != lists.check("https://lists.example/a.txt").fingerprint


@pytest.mark.parametrize("headers", [{}, {"Last-Modified": "not a date"}, {"Last-Modified": "Thu, 01 Jan 1970 00:00:00 GMT"}])
def test_useless_dates_are_ignored(headers):
    assert lists.http_date(headers) is None


@pytest.mark.parametrize("url, expected", [
    ("https://raw.githubusercontent.com/o/r/master/hosts", ("o/r", "master", "hosts")),
    ("https://raw.githubusercontent.com/o/r/refs/heads/main/a/b.txt", ("o/r", "main", "a/b.txt")),
    ("https://cdn.jsdelivr.net/gh/o/r@latest/a/b.txt", ("o/r", "", "a/b.txt")),
    ("https://cdn.jsdelivr.net/gh/o/r/a/b.txt", ("o/r", "", "a/b.txt")),
    ("https://cdn.jsdelivr.net/gh/o/r@v2/b.txt", ("o/r", "v2", "b.txt")),
    ("https://lists.example/o/r/master/hosts", None),
    ("https://cdn.jsdelivr.net/npm/o/r/b.txt", None),
])
def test_finds_files_served_from_github(url, expected):
    assert lists.github_source(url) == expected


def test_asks_github_when_the_file_last_changed(monkeypatch):
    seen = {}
    class Answer:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"commit": {"committer": {"date": "2024-01-01T00:00:00Z"}}}]
    def get(url, params, **_):
        seen.update(url=url, **params)
        return Answer()
    monkeypatch.setattr(lists.requests, "get", get)
    assert lists.github_updated("https://raw.githubusercontent.com/o/r/master/a/b.txt") == ts("2024-01-01T00:00:00+00:00")
    assert seen == {"url": "https://api.github.com/repos/o/r/commits", "path": "a/b.txt", "per_page": 1, "sha": "master"}


@pytest.mark.parametrize("failure", [requests.exceptions.ConnectionError(), ValueError(), IndexError()])
def test_github_not_answering_is_no_answer(monkeypatch, failure):
    def get(*_, **__):
        raise failure
    monkeypatch.setattr(lists.requests, "get", get)
    assert lists.github_updated("https://raw.githubusercontent.com/o/r/master/hosts") is None


# --- Abandoned lists ---

OLD = ts("2025-01-01T00:00:00")  # over 300 days before these tests' November 2026
FRESH = ts("2099-01-01T00:00:00")  # keeps the other lists out of a test's way


def live(fingerprint="v1", published=None):
    return lists.Result(lists.ALIVE, fingerprint=fingerprint, published=published)


def abandon_rig(tmp_path, result, comment="stale", **cfg):
    stale, others = adlist("stale"), [adlist("a"), adlist("b")]
    stale["comment"] = comment
    verdicts = {stale["address"]: result, **{o["address"]: live(published=FRESH) for o in others}}
    return Rig(tmp_path, [stale, *others], verdicts, **cfg), stale


def test_an_old_list_goes_through_the_same_days_in_a_row(tmp_path):
    rig, stale = abandon_rig(tmp_path, live(published=OLD))
    rig.day(1), rig.day(2)
    assert rig.api.removed == [] and rig.titles() == []
    rig.day(3)
    assert rig.api.removed == [stale["address"]] and rig.api.gravity_runs == 1
    assert rig.titles() == ["🗑️ Removed 1 dead or abandoned adlist from the primary Pi-hole"]
    line = rig.outbox.sent[0].sections[0].lines[0]
    assert stale["address"] in line and "abandoned, no changes since 2025-01-01" in line


def test_a_recently_published_list_isnt_abandoned(tmp_path):
    rig, _ = abandon_rig(tmp_path, live(published=ts("2026-10-01T00:00:00")), dead_after_days=1)
    rig.day(1), rig.day(2)
    assert rig.api.removed == [] and rig.state["strikes"] == {}


def test_a_change_seen_here_outweighs_an_old_date(tmp_path):
    rig, stale = abandon_rig(tmp_path, live("v1", published=OLD), dead_after_days=3)
    rig.day(1), rig.day(2)
    assert rig.state["strikes"][f"block {stale['address']}"]["count"] == 2
    rig.verdicts[stale["address"]] = live("v2", published=OLD)
    rig.day(3)
    assert rig.api.removed == [] and rig.state["strikes"] == {}


def test_an_old_change_seen_here_outweighs_nothing_newer(tmp_path):
    rig, stale = abandon_rig(tmp_path, live("v1"), abandoned_after_days=2, dead_after_days=1)
    rig.day(1), rig.day(2)
    rig.verdicts[stale["address"]] = live("v2")
    rig.day(3), rig.day(5)  # the change on the 3rd is two days old: not over the limit
    assert rig.api.removed == []
    rig.day(6)
    assert rig.api.removed == [stale["address"]]


def test_with_no_date_at_all_it_goes_by_how_long_its_been_unchanged(tmp_path):
    rig, stale = abandon_rig(tmp_path, live("v1"), abandoned_after_days=2, dead_after_days=1)
    rig.day(1), rig.day(2), rig.day(3)
    assert rig.api.removed == []  # exactly two days isn't over two days
    rig.day(4)
    assert rig.api.removed == [stale["address"]]


def test_a_date_lost_later_is_remembered(tmp_path):
    rig, stale = abandon_rig(tmp_path, live(published=ts("2026-10-30T00:00:00")), abandoned_after_days=30, dead_after_days=1)
    rig.day(1)
    rig.verdicts[stale["address"]] = live()  # GitHub stopped answering, and first_seen would be newer anyway
    rig.agent.tick(ts("2026-11-28T10:00:00"))
    assert rig.api.removed == []
    assert rig.state["content"][f"block {stale['address']}"]["published"] == ts("2026-10-30T00:00:00")
    rig.agent.tick(ts("2026-12-01T10:00:00"))
    assert rig.api.removed == [stale["address"]]


def test_keep_in_the_comment_protects_a_list(tmp_path):
    rig, _ = abandon_rig(tmp_path, live(published=OLD), comment="small but good [keep]", dead_after_days=1)
    rig.day(1), rig.day(2)
    assert rig.api.removed == [] and rig.state["strikes"] == {}


def test_keep_doesnt_protect_a_dead_list(tmp_path):
    rig, stale = abandon_rig(tmp_path, DEAD, comment="[keep]", dead_after_days=1)
    rig.day(1)
    assert rig.api.removed == [stale["address"]]


def test_zero_turns_abandonment_off(tmp_path):
    rig, _ = abandon_rig(tmp_path, live(published=OLD), abandoned_after_days=0, dead_after_days=1)
    rig.day(1), rig.day(2)
    assert rig.api.removed == [] and rig.state["strikes"] == {}


def test_many_old_lists_at_once_are_held_back_too(tmp_path):
    items = [adlist("a"), adlist("b"), adlist("c")]
    rig = Rig(tmp_path, items, {i["address"]: live(published=OLD) for i in items[:2]}, dead_after_days=1)
    rig.day(1)
    assert rig.api.removed == []
    assert rig.titles() == ["❌ 2 of 3 adlists look dead or abandoned, so none were removed"]


def test_a_failed_download_doesnt_look_like_a_change(tmp_path):
    rig, stale = abandon_rig(tmp_path, live("v1"))
    rig.day(1)
    rig.verdicts[stale["address"]] = UNKNOWN
    rig.day(2)
    rig.verdicts[stale["address"]] = live("v1")
    rig.day(3)
    assert "changed" not in rig.state["content"][f"block {stale['address']}"]


def test_a_list_gone_from_pihole_is_forgotten(tmp_path):
    rig, stale = abandon_rig(tmp_path, live("v1"))
    rig.day(1)
    assert f"block {stale['address']}" in rig.state["content"]
    rig.api.items.remove(stale)
    rig.day(2)
    assert f"block {stale['address']}" not in rig.state["content"]


# --- The secondary's versions ---

def test_reads_pihole_v():
    text = ("Core version is v6.4.3 (Latest: v6.5)\nWeb version is v6.6 (Latest: v6.6.1)\n"
            "FTL version is v6.8 (Latest: v6.8)\n")
    versions = parse_versions(text)
    assert versions == {"Core": ["v6.4.3", "v6.5"], "Web": ["v6.6", "v6.6.1"], "FTL": ["v6.8", "v6.8"]}
    assert set(outdated(versions)) == {"Core", "Web"}


def test_an_unknown_latest_version_isnt_an_update():
    assert outdated({"Core": ["v6.5", "null"], "Web": ["v6.6", "N/A"]}) == {}


def test_unreadable_versions_are_an_error():
    with pytest.raises(SecondaryError):
        parse_versions("pihole: command not found")


# --- Updating the secondary ---

def test_nothing_to_update_is_silent(tmp_path):
    rig = Rig(tmp_path)
    rig.day(1)
    assert rig.secondary.started == 0 and rig.titles() == []


def test_updates_and_notifies(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    assert rig.secondary.started == 1 and rig.titles() == []
    rig.agent.tick(ts("2026-11-01T10:01:00"))  # still running
    assert rig.titles() == []
    rig.secondary.status, rig.secondary.current = "0", CURRENT
    rig.agent.tick(ts("2026-11-01T10:02:00"))
    assert rig.titles() == ["⬆️ Secondary Pi-hole updated"]
    assert rig.outbox.sent[0].sections[0].lines == ["Core: v6.4.3 → v6.5", "FTL: v6.7.1 → v6.8"]
    assert "update" not in rig.state["run"]


def test_one_update_at_a_time_across_a_restart(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    rig.state.save()
    again = Agent(rig.cfg, State(rig.cfg.state_path), rig.outbox, rig.secondary, primary=lambda: rig.api,
                  check=lambda url: ALIVE)
    open(rig.cfg.run_now_path, "w").close()
    again.tick(ts("2026-11-01T10:05:00"))
    assert rig.secondary.started == 1


def test_a_failed_update_is_reported_with_its_output_and_retried_next_day(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    rig.secondary.status, rig.secondary.output = "1", "Unable to fetch ```"
    rig.agent.tick(ts("2026-11-01T10:02:00"))
    assert rig.titles() == ["❌ `pihole -up` failed on the secondary Pi-hole"]
    assert "Unable to fetch" in rig.outbox.sent[0].sections[0].lines[-1]
    rig.secondary.status = "running"
    rig.day(2)
    assert rig.secondary.started == 2
    rig.secondary.status, rig.secondary.current = "0", CURRENT
    rig.agent.tick(ts("2026-11-02T10:01:00"))
    assert rig.titles()[-1] == "⬆️ Secondary Pi-hole updated" and rig.state["problems"] == {}


def test_success_without_dns_is_a_problem(tmp_path, monkeypatch):
    monkeypatch.setattr("pihole_agent.__main__.time.sleep", lambda _: None)
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    rig.secondary.status, rig.secondary.current, rig.secondary.dns = "0", CURRENT, False
    rig.agent.tick(ts("2026-11-01T10:02:00"))
    assert rig.titles() == ["❌ The secondary Pi-hole isn't right after `pihole -up`"]
    assert "isn't answering DNS" in rig.outbox.sent[0].sections[0].lines[0]


def test_success_while_still_behind_is_a_problem(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    rig.secondary.status = "0"
    rig.agent.tick(ts("2026-11-01T10:02:00"))
    assert rig.titles() == ["❌ The secondary Pi-hole isn't right after `pihole -up`"]


def test_an_update_that_never_ends_is_reported(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.day(1)
    rig.agent.tick(ts("2026-11-01T10:31:00"))
    assert rig.titles() == ["❌ The secondary Pi-hole's update hasn't finished after 30 minutes"]


def test_an_unreachable_secondary_is_said_once_and_cleared(tmp_path):
    rig = Rig(tmp_path)
    rig.secondary.error = "`versions` failed: Permission denied (publickey)."
    rig.day(1), rig.day(2)
    assert rig.titles() == ["❌ Can't check the secondary Pi-hole for updates"]
    rig.secondary.error = None
    rig.day(3)
    assert rig.titles()[-1].startswith("✅ Resolved")


# --- When things run ---

def test_runs_once_a_day_from_the_set_hour(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.agent.tick(ts("2026-11-01T08:59:00"))
    assert rig.secondary.started == 0
    rig.agent.tick(ts("2026-11-01T09:00:00"))
    assert rig.secondary.started == 1
    assert rig.state["run"]["ran"] == "2026-11-01"


def test_a_new_deployment_waits_for_the_next_run(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.agent.start(ts("2026-11-01T14:00:00"))
    rig.agent.tick(ts("2026-11-01T14:01:00"))
    assert rig.secondary.started == 0
    rig.agent.tick(ts("2026-11-02T09:00:00"))
    assert rig.secondary.started == 1


def test_deploying_before_the_hour_still_runs_today(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.agent.start(ts("2026-11-01T07:00:00"))
    rig.agent.tick(ts("2026-11-01T09:00:00"))
    assert rig.secondary.started == 1


def test_run_now_ignores_the_clock(tmp_path):
    rig = Rig(tmp_path, versions=BEHIND)
    rig.agent.start(ts("2026-11-01T14:00:00"))
    open(rig.cfg.run_now_path, "w").close()
    rig.agent.tick(ts("2026-11-01T14:01:00"))
    assert rig.secondary.started == 1


# --- Notifications survive an outage ---

def test_messages_wait_for_discord(tmp_path):
    bad = adlist("bad")
    rig = Rig(tmp_path, [bad, adlist("a"), adlist("b")], {bad["address"]: DEAD}, dead_after_days=1)
    rig.outbox.working = False
    rig.day(1)
    assert rig.api.removed == [bad["address"]] and rig.titles() == []
    restarted = State(rig.cfg.state_path)  # and a restart
    assert len(restarted["pending"]["messages"]) == 1
    rig.agent.state, rig.outbox.working = restarted, True
    rig.agent.tick(ts("2026-11-01T10:01:00"))
    assert rig.titles() == ["🗑️ Removed 1 dead or abandoned adlist from the primary Pi-hole"]
    assert restarted["pending"]["messages"] == []


# --- The primary's API ---

class FakeHttp:
    def __init__(self, status=200, body=None):
        self.status, self.body, self.calls, self.headers = status, body or {}, [], {}

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        response = requests.Response()
        response.status_code = self.status
        response.json = lambda: self.body
        return response


def test_addresses_are_encoded_when_removing():
    api = Primary("http://primary", "pw")
    api.http = FakeHttp(204)
    assert api.remove({"address": "https://cdn.example/gh/x@latest/a.txt?x=1", "type": "block"})
    method, url, kw = api.http.calls[0]
    assert method == "DELETE" and kw["params"] == {"type": "block"}
    assert url == "http://primary/api/lists/https%3A%2F%2Fcdn.example%2Fgh%2Fx%40latest%2Fa.txt%3Fx%3D1"


def test_removing_a_list_already_gone_isnt_a_removal():
    api = Primary("http://primary", "pw")
    api.http = FakeHttp(404)
    assert api.remove({"address": "https://cdn.example/a.txt", "type": "block"}) is False


def test_a_refused_login_is_an_error():
    api = Primary("http://primary", "wrong")
    api.http = FakeHttp(401)
    with pytest.raises(PrimaryError):
        api.__enter__()
