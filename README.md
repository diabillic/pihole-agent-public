# pihole-agent

For a pair of Pi-holes kept in step by [nebula-sync](https://github.com/lovelaze/nebula-sync). Once a day it
removes dead and abandoned adlists from the primary, and runs `pihole -up` on the secondary if it's behind. It
posts to Discord when it does either, or when something goes wrong. A day with nothing to do posts nothing; if
the agent itself stops, its container goes unhealthy, so anything watching container health can alert.

It runs as a Docker container and needs Pi-hole v6.

## Dead adlists

Each list on the primary, block or allow, enabled or not, is downloaded with up to 3 tries.

| The list | Today's verdict |
|---|---|
| Has domains in it, and shows a sign of life (below) | Alive, and any failures so far are forgotten |
| Has domains in it, but no sign of life for `ABANDONED_AFTER_DAYS` | Failed |
| HTTP 400 or above, except 429 | Failed |
| No domains in the response, such as a parked page | Failed |
| Domain gone, connection refused, timed out or TLS failure | Failed |
| HTTP 429, or public DNS can't be reached (our connection is probably down) | Not judged |
| Its host is blocked by Pi-hole itself | Not judged |
| Not a web address (`file://`) | Not judged |

A list that fails on `DEAD_AFTER_DAYS` runs in a row (default 3, runs where it isn't judged don't count either
way) is removed and gravity is rebuilt. The Discord message has its full address, so it's easy to add back.
nebula-sync copies the change to the secondary within the hour; the secondary keeps blocking that list's
domains until its own next gravity run.

**It won't remove more than half the lists at once.** Lists often share a host, so that looks like an outage. It
posts them instead, for you to remove by hand if they really are dead.

## Abandoned adlists

A list that still downloads can be years out of date. The agent looks for the latest of these signs of life:

- **A change it saw itself:** it keeps a hash of each list's whole file, comments included, and notes when that
  changes.
- **The date from the list's source:** the HTTP `Last-Modified` header, or for files served from
  `raw.githubusercontent.com` or `cdn.jsdelivr.net/gh`, which don't send one, the last commit to touch the file
  (GitHub's API, without a token, one call per list per day).

If the latest is older than `ABANDONED_AFTER_DAYS` (default 180), the list counts as failed, and everything above
applies, including the days in a row and the limit of half. With no date from its source, the count starts when
the agent first sees the list, so that kind of list can't be flagged sooner than `ABANDONED_AFTER_DAYS` after
that.

Some small lists are finished, not abandoned. **Put `[keep]` in a list's comment in Pi-hole** and it's never
treated as abandoned, though it's still removed if it dies. Without that, a list you add back after it's removed
as abandoned is simply removed again.

A list whose file is regenerated with a fresh date in its header counts as alive, even if its domains never
change. That's deliberate: it errs towards keeping lists.

## Updates on the secondary

The agent runs `pihole updatechecker` and reads `pihole -v`. If anything is behind, it starts `pihole -up` in
its own systemd unit, so a dropped connection or agent restart can't interrupt it, and follows it from there.
Discord gets the version changes afterwards, once the versions are current and DNS answers, or else the end of
the update's output. A failure is posted once and tried again the next day. There's no snapshot first, since
the primary keeps answering DNS and nebula-sync can restore the settings.

The primary isn't updated. This suits a primary running as a container, where `pihole -up` doesn't apply.

## Doing a run by hand

```bash
docker exec pihole-agent python -m pihole_agent check                # changes nothing, prints what it finds
docker exec pihole-agent touch /var/lib/pihole-agent/run-now         # a real run, within a minute
```

`check` doesn't compare hashes between runs, so it shows each list's verdict and last published date only.

## Deployment

Every push to `main` runs the tests, then deploys to the Docker host with `agent-deploy`, a small root-owned
script that builds the image and replaces the container. To run it elsewhere, build the `Dockerfile` and pass the
settings in `.env.example`. A brand new deployment waits for the next `CHECK_HOUR` before doing anything.

State and the agent's SSH key are in the `pihole-agent-data` volume. The key is made there on first start, so a
new volume needs this run again, from a machine with root SSH to the Proxmox node. It assumes the secondary is an
LXC container and the Docker host a VM on that node. Safe to repeat:

```bash
PVE=<node> CTID=<secondary's container id> VM=<Docker host's VM id> FROM=<Docker host's address> deploy/install-secondary.sh
```

It installs `deploy/secondary/pihole-agent-cmd` and adds the key to root's `authorized_keys` on the secondary,
limited to that script and to connections from the Docker host. **After changing that script, run this again:
deploying the agent doesn't update it.**

## Secrets and variables

This repository contains **no secrets**. Set these under **Settings → Secrets and variables → Actions**.

### Secrets

| Name | Required | Expected value |
|---|---|---|
| `NOTIFY_URLS` | **yes** | Apprise URLs or Discord webhook URLs, comma separated. |
| `PIHOLE_PASSWORD` | **yes** | An app password for the primary's API (Settings → Web interface / API in Pi-hole). Sent over plain HTTP on your LAN if `PRIMARY_URL` is `http://`. |

### Variables

| Name | Required | Expected value |
|---|---|---|
| `AGENT_HOST` | **yes** | Address of the Docker host. |
| `PRIMARY_URL` | **yes** | The primary Pi-hole's address, such as `http://pi.hole`. |
| `SECONDARY_HOST` | **yes** | The secondary Pi-hole's address. |
| `SECONDARY_HOST_KEY` | **yes** | Its SSH host key: the first two fields of `/etc/ssh/ssh_host_ed25519_key.pub`. |
| `CHECK_HOUR` | no | Hour of the daily run, 0 to 23, in the container's time zone (default 9). |
| `DEAD_AFTER_DAYS` | no | Runs in a row a list must fail before it's removed, at least 1 (default 3). |
| `ABANDONED_AFTER_DAYS` | no | Days with no sign of a change before a list counts as failed (default 180). 0 turns this off. |
