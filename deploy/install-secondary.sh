#!/usr/bin/env bash
# Lets the deployed agent reach the secondary Pi-hole, through deploy/secondary/pihole-agent-cmd only.
# Run from a machine with root SSH to the Proxmox node. Safe to run again.
#   PVE       node with both guests
#   CTID      the secondary Pi-hole's container
#   VM        the Docker host's VM, where the agent's container runs
#   FROM      the Docker host's address: the only place the key is accepted from
set -euo pipefail
: "${PVE:?}" "${CTID:?}" "${VM:?}" "${FROM:?}"
here=$(cd "$(dirname "$0")" && pwd)

pub=$(ssh "$PVE" "qm guest exec $VM -- docker exec pihole-agent cat /var/lib/pihole-agent/id_ed25519.pub" \
  | ssh "$PVE" "python3 -c 'import json,sys; print(json.load(sys.stdin)[\"out-data\"].strip())'")
case "$pub" in ssh-ed25519\ *) ;; *) echo "Couldn't read the agent's public key: is the container running?" >&2; exit 1;; esac

ssh "$PVE" "pct exec $CTID -- bash -c 'cat > /tmp/pihole-agent-cmd && install -m 755 -o root -g root /tmp/pihole-agent-cmd /usr/local/sbin/pihole-agent-cmd && rm /tmp/pihole-agent-cmd'" \
  < "$here/secondary/pihole-agent-cmd"

line="command=\"/usr/local/sbin/pihole-agent-cmd\",restrict,from=\"$FROM\" $pub"
printf '%s\n' "$line" | ssh "$PVE" "pct exec $CTID -- bash -c '
  install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
  read -r line; key=\$(printf %s \"\$line\" | cut -d\" \" -f3)
  grep -vF \"\$key\" /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.new || true
  printf \"%s\n\" \"\$line\" >> /root/.ssh/authorized_keys.new
  mv /root/.ssh/authorized_keys.new /root/.ssh/authorized_keys'"
echo "Installed on CT $CTID. Try it: docker exec pihole-agent python -m pihole_agent check"
