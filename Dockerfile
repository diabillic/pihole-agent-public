# Build: docker build --pull --build-arg PATCHED_AT=$(date +%s) --build-arg REVISION=$(git rev-parse HEAD) -t pihole-agent .
# Run:   docker run -d --name pihole-agent --restart unless-stopped \
#     --env-file agent.env \
#     -v pihole-agent-data:/var/lib/pihole-agent \
#     pihole-agent
#
# agent.env holds the settings in .env.example (the deploy workflow renders it from repo variables and secrets).

FROM python:3.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
ENV TZ=America/New_York

ARG DEBIAN_FRONTEND=noninteractive
ARG PATCHED_AT=unknown
RUN echo "Patching the base OS ($PATCHED_AT)" \
 && apt-get update \
 && apt-get -y full-upgrade \
 && apt-get install -y --no-install-recommends ca-certificates openssh-client tzdata \
 && ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime && echo "$TZ" > /etc/timezone \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --system pihole-agent \
 && useradd --system --gid pihole-agent --home-dir /var/lib/pihole-agent --shell /usr/sbin/nologin pihole-agent \
 && install -d -o pihole-agent -g pihole-agent /var/lib/pihole-agent

WORKDIR /opt/pihole-agent/app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY pihole_agent/ ./pihole_agent/
ARG REVISION=unknown
RUN echo "$REVISION" > REVISION

USER pihole-agent
VOLUME ["/var/lib/pihole-agent"]
HEALTHCHECK --interval=60s --timeout=15s --start-period=2m --retries=5 \
  CMD ["python", "-m", "pihole_agent.health"]
CMD ["python", "-m", "pihole_agent"]
