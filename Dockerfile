# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
ARG ELIXIR_VERSION=1.17.3
ARG OTP_VERSION=27.1.2
ARG DEBIAN_VERSION=bookworm-20241202-slim

ARG BUILDER_IMAGE="hexpm/elixir:${ELIXIR_VERSION}-erlang-${OTP_VERSION}-debian-${DEBIAN_VERSION}"
ARG RUNNER_IMAGE="debian:${DEBIAN_VERSION}"

FROM ${BUILDER_IMAGE} AS builder

# git is required to fetch the heroicons/daisyui github deps declared in
# mix.exs; build-essential + curl are needed to compile exqlite (sqlite)
# and to let the tailwind/esbuild mix tasks download their binaries.
RUN apt-get update -y && apt-get install -y build-essential git curl ca-certificates \
    && apt-get clean && rm -f /var/lib/apt/lists/*_*

WORKDIR /app

RUN mix local.hex --force && \
    mix local.rebar --force

ENV MIX_ENV="prod"

COPY mix.exs mix.lock ./
RUN mix deps.get --only $MIX_ENV
RUN mkdir config

# Compile-time config first, so dependency compilation is cached separately
# from the app's own source changes.
COPY config/config.exs config/${MIX_ENV}.exs config/
RUN mix deps.compile

COPY priv priv
COPY lib lib
COPY assets assets

# mix compile must run first: it generates the colocated CSS/JS that
# assets.deploy's tailwind/esbuild steps import from.
RUN mix compile
RUN mix assets.deploy

# Runtime config (config/runtime.exs) is intentionally copied last — it's
# read at boot, not at compile time, so it doesn't need to invalidate the
# compile cache above.
COPY config/runtime.exs config/

RUN mix release

# ---- Demo MCP server stage ------------------------------------------------
# The dashboard's "+ filesystem" button spawns the real
# `@modelcontextprotocol/server-filesystem` as a stdio subprocess. Install it
# (and get a matching Node runtime) here so the runtime image can copy just
# the built artifacts instead of carrying npm.
FROM node:22-bookworm-slim AS mcp-node

ARG MCP_FILESYSTEM_VERSION=2026.7.10
RUN npm install --omit=dev --prefix /opt/mcp/filesystem \
      "@modelcontextprotocol/server-filesystem@${MCP_FILESYSTEM_VERSION}" \
    && npm cache clean --force

# ---- Runtime stage ----------------------------------------------------------
FROM ${RUNNER_IMAGE} AS runner

# python3 + python3-venv back the "+ fetch" demo server (mcp-server-fetch).
RUN apt-get update -y && \
    apt-get install -y libstdc++6 openssl libncurses6 locales ca-certificates curl \
      python3 python3-venv \
    && apt-get clean && rm -f /var/lib/apt/lists/*_*

# Real stdio MCP servers spawned by the dashboard presets. MCP_FILESYSTEM_CMD /
# MCP_FETCH_CMD are read by PhoenixElxirBeamWeb.MCPDashboardLive; the filesystem
# command gets the sandbox directory appended automatically.
ARG MCP_SERVER_FETCH_VERSION=2026.8.18
COPY --from=mcp-node /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp-node /opt/mcp/filesystem /opt/mcp/filesystem
RUN python3 -m venv /opt/mcp/venv && \
    /opt/mcp/venv/bin/pip install --no-cache-dir \
      "mcp-server-fetch==${MCP_SERVER_FETCH_VERSION}"

ENV MCP_FILESYSTEM_CMD="/usr/local/bin/node /opt/mcp/filesystem/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js" \
    MCP_FETCH_CMD="/opt/mcp/venv/bin/python -m mcp_server_fetch"

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8
ENV MIX_ENV="prod"
ENV PHX_SERVER=true

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home /app app && \
    mkdir -p /data && chown app:app /data /app

COPY --from=builder --chown=app:app /app/_build/${MIX_ENV}/rel/phoenix_elxir_beam ./
COPY --chown=app:app docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

USER app

VOLUME ["/data"]
EXPOSE 4000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["start"]
