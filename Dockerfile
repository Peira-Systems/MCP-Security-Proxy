# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
ARG ELIXIR_VERSION=1.17.3
ARG OTP_VERSION=27.1.2
ARG DEBIAN_VERSION=bookworm-20241202-slim

ARG BUILDER_IMAGE="hexpm/elixir:${ELIXIR_VERSION}-erlang-${OTP_VERSION}-debian-${DEBIAN_VERSION}"
ARG RUNNER_IMAGE="debian:${DEBIAN_VERSION}"

FROM ${BUILDER_IMAGE} AS builder

# git fetches the heroicons/daisyui github deps declared in mix.exs; curl
# lets the tailwind/esbuild mix tasks download their binaries. (postgrex is
# pure Elixir — no build toolchain needed for the DB driver.)
RUN apt-get update -y && apt-get install -y git curl ca-certificates \
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

# ---- Runtime stage ----------------------------------------------------------
FROM ${RUNNER_IMAGE} AS runner

# python3 backs the in-tree prompt-injection sidecar plugin
# (priv/plugins/prompt_injection_scanner.py), spawned over stdio by the
# plugin Registry.
# util-linux provides `prlimit` for the sidecar resource caps (M3.5).
RUN apt-get update -y && \
    apt-get install -y libstdc++6 openssl libncurses6 locales ca-certificates curl \
      python3 util-linux \
    && apt-get clean && rm -f /var/lib/apt/lists/*_*

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8
ENV MIX_ENV="prod"
ENV PHX_SERVER=true

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home /app app && \
    chown app:app /app

COPY --from=builder --chown=app:app /app/_build/${MIX_ENV}/rel/phoenix_elxir_beam ./
COPY --chown=app:app docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

USER app

EXPOSE 4000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["start"]
