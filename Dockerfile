# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
ARG ELIXIR_VERSION=1.18.5
ARG OTP_VERSION=27.3.4.17
ARG DEBIAN_VERSION=bookworm-20260824-slim

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

# Similarity-layer model/tokenizer files (2026-10-05 plan) -- fetched
# here, in the builder stage, so `mix release` below bundles them into
# the release's priv/ directory. Checksum-verified immediately after
# download; the build fails if either doesn't match (the same integrity
# principle as this project's provenance pins, applied to a build-time
# fetch). `curl` is already installed above for the tailwind/esbuild
# mix tasks.
RUN mkdir -p priv/plugins/model && \
    curl -sL -o priv/plugins/model/model.onnx \
      https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/onnx/model.onnx && \
    curl -sL -o priv/plugins/model/tokenizer.json \
      https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/main/tokenizer.json && \
    echo "10f7a088420252b26caf819236ca2c9d2987afd0fc06fec7553b542a5655a05a  priv/plugins/model/model.onnx" | sha256sum -c - && \
    echo "2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8  priv/plugins/model/tokenizer.json" | sha256sum -c -

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
      python3 python3-pip util-linux \
    && apt-get clean && rm -f /var/lib/apt/lists/*_*

# MIX_ENV is set here (ahead of its previous position below) because the
# similarity-layer COPY --from=builder just below needs it already
# expanded to "prod" to resolve the release path.
ENV MIX_ENV="prod"

# Similarity-layer Python dependencies (2026-10-05 plan) -- installed
# here, in the runtime stage, since this is where `python3` actually
# runs the sidecar script. The model/tokenizer files themselves were
# already fetched into priv/ in the builder stage above and arrive here
# via the release COPY below.
#
# Verified against the real release layout (not just the plan's assumed
# path): `mix release` nests an app's priv/ under
# lib/<app>-<vsn>/priv/, not directly under the release root, so the
# source path below globs the versioned dir instead of hardcoding
# "0.1.0" (which would break on every version bump).
COPY --from=builder /app/_build/${MIX_ENV}/rel/phoenix_elxir_beam/lib/phoenix_elxir_beam-*/priv/plugins/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8
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
