#!/usr/bin/env bash
# Rebuilds rule-engine-wasm and copies it to priv/wasm_plugins/rule_engine.wasm,
# where the proxy loads it from (see config/dev.exs's {:wasm, ...} entry and
# docs/plugin-supply-chain.md for the provenance pin this changes).
#
# Needs a Rust toolchain with the wasm32-wasip1 target. If you don't have one
# locally, this is exactly what CI/the Dockerfile use it for too -- run it
# inside `rust:1-bookworm` (or newer) with the crate directory mounted:
#
#   docker run --rm -v "$(pwd):/spike" -w /spike rust:1-bookworm \
#     sh -c "rustup target add wasm32-wasip1 && ./build.sh"

set -euo pipefail
cd "$(dirname "$0")"

rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/rule_engine_wasm.wasm ../rule_engine.wasm

echo "built ../rule_engine.wasm ($(wc -c < ../rule_engine.wasm) bytes)"
echo
echo "recompute the provenance digest to update the pin in config/dev.exs with:"
echo '  mix run --no-start -e '"'"'IO.puts PhoenixElxirBeam.MCP.Plugin.Provenance.wasm_code_digest("priv/wasm_plugins/rule_engine.wasm")'"'"
