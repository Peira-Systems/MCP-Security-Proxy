#!/bin/sh
set -eu

case "${1:-start}" in
  start)
    /app/bin/phoenix_elxir_beam eval "PhoenixElxirBeam.Release.migrate()"
    exec /app/bin/phoenix_elxir_beam start
    ;;
  migrate)
    exec /app/bin/phoenix_elxir_beam eval "PhoenixElxirBeam.Release.migrate()"
    ;;
  *)
    exec /app/bin/phoenix_elxir_beam "$@"
    ;;
esac
