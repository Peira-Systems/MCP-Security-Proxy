# Request-path load test for the MCP Security Proxy (M3.3).
#
#   mix run --no-start bench/load.exs
#
# `--no-start` matters: the script starts the app itself with the HTTP endpoint
# enabled, drives it over real HTTP with `Req` (full plug pipeline: auth, rate
# limit, session store, policy pipeline, upstream), then reports latency.
#
# Env knobs (all optional):
#   LOAD_CONCURRENCY        parallel workers            (default 50)
#   LOAD_DURATION_S         seconds to sustain load     (default 20)
#   LOAD_CALLS_PER_SESSION  tools/call per handshake    (default 5)
#   LOAD_WARMUP_S           warmup before measuring     (default 3)
#   LOAD_BUDGET_P99_MS      pipeline pre_call p99 budget (default 10)
#   LOAD_ENFORCE            "true" ⇒ exit 1 if over budget (default false)
#
# The number that matters is the *pipeline* phase latency (the proxy's own
# added cost), read from the mcp_pipeline_run_stop_duration histogram. The
# end-to-end figure includes the stdio upstream fixture and is reported for
# context only. See docs/latency-budget.md.

require Logger
Logger.configure(level: :warning)

concurrency = String.to_integer(System.get_env("LOAD_CONCURRENCY", "50"))
duration_ms = String.to_integer(System.get_env("LOAD_DURATION_S", "20")) * 1000
calls_per_session = String.to_integer(System.get_env("LOAD_CALLS_PER_SESSION", "5"))
warmup_ms = String.to_integer(System.get_env("LOAD_WARMUP_S", "3")) * 1000
budget_p99_ms = String.to_float(System.get_env("LOAD_BUDGET_P99_MS", "10.0"))
enforce? = System.get_env("LOAD_ENFORCE") == "true"

# -- boot the app with the endpoint serving -----------------------------------
# Enable the HTTP server; strip the dev-only asset watchers / reloader so this
# runs clean under `MIX_ENV=dev` in CI with no Node/esbuild toolchain.
Application.put_env(
  :phoenix_elxir_beam,
  PhoenixElxirBeamWeb.Endpoint,
  Application.get_env(:phoenix_elxir_beam, PhoenixElxirBeamWeb.Endpoint)
  |> Keyword.put(:server, true)
  |> Keyword.put(:watchers, [])
  |> Keyword.put(:code_reloader, false)
  |> Keyword.put(:live_reload, [])
)

# Take the per-principal rate limiter out of the way — this bench measures
# pipeline latency, not the limiter (which has its own suite).
Application.put_env(:phoenix_elxir_beam, PhoenixElxirBeam.MCP.RateLimiter,
  window_ms: 1_000,
  max_per_window: 10_000_000
)

{:ok, _} = Application.ensure_all_started(:phoenix_elxir_beam)

alias PhoenixElxirBeam.MCP.{ApiKey, ServerRegistry}

port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]
base = "http://127.0.0.1:#{port}"

node = System.find_executable("node") || raise "node is required for the stdio fixture"
fixture = Path.expand("../test/support/fixtures/catalog_mcp_server.js", __DIR__)

{:ok, server} =
  ServerRegistry.register_stdio_server("bench-#{System.system_time()}", node, [fixture])

# One key per worker — mirrors one agent identity per client.
tokens =
  for i <- 1..concurrency do
    {:ok, _key, token} =
      ApiKey.issue(%{principal: "bench", agent_id: "agent://bench-#{i}", all_servers: true})

    token
  end

IO.puts(
  "target #{base}  server #{server.id}  concurrency #{concurrency}  duration #{duration_ms}ms"
)

# -- one worker: handshake, N calls, teardown; repeat until deadline ----------
defmodule Worker do
  def run(base, server_id, token, calls, deadline, acc \\ {[], 0}) do
    auth = [{"authorization", "Bearer #{token}"}]

    if System.monotonic_time(:millisecond) >= deadline do
      acc
    else
      acc = session(base, server_id, auth, calls, acc)
      run(base, server_id, token, calls, deadline, acc)
    end
  end

  defp session(base, server_id, auth, calls, {lat, errs}) do
    url = "#{base}/mcp/proxy/#{server_id}"

    with {:ok, %{status: 200} = init} <-
           Req.post(url,
             headers: auth,
             retry: false,
             json: %{
               "jsonrpc" => "2.0",
               "id" => 1,
               "method" => "initialize",
               "params" => %{
                 "protocolVersion" => "2025-06-18",
                 "clientInfo" => %{"name" => "bench", "version" => "1"}
               }
             }
           ),
         [sid | _] <- Req.Response.get_header(init, "mcp-session-id") do
      sauth = [{"mcp-session-id", sid} | auth]

      Req.post(url,
        headers: sauth,
        retry: false,
        json: %{"jsonrpc" => "2.0", "method" => "notifications/initialized"}
      )

      {lat, errs} =
        Enum.reduce(1..calls, {lat, errs}, fn _, {lat, errs} ->
          t0 = System.monotonic_time(:microsecond)

          result =
            Req.post(url,
              headers: sauth,
              retry: false,
              json: %{
                "jsonrpc" => "2.0",
                "id" => 2,
                "method" => "tools/call",
                "params" => %{"name" => "readme", "arguments" => %{}}
              }
            )

          dt = System.monotonic_time(:microsecond) - t0

          case result do
            {:ok, %{status: 200}} -> {[dt | lat], errs}
            _ -> {lat, errs + 1}
          end
        end)

      Req.request(method: :delete, url: url, headers: sauth, retry: false)
      {lat, errs}
    else
      _ -> {lat, errs + 1}
    end
  end
end

deadline = fn ms -> System.monotonic_time(:millisecond) + ms end

# -- warmup -----------------------------------------------------------------
if warmup_ms > 0 do
  IO.puts("warming up #{warmup_ms}ms…")

  tokens
  |> Enum.map(fn token ->
    Task.async(fn ->
      Worker.run(base, server.id, token, calls_per_session, deadline.(warmup_ms))
    end)
  end)
  |> Task.await_many(warmup_ms + 30_000)
end

# -- measured run ---------------------------------------------------------------
IO.puts("measuring #{duration_ms}ms…")
wall0 = System.monotonic_time(:millisecond)

results =
  tokens
  |> Enum.map(fn token ->
    Task.async(fn ->
      Worker.run(base, server.id, token, calls_per_session, deadline.(duration_ms))
    end)
  end)
  |> Task.await_many(duration_ms + 60_000)

wall_ms = System.monotonic_time(:millisecond) - wall0

latencies = results |> Enum.flat_map(&elem(&1, 0)) |> Enum.sort()
errors = results |> Enum.map(&elem(&1, 1)) |> Enum.sum()
n = length(latencies)

pct = fn p ->
  if n == 0, do: 0.0, else: Enum.at(latencies, min(n - 1, round(p / 100 * n))) / 1000
end

IO.puts("""

── end-to-end tools/call (proxy + stdio fixture) ─────────────────
  samples      #{n}   errors #{errors}
  throughput   #{Float.round(n * 1000 / wall_ms, 1)} req/s
  p50 / p90    #{Float.round(pct.(50), 2)} / #{Float.round(pct.(90), 2)} ms
  p99 / max    #{Float.round(pct.(99), 2)} / #{Float.round((List.last(latencies) || 0) / 1000, 2)} ms
""")

# -- phase latency from the Prometheus histograms -----------------------------
scrape = TelemetryMetricsPrometheus.Core.scrape(PhoenixElxirBeamWeb.Telemetry.prometheus_name())

to_num = fn
  "+Inf" -> :infinity
  s -> s |> Float.parse() |> elem(0)
end

buckets_for = fn metric, tag ->
  Regex.scan(
    ~r/#{metric}_bucket\{[^}]*#{tag}[^}]*le="([^"]+)"\}\s+([0-9.eE+-]+)/,
    scrape
  )
  |> Enum.map(fn [_, le, c] -> {to_num.(le), elem(Float.parse(c), 0)} end)
  |> Enum.sort_by(fn {le, _} -> (le == :infinity && 1.0e18) || le end)
end

quantile = fn buckets, q ->
  with [_ | _] <- buckets,
       {_, total} when total > 0 <- List.last(buckets),
       {le, _} <- Enum.find(buckets, fn {_, c} -> c >= q * total end) do
    (le == :infinity && :inf) || le
  else
    _ -> :na
  end
end

report_hist = fn label, buckets ->
  IO.puts(
    "  #{String.pad_trailing(label, 22)} p50 ≤ #{inspect(quantile.(buckets, 0.5))} ms" <>
      "   p99 ≤ #{inspect(quantile.(buckets, 0.99))} ms"
  )
end

pre_buckets = buckets_for.("mcp_pipeline_run_stop_duration", ~s(phase="pre_call"))
p99 = quantile.(pre_buckets, 0.99)

IO.puts("── phase latency (histogram bucket ceilings) ─────────────────────")
report_hist.("pipeline pre_call", pre_buckets)

report_hist.(
  "pipeline post_call",
  buckets_for.("mcp_pipeline_run_stop_duration", ~s(phase="post_call"))
)

report_hist.(
  "upstream (http/stdio)",
  buckets_for.("mcp_upstream_request_stop_duration", "transport=")
)

IO.puts("  budget: pre_call p99 ≤ #{budget_p99_ms} ms\n")

over? = is_number(p99) and p99 > budget_p99_ms

cond do
  errors > n * 0.01 ->
    IO.puts("RESULT: FAIL — error rate #{Float.round(errors * 100 / max(n, 1), 2)}% > 1%")

  over? ->
    IO.puts("RESULT: #{if enforce?, do: "FAIL", else: "WARN"} — pipeline p99 over budget")

  true ->
    IO.puts("RESULT: PASS")
end

ServerRegistry.remove_server(server.id)

if (over? and enforce?) or errors > n * 0.01, do: System.halt(1)
