defmodule PhoenixElxirBeam.MCP.Health do
  @moduledoc """
  Readiness assessment for the proxy (M3.2).

  `check/0` reports whether the process can actually serve traffic:

    * `:db` — a `SELECT 1` against Postgres succeeds;
    * `:upstreams` — each registered upstream is reachable (`:http` → the base
      URL answers *anything*; `:stdio` → the subprocess is alive), plus any
      persisted server that failed to restore on boot.

  `GET /health/ready` returns `200` when `status == :ok`, `503` otherwise.
  `GET /health/live` never consults this — liveness is process-only, so a
  transient upstream outage doesn't get the container killed by an orchestrator.

  Whether an unreachable upstream actually fails readiness is governed by
  `config :phoenix_elxir_beam, :readiness, require_upstreams: true` (default
  true — matches the productionization plan; set false to treat upstream
  reachability as advisory only).

  `refresh/0` is called on the telemetry-poller period: it runs `check/0`, feeds
  the `mcp.servers.unreachable` gauge, and raises a `:upstream_unreachable`
  alert on the transition into a degraded set (and a recovery log on the way
  back), deduped via `:persistent_term`.
  """

  require Logger

  alias PhoenixElxirBeam.MCP.{Alerts, HttpTransport, ServerRegistry, ServerStore}
  alias PhoenixElxirBeam.Repo

  @probe_timeout_ms 2_000
  @pt_key {__MODULE__, :degraded_ids}

  @type upstream :: %{id: String.t(), name: String.t(), transport: atom(), status: atom()}
  @type report :: %{
          status: :ok | :degraded,
          db: :ok | :error,
          upstreams: [upstream()],
          unreachable: non_neg_integer()
        }

  @spec check() :: report()
  def check do
    db = db_status()
    upstreams = upstream_statuses()
    unreachable = Enum.count(upstreams, &(&1.status != :ok))
    require_upstreams? = Keyword.get(readiness_config(), :require_upstreams, true)

    ok? = db == :ok and (not require_upstreams? or unreachable == 0)

    %{
      status: if(ok?, do: :ok, else: :degraded),
      db: db,
      upstreams: upstreams,
      unreachable: unreachable
    }
  end

  @doc false
  def refresh do
    report = check()

    :telemetry.execute(
      [:mcp, :servers],
      %{
        count: Enum.count(report.upstreams, &(&1.status == :ok)),
        unreachable: report.unreachable
      },
      %{}
    )

    degraded_now = for u <- report.upstreams, u.status != :ok, into: MapSet.new(), do: u.id
    degraded_before = :persistent_term.get(@pt_key, MapSet.new())

    newly_degraded = MapSet.difference(degraded_now, degraded_before)
    recovered = MapSet.difference(degraded_before, degraded_now)

    for id <- newly_degraded do
      u = Enum.find(report.upstreams, &(&1.id == id))

      Alerts.emit(:upstream_unreachable, :warning, "upstream #{u.name} (#{id}) is unreachable", %{
        server_id: id,
        transport: u.transport
      })
    end

    if MapSet.size(recovered) > 0 do
      Logger.info("mcp.health: upstream(s) recovered: #{Enum.join(recovered, ", ")}")
    end

    :persistent_term.put(@pt_key, degraded_now)
    report
  end

  # -- internals ---------------------------------------------------------

  defp db_status do
    case Ecto.Adapters.SQL.query(Repo, "SELECT 1", []) do
      {:ok, _} -> :ok
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    :exit, _ -> :error
  end

  defp upstream_statuses do
    live = ServerRegistry.list_servers()
    live_ids = MapSet.new(live, & &1.id)

    probed =
      live
      |> Task.async_stream(&probe/1,
        timeout: @probe_timeout_ms + 500,
        on_timeout: :kill_task,
        max_concurrency: 8
      )
      |> Enum.zip(live)
      |> Enum.map(fn
        {{:ok, status}, server} ->
          %{id: server.id, name: server.name, transport: server.transport, status: status}

        {{:exit, _}, server} ->
          %{id: server.id, name: server.name, transport: server.transport, status: :timeout}
      end)

    # Persisted servers that never made it into the live map (boot restore /
    # re-handshake failed) count as unreachable too.
    persisted_missing =
      for reg <- safe_all(), reg.id not in live_ids do
        %{id: reg.id, name: reg.name, transport: reg.transport, status: :not_restored}
      end

    probed ++ persisted_missing
  end

  defp probe(%{transport: :stdio, pid: pid}) when is_pid(pid) do
    if Process.alive?(pid), do: :ok, else: :down
  end

  defp probe(%{transport: :stdio}), do: :down

  defp probe(%{transport: :http} = server) do
    {url, headers} = HttpTransport.prepare(server.base_url)

    # @probe_timeout_ms stays fixed regardless of a server's own timeout_ms
    # override — a readiness probe should stay fast, not wait as long as a
    # tool call is allowed to. tls_verify still applies: a probe against a
    # self-signed dev server shouldn't itself report unreachable.
    case Req.request(
           method: :get,
           url: url,
           headers: headers,
           receive_timeout: @probe_timeout_ms,
           connect_options: HttpTransport.connect_options(server),
           retry: false
         ) do
      # Any HTTP answer means the socket + server are up; MCP servers commonly
      # reject a bare GET with 405/406, which is still "reachable".
      {:ok, _resp} -> :ok
      {:error, _} -> :unreachable
    end
  rescue
    _ -> :unreachable
  catch
    :exit, _ -> :unreachable
  end

  defp probe(_), do: :unreachable

  defp safe_all do
    ServerStore.all()
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp readiness_config, do: Application.get_env(:phoenix_elxir_beam, :readiness, [])
end
