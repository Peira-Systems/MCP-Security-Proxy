defmodule PhoenixElxirBeam.MCP.CiFixtureServer do
  @moduledoc """
  A minimal, real MCP server over Streamable HTTP, exposing a fixed 3-tool
  catalog chosen to exercise `PhoenixElxirBeam.MCP.RuleCoverage`'s two gap
  types plus a clean baseline — used by `mix mcp.rules.seed_fixtures` to
  seed a real `ServerRegistry.register_server/4` handshake in CI, so
  `mix mcp.rules.check` has a real, representative registration to audit
  instead of always reporting "0 servers registered".

  Deliberately separate from `test/support/mcp_http_test_server.ex` (that
  module lives under `test/support`, compiled only under `MIX_ENV=test`,
  and carries streaming/chunking edge cases this seed task doesn't need) —
  this one is compiled under `lib/` so a production-path mix task can
  depend on it under any `MIX_ENV`.

    * `read_secrets` — name/description match `TagInference`'s
      `:sensitive_read` pattern.
    * `post_webhook` — matches `:network_egress`.
    * `list_files` — matches neither; the clean baseline.
  """

  import Plug.Conn

  @tools [
    %{
      "name" => "read_secrets",
      "description" => "Read the contents of a sensitive secrets file",
      "inputSchema" => %{"type" => "object", "properties" => %{}}
    },
    %{
      "name" => "post_webhook",
      "description" => "Post data to an external webhook URL",
      "inputSchema" => %{
        "type" => "object",
        "properties" => %{"url" => %{"type" => "string"}, "body" => %{"type" => "string"}}
      }
    },
    %{
      "name" => "list_files",
      "description" => "List files in the workspace",
      "inputSchema" => %{"type" => "object", "properties" => %{}}
    }
  ]

  @doc "The tool names this server reports, in order."
  def tool_names, do: Enum.map(@tools, & &1["name"])

  @doc """
  Starts the server on a free loopback port under its own one-off
  supervisor (not a test's `start_supervised!`, since this runs from a
  plain mix task process, not inside ExUnit) and returns its base URL.
  """
  def start! do
    port = free_port()

    # Unnamed (no `:name` option) — a fixed, registered name would collide
    # if `start!/0` is ever called more than once in the same BEAM VM
    # (confirmed: this broke when both this module's own test and the seed
    # mix task's test called it in the same `mix test` run).
    {:ok, _pid} =
      Supervisor.start_link(
        [{Bandit, plug: __MODULE__, scheme: :http, ip: {127, 0, 0, 1}, port: port}],
        strategy: :one_for_one
      )

    "http://127.0.0.1:#{port}/mcp"
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)
    port
  end

  # Plug callbacks

  def init(opts), do: opts

  def call(conn, _opts) do
    {:ok, body, conn} = read_body(conn)
    req = Jason.decode!(body)
    payload = respond(req["method"], req["params"] || %{}, req["id"])

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(payload))
  end

  defp respond("initialize", _params, id) do
    ok(id, %{
      "protocolVersion" => "2024-11-05",
      "capabilities" => %{"tools" => %{}},
      "serverInfo" => %{"name" => "ci-fixture-catalog", "version" => "0.0.1"}
    })
  end

  defp respond("tools/list", _params, id) do
    ok(id, %{"tools" => @tools})
  end

  defp respond(_method, _params, id) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => -32601, "message" => "method not found"}
    }
  end

  defp ok(id, result), do: %{"jsonrpc" => "2.0", "id" => id, "result" => result}
end
