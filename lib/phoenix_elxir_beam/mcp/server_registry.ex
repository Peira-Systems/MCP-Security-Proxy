defmodule PhoenixElxirBeam.MCP.ServerRegistry do
  @moduledoc """
  Registry of real MCP servers registered at runtime from the dashboard,
  over either of two real transports. In-memory for the request path, with
  every registration persisted to Postgres (`PhoenixElxirBeam.MCP.ServerStore`)
  so a restart reloads them and re-handshakes — no hand re-registration
  after a deploy.

  Transports:

    * `:http` — Streamable HTTP against a base URL.
    * `:stdio` — a real MCP server process spawned locally, spoken to
      directly over its stdin/stdout via `PhoenixElxirBeam.MCP.StdioServer`.

  Either way, registering a server performs a real `initialize` +
  `tools/list` handshake, capturing whatever `tools` it reports (and, for
  `:http`, the upstream `mcp-session-id`, if any, so later `tools/call`
  forwards can reuse the same MCP session). Discovered tools start untagged
  — `ProxyController` only enforces the tool-chaining policy on tags a human
  has explicitly assigned via `set_tool_tags/3`.

  Each tool's definition is content-hashed at registration
  (`PhoenixElxirBeam.MCP.ToolHash`). `rehandshake/2` re-runs the handshake
  and feeds the fresh tools + the pinned hashes through the `discovery`
  scanner set (`PhoenixElxirBeam.MCP.Pipeline.run_discovery/2`); a scanner
  can `quarantine` a tool that drifted (rug pull). Every mutation broadcasts
  `{:servers_changed}` on the `"mcp:servers"` PubSub topic so dashboards
  refresh.
  """

  use GenServer
  require Logger

  alias PhoenixElxirBeam.MCP.{
    CallContext,
    HttpTransport,
    Pipeline,
    ServerRegistration,
    ServerStore,
    StdioServer,
    ToolHash
  }

  alias PhoenixElxirBeam.MCP.Plugin.Registry, as: PluginRegistry

  @servers_topic "mcp:servers"

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  @doc """
  Registers a real HTTP server, discovering its tools via a live handshake.

  `opts` (all optional, M1.5 follow-up):

    * `:timeout_ms` — overrides the default upstream receive timeout for
      every request to this server (handshake, forwarded calls, streaming).
    * `:tls_verify` — overrides `config :phoenix_elxir_beam,
      :upstream_tls_verify` for just this server.

  Either left unset inherits the proxy-wide default.
  """
  def register_server(name, base_url, opts \\ [], registry \\ __MODULE__) do
    GenServer.call(registry, {:register, name, base_url, opts}, 15_000)
  end

  @doc """
  Registers a real MCP server process, spawning `cmd` with `args` and
  discovering its tools via a live handshake over stdio.
  """
  def register_stdio_server(name, cmd, args, registry \\ __MODULE__) do
    GenServer.call(registry, {:register_stdio, name, cmd, args}, 20_000)
  end

  def list_servers(registry \\ __MODULE__) do
    GenServer.call(registry, :list)
  end

  def get_server(server_id, registry \\ __MODULE__) do
    GenServer.call(registry, {:get, server_id})
  end

  @doc "Overwrites the tag list for a single discovered tool."
  def set_tool_tags(server_id, tool_name, tags, registry \\ __MODULE__) do
    GenServer.call(registry, {:set_tags, server_id, tool_name, tags})
  end

  @doc """
  Re-runs the `initialize` + `tools/list` handshake against an already
  registered server, compares each tool's fresh definition hash against the
  one pinned last time, and runs the `discovery` scanner set. A tool that
  drifted may be quarantined. Operator-assigned tags are carried across.
  """
  def rehandshake(server_id, registry \\ __MODULE__) do
    GenServer.call(registry, {:rehandshake, server_id}, 20_000)
  end

  @doc "Lifts a scanner-imposed quarantine on a single tool."
  def clear_tool_block(server_id, tool_name, registry \\ __MODULE__) do
    GenServer.call(registry, {:clear_tool_block, server_id, tool_name})
  end

  def remove_server(server_id, registry \\ __MODULE__) do
    GenServer.call(registry, {:remove, server_id})
  end

  # Server callbacks

  @impl true
  def init(_), do: {:ok, %{servers: %{}}, {:continue, :restore}}

  @impl true
  def handle_continue(:restore, state) do
    servers =
      for reg <- ServerStore.all(), reduce: %{} do
        acc ->
          case safe_restore(reg) do
            {:ok, server} ->
              Map.put(acc, server.id, server)

            {:error, reason} ->
              Logger.warning(
                "ServerRegistry: could not restore #{reg.id} (#{reg.name}): #{inspect(reason)}"
              )

              acc
          end
      end

    if map_size(servers) > 0 do
      Logger.info("ServerRegistry: restored #{map_size(servers)} server(s) from Postgres")
      broadcast_change()
    end

    {:noreply, %{state | servers: servers}}
  end

  @impl true
  def handle_call({:register, name, base_url, opts}, _from, state) do
    timeout_ms = opts[:timeout_ms]
    tls_verify = opts[:tls_verify]

    case discover(base_url, %{timeout_ms: timeout_ms, tls_verify: tls_verify}) do
      {:ok, session_id, tools} ->
        server =
          apply_discovery(
            %{
              id: generate_id(),
              name: name,
              transport: :http,
              base_url: base_url,
              session_id: session_id,
              pid: nil,
              timeout_ms: timeout_ms,
              tls_verify: tls_verify,
              tools: discovered_tools(tools),
              findings: [],
              last_handshake_at: DateTime.utc_now()
            },
            %{}
          )

        {:reply, {:ok, server}, put_and_broadcast(state, server)}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:register_stdio, name, cmd, args}, _from, state) do
    case DynamicSupervisor.start_child(
           PhoenixElxirBeam.MCP.StdioServerSupervisor,
           {StdioServer, cmd: cmd, args: args}
         ) do
      {:ok, pid} ->
        case discover_stdio(pid) do
          {:ok, tools} ->
            server =
              apply_discovery(
                %{
                  id: generate_id(),
                  name: name,
                  transport: :stdio,
                  base_url: nil,
                  session_id: nil,
                  timeout_ms: nil,
                  tls_verify: nil,
                  pid: pid,
                  command: cmd,
                  args: args,
                  command_label: command_label(cmd, args),
                  tools: discovered_tools(tools),
                  findings: [],
                  last_handshake_at: DateTime.utc_now()
                },
                %{}
              )

            {:reply, {:ok, server}, put_and_broadcast(state, server)}

          {:error, reason} ->
            DynamicSupervisor.terminate_child(PhoenixElxirBeam.MCP.StdioServerSupervisor, pid)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, "failed to start server process: #{inspect(reason)}"}, state}
    end
  end

  @impl true
  def handle_call({:rehandshake, server_id}, _from, state) do
    case Map.get(state.servers, server_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{transport: :http} = server ->
        case discover(server.base_url, server) do
          {:ok, session_id, raw_tools} ->
            server = rehandshaked(%{server | session_id: session_id}, raw_tools)
            {:reply, {:ok, server}, put_and_broadcast(state, server)}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      %{transport: :stdio, pid: pid} = server ->
        case discover_stdio(pid) do
          {:ok, raw_tools} ->
            server = rehandshaked(server, raw_tools)
            {:reply, {:ok, server}, put_and_broadcast(state, server)}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:clear_tool_block, server_id, tool_name}, _from, state) do
    case Map.get(state.servers, server_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      server ->
        tools =
          Enum.map(server.tools, fn
            %{name: ^tool_name} = tool ->
              %{tool | quarantined: false, quarantine_reason: nil}

            tool ->
              tool
          end)

        server = %{server | tools: tools}
        {:reply, {:ok, server}, put_and_broadcast(state, server)}
    end
  end

  @impl true
  def handle_call(:list, _from, state) do
    {:reply, state.servers |> Map.values() |> Enum.sort_by(& &1.name), state}
  end

  @impl true
  def handle_call({:get, server_id}, _from, state) do
    {:reply, Map.get(state.servers, server_id), state}
  end

  @impl true
  def handle_call({:set_tags, server_id, tool_name, tags}, _from, state) do
    case Map.get(state.servers, server_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      server ->
        tools =
          Enum.map(server.tools, fn
            %{name: ^tool_name} = tool -> %{tool | tags: tags}
            tool -> tool
          end)

        server = %{server | tools: tools}
        {:reply, {:ok, server}, put_and_broadcast(state, server)}
    end
  end

  @impl true
  def handle_call({:remove, server_id}, _from, state) do
    case Map.get(state.servers, server_id) do
      %{transport: :stdio, pid: pid} ->
        DynamicSupervisor.terminate_child(PhoenixElxirBeam.MCP.StdioServerSupervisor, pid)

      _ ->
        :ok
    end

    ServerStore.delete(server_id)
    broadcast_change()
    {:reply, :ok, %{state | servers: Map.delete(state.servers, server_id)}}
  end

  # Persists `server` to Postgres, caches it, and tells dashboards to refresh.
  defp put_and_broadcast(state, server) do
    ServerStore.persist(server)
    broadcast_change()
    put_in(state.servers[server.id], server)
  end

  # -- restore-on-boot ------------------------------------------------

  defp safe_restore(%ServerRegistration{} = reg) do
    restore(reg)
  rescue
    error -> {:error, Exception.message(error)}
  catch
    :exit, reason -> {:error, reason}
  end

  defp restore(%ServerRegistration{transport: "http"} = reg) do
    case discover(reg.base_url, reg) do
      {:ok, session_id, raw_tools} ->
        conn = %{
          transport: :http,
          base_url: reg.base_url,
          session_id: session_id,
          pid: nil,
          timeout_ms: reg.timeout_ms,
          tls_verify: reg.tls_verify
        }

        {:ok, rebuild(reg, conn, raw_tools)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp restore(%ServerRegistration{transport: "stdio"} = reg) do
    with {:ok, pid} <-
           DynamicSupervisor.start_child(
             PhoenixElxirBeam.MCP.StdioServerSupervisor,
             {StdioServer, cmd: reg.command, args: reg.args}
           ),
         {:ok, raw_tools} <- discover_stdio(pid) do
      conn = %{
        transport: :stdio,
        base_url: nil,
        session_id: nil,
        timeout_ms: nil,
        tls_verify: nil,
        pid: pid,
        command: reg.command,
        args: reg.args,
        command_label: reg.command_label
      }

      {:ok, rebuild(reg, conn, raw_tools)}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  # Fresh tools from the live handshake, with the persisted operator/scanner
  # overlay merged back by name and the discovery scanners re-run against the
  # pinned hashes.
  defp rebuild(%ServerRegistration{} = reg, conn, raw_tools) do
    overlay = reg.tool_state || %{}
    previous_hashes = Map.new(overlay, fn {name, ts} -> {name, ts["hash"]} end)

    tools =
      raw_tools
      |> discovered_tools()
      |> Enum.map(fn tool ->
        case Map.get(overlay, tool.name) do
          nil ->
            tool

          ts ->
            %{
              tool
              | tags: restore_tags(ts["tags"]),
                quarantined: ts["quarantined"] || false,
                quarantine_reason: ts["quarantine_reason"]
            }
        end
      end)

    server =
      Map.merge(conn, %{
        id: reg.id,
        name: reg.name,
        tools: tools,
        findings: [],
        last_handshake_at: DateTime.utc_now()
      })

    apply_discovery(server, previous_hashes)
  end

  defp restore_tags(nil), do: []

  defp restore_tags(tags) when is_list(tags), do: Enum.flat_map(tags, &safe_atom/1)

  defp safe_atom(tag) do
    [String.to_existing_atom(tag)]
  rescue
    ArgumentError -> []
  end

  defp broadcast_change do
    Phoenix.PubSub.broadcast(PhoenixElxirBeam.PubSub, @servers_topic, {:servers_changed})
  end

  # Rebuilds a server's tool list from a fresh `tools/list`, carrying operator
  # tags and any standing quarantine across by tool name, then runs the
  # discovery scanners against the previously-pinned hashes.
  defp rehandshaked(server, raw_tools) do
    previous_hashes = Map.new(server.tools, &{&1.name, &1.description_hash})
    old_by_name = Map.new(server.tools, &{&1.name, &1})

    fresh_tools =
      raw_tools
      |> discovered_tools()
      |> Enum.map(fn tool ->
        case Map.get(old_by_name, tool.name) do
          nil ->
            tool

          old ->
            %{
              tool
              | tags: old.tags,
                quarantined: old.quarantined,
                quarantine_reason: old.quarantine_reason
            }
        end
      end)

    %{server | tools: fresh_tools, last_handshake_at: DateTime.utc_now()}
    |> apply_discovery(previous_hashes)
  end

  # Runs the `discovery` scanner set over the server's current tools and
  # applies any `tool_update`s (quarantine, add_tags) + records findings.
  defp apply_discovery(server, previous_hashes) do
    ctx =
      CallContext.new(%{
        phase: :discovery,
        discovery: %{
          server: %{id: server.id, name: server.name, transport: server.transport},
          tools: server.tools,
          previous_hashes: previous_hashes
        }
      })

    {:ok, findings, tool_updates} =
      Pipeline.run_discovery(ctx, PluginRegistry.active_scanners(:discovery))

    tools = Enum.map(server.tools, &apply_tool_update(&1, tool_updates))
    %{server | tools: tools, findings: findings}
  end

  defp apply_tool_update(tool, tool_updates) do
    case Enum.find(tool_updates, &(&1.name == tool.name)) do
      nil ->
        tool

      update ->
        quarantine? = Map.get(update, :quarantine, false)

        %{
          tool
          | tags: Enum.uniq(tool.tags ++ Map.get(update, :add_tags, [])),
            quarantined: tool.quarantined or quarantine?,
            quarantine_reason:
              if(quarantine?,
                do: update[:reason] || tool.quarantine_reason,
                else: tool.quarantine_reason
              )
        }
    end
  end

  # Renders each part of the spawn command relative to the app's working
  # directory (or just its basename outside that tree) so the UI shows
  # a short "bin/mcp-server" instead of the full local filesystem path —
  # the project directory and username don't belong on screen.
  defp command_label(cmd, args) do
    [cmd | args] |> Enum.map(&relative_path_label/1) |> Enum.join(" ")
  end

  defp relative_path_label(part) do
    cwd = File.cwd!()

    if String.starts_with?(part, cwd) do
      Path.relative_to(part, cwd)
    else
      Path.basename(part)
    end
  end

  defp discovered_tools(tools) do
    Enum.map(tools, fn tool ->
      base = %{
        name: tool["name"],
        description: tool["description"],
        input_schema: tool["inputSchema"],
        tags: []
      }

      Map.merge(base, %{
        description_hash: ToolHash.hash(base),
        quarantined: false,
        quarantine_reason: nil,
        # M4.2: name/description heuristics — a hint for the operator, never
        # enforced. `UnclassifiedGuard` still gates on operator `tags`.
        suggested_tags: PhoenixElxirBeam.MCP.TagInference.infer(tool["name"], tool["description"])
      })
    end)
  end

  defp discover_stdio(pid) do
    init_body = %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "initialize",
      "params" => %{
        "protocolVersion" => "2024-11-05",
        "capabilities" => %{},
        "clientInfo" => %{"name" => "mcp-security-proxy-demo", "version" => "0.1.0"}
      }
    }

    list_body = %{"jsonrpc" => "2.0", "id" => 2, "method" => "tools/list", "params" => %{}}

    with {:ok, %{"result" => _}} <- StdioServer.request(pid, init_body),
         {:ok, %{"result" => %{"tools" => tools}}} <- StdioServer.request(pid, list_body) do
      {:ok, tools}
    else
      {:ok, %{"error" => error}} ->
        {:error, Map.get(error, "message", "server returned an error")}

      {:error, reason} ->
        {:error, reason}

      _ ->
        {:error, "unexpected response while discovering tools"}
    end
  end

  defp discover(base_url, opts) do
    init_body = %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "initialize",
      "params" => %{
        "protocolVersion" => "2024-11-05",
        "capabilities" => %{},
        "clientInfo" => %{"name" => "mcp-security-proxy-demo", "version" => "0.1.0"}
      }
    }

    with {:ok, _init_result, init_resp} <- post_rpc(base_url, init_body, [], opts),
         session_id = session_id_from(init_resp),
         list_body = %{"jsonrpc" => "2.0", "id" => 2, "method" => "tools/list", "params" => %{}},
         {:ok, %{"tools" => tools}, _resp} <-
           post_rpc(base_url, list_body, session_headers(session_id), opts) do
      {:ok, session_id, tools}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "unexpected response while discovering tools"}
    end
  end

  defp post_rpc(base_url, body, headers, opts) do
    {url, transport_headers} = HttpTransport.prepare(base_url)
    headers = transport_headers ++ headers

    case Req.post(url,
           json: body,
           headers: headers,
           receive_timeout: HttpTransport.receive_timeout(opts),
           connect_options: HttpTransport.connect_options(opts)
         ) do
      {:ok, %Req.Response{status: status} = resp} when status in 200..299 ->
        decode_rpc_response(resp)

      {:ok, %Req.Response{status: status}} ->
        {:error, "server responded with HTTP #{status}"}

      {:error, reason} ->
        {:error, "connection failed: #{Exception.format(:error, reason)}"}
    end
  end

  # A 2xx response may carry its JSON-RPC message as `application/json` or a
  # single `text/event-stream` frame — see `HttpTransport.decode_body/1`.
  defp decode_rpc_response(resp) do
    case HttpTransport.decode_body(resp) do
      {:ok, %{"result" => result}} ->
        {:ok, result, resp}

      {:ok, %{"error" => error}} ->
        {:error, Map.get(error, "message", "server returned an error")}

      {:ok, _decoded} ->
        {:error, "unexpected response while discovering tools"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp session_id_from(%Req.Response{} = resp) do
    case Req.Response.get_header(resp, "mcp-session-id") do
      [id | _] -> id
      _ -> nil
    end
  end

  defp session_headers(nil), do: []
  defp session_headers(session_id), do: [{"mcp-session-id", session_id}]

  defp generate_id do
    "real-" <> (:crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower))
  end
end
