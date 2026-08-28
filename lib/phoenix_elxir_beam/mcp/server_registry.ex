defmodule PhoenixElxirBeam.MCP.ServerRegistry do
  @moduledoc """
  In-memory registry of real MCP servers registered at runtime from the
  dashboard, over either of two real transports:

    * `:http` — Streamable HTTP against a base URL.
    * `:stdio` — a real MCP server process spawned locally, spoken to
      directly over its stdin/stdout via `PhoenixElxirBeam.MCP.StdioServer`.

  Either way, registering a server performs a real `initialize` +
  `tools/list` handshake, capturing whatever `tools` it reports (and, for
  `:http`, the upstream `mcp-session-id`, if any, so later `tools/call`
  forwards can reuse the same MCP session). Discovered tools start untagged
  — `ProxyController` only enforces the tool-chaining policy on tags a human
  has explicitly assigned via `set_tool_tags/3`.
  """

  use GenServer

  alias PhoenixElxirBeam.MCP.{HttpTransport, StdioServer}

  # Client API

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  @doc "Registers a real HTTP server, discovering its tools via a live handshake."
  def register_server(name, base_url, registry \\ __MODULE__) do
    GenServer.call(registry, {:register, name, base_url}, 15_000)
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

  def remove_server(server_id, registry \\ __MODULE__) do
    GenServer.call(registry, {:remove, server_id})
  end

  # Server callbacks

  @impl true
  def init(_), do: {:ok, %{servers: %{}}}

  @impl true
  def handle_call({:register, name, base_url}, _from, state) do
    case discover(base_url) do
      {:ok, session_id, tools} ->
        server = %{
          id: generate_id(),
          name: name,
          transport: :http,
          base_url: base_url,
          session_id: session_id,
          pid: nil,
          tools: discovered_tools(tools)
        }

        {:reply, {:ok, server}, put_in(state.servers[server.id], server)}

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
            server = %{
              id: generate_id(),
              name: name,
              transport: :stdio,
              base_url: nil,
              session_id: nil,
              pid: pid,
              command_label: command_label(cmd, args),
              tools: discovered_tools(tools)
            }

            {:reply, {:ok, server}, put_in(state.servers[server.id], server)}

          {:error, reason} ->
            DynamicSupervisor.terminate_child(PhoenixElxirBeam.MCP.StdioServerSupervisor, pid)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, "failed to start server process: #{inspect(reason)}"}, state}
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
        {:reply, {:ok, server}, put_in(state.servers[server_id], server)}
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

    {:reply, :ok, %{state | servers: Map.delete(state.servers, server_id)}}
  end

  # Renders each part of the spawn command relative to the app's working
  # directory (or just its basename outside that tree) so the UI shows
  # "priv/mcp_servers/.../index.js" instead of the full local filesystem
  # path — the project directory and username don't belong on screen.
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
      %{
        name: tool["name"],
        description: tool["description"],
        input_schema: tool["inputSchema"],
        tags: []
      }
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

  defp discover(base_url) do
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

    with {:ok, _init_result, init_resp} <- post_rpc(base_url, init_body, []),
         session_id = session_id_from(init_resp),
         list_body = %{"jsonrpc" => "2.0", "id" => 2, "method" => "tools/list", "params" => %{}},
         {:ok, %{"tools" => tools}, _resp} <-
           post_rpc(base_url, list_body, session_headers(session_id)) do
      {:ok, session_id, tools}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "unexpected response while discovering tools"}
    end
  end

  defp post_rpc(base_url, body, headers) do
    {url, transport_headers} = HttpTransport.prepare(base_url)
    headers = transport_headers ++ headers

    case Req.post(url, json: body, headers: headers, receive_timeout: 10_000) do
      {:ok, %Req.Response{status: status, body: %{"result" => result}} = resp}
      when status in 200..299 ->
        {:ok, result, resp}

      {:ok, %Req.Response{status: status, body: %{"error" => error}}} when status in 200..299 ->
        {:error, Map.get(error, "message", "server returned an error")}

      {:ok, %Req.Response{status: status}} ->
        {:error, "server responded with HTTP #{status}"}

      {:error, reason} ->
        {:error, "connection failed: #{Exception.format(:error, reason)}"}
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
