defmodule PhoenixElxirBeamWeb.MCPDashboardLive do
  @moduledoc """
  Live dashboard visualizing MCP tool calls flowing through the policy
  proxy: a small tool graph that lights up as calls are made and turns red
  when a dangerous tool-chain is detected and blocked, plus a scrolling
  event feed.
  """

  use PhoenixElxirBeamWeb, :live_view

  alias PhoenixElxirBeam.MCP.{Demo, ServerRegistry, ToolCatalog}

  @topic "mcp:events"

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @topic)
    end

    graph =
      for server_id <- ToolCatalog.servers(),
          do: %{id: server_id, tools: ToolCatalog.tools(server_id)}

    {:ok,
     socket
     |> assign(:page_title, "MCP Dashboard")
     |> assign(:graph, graph)
     |> assign(:positions, layout_positions(graph))
     |> assign(:running, false)
     |> assign(:scenario, nil)
     |> assign(:real_servers, ServerRegistry.list_servers())
     |> assign(:registering, false)
     |> assign(:manual_session_id, generate_manual_session_id())
     |> stream(:events, [])}
  end

  # Fixed four-tier layout — agent, policy gate, server, tool — left to
  # right. Positions are final, not a seed for client-side relaxation: the
  # graph no longer jitters into place, it's laid out once here.
  defp layout_positions(graph) do
    server_count = length(graph)
    server_spacing = 170
    first_server_y = 240 - server_spacing * (server_count - 1) / 2

    graph
    |> Enum.with_index()
    |> Enum.reduce(%{"agent" => {70, 240}, "gate" => {240, 240}}, fn
      {%{id: server_id, tools: tools}, i}, acc ->
        server_y = first_server_y + i * server_spacing
        acc = Map.put(acc, "server-" <> server_id, {450, server_y})

        tool_spacing = 70
        first_tool_y = server_y - tool_spacing * (length(tools) - 1) / 2

        tools
        |> Enum.with_index()
        |> Enum.reduce(acc, fn {tool, j}, acc2 ->
          Map.put(acc2, "tool-" <> tool.name, {700, first_tool_y + j * tool_spacing})
        end)
    end)
  end

  @impl true
  def handle_event("run_benign", _params, socket) do
    {:ok, _pid} = Demo.run_benign_session()
    {:noreply, assign(socket, running: true)}
  end

  def handle_event("run_attack", _params, socket) do
    {:ok, _pid} = Demo.run_attack_simulation()
    {:noreply, assign(socket, running: true)}
  end

  def handle_event("register_server", %{"name" => name, "base_url" => base_url}, socket) do
    name = String.trim(name)
    base_url = String.trim(base_url)

    if name == "" or base_url == "" do
      {:noreply, put_flash(socket, :error, "Name and base URL are both required")}
    else
      liveview = self()

      Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
        send(liveview, {:server_registered, ServerRegistry.register_server(name, base_url)})
      end)

      {:noreply, socket |> assign(:registering, true) |> clear_flash()}
    end
  end

  def handle_event("register_stdio_preset", %{"preset" => preset}, socket) do
    liveview = self()

    case stdio_preset(preset) do
      {:ok, name, cmd, args} ->
        Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
          send(
            liveview,
            {:server_registered, ServerRegistry.register_stdio_server(name, cmd, args)}
          )
        end)

        {:noreply, socket |> assign(:registering, true) |> clear_flash()}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, reason)}
    end
  end

  def handle_event("remove_server", %{"server_id" => server_id}, socket) do
    :ok = ServerRegistry.remove_server(server_id)
    {:noreply, assign(socket, :real_servers, ServerRegistry.list_servers())}
  end

  def handle_event(
        "toggle_tool_tag",
        %{"server_id" => server_id, "tool_name" => tool_name, "tag" => tag_str},
        socket
      ) do
    tag = tag_atom(tag_str)
    server = ServerRegistry.get_server(server_id)
    tool = Enum.find(server.tools, &(&1.name == tool_name))
    new_tags = if tag in tool.tags, do: List.delete(tool.tags, tag), else: [tag | tool.tags]

    {:ok, _server} = ServerRegistry.set_tool_tags(server_id, tool_name, new_tags)
    {:noreply, assign(socket, :real_servers, ServerRegistry.list_servers())}
  end

  def handle_event(
        "call_tool",
        %{"server_id" => server_id, "tool_name" => tool_name, "arguments" => arguments_json},
        socket
      ) do
    arguments =
      case Jason.decode(arguments_json) do
        {:ok, decoded} when is_map(decoded) -> decoded
        _ -> %{}
      end

    session_id = socket.assigns.manual_session_id

    Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
      call_real_tool(server_id, tool_name, arguments, session_id)
    end)

    {:noreply, socket}
  end

  def handle_event("new_manual_session", _params, socket) do
    {:noreply, assign(socket, :manual_session_id, generate_manual_session_id())}
  end

  def handle_event("clear_feed", _params, socket) do
    # The manual "Call tool" flow never emits a `:session_start` event (see
    # `apply_event/2` below), so it never gets the clean-slate reset a demo
    # run gets for free — this button is that reset, made explicit instead
    # of implicit.
    {:noreply,
     socket
     |> stream(:events, [], reset: true)
     |> push_event("mcp_graph_reset", %{})}
  end

  @impl true
  def handle_info({:mcp_event, event}, socket) do
    {:noreply, apply_event(socket, event)}
  end

  def handle_info({:server_registered, {:ok, server}}, socket) do
    {:noreply,
     socket
     |> assign(:registering, false)
     |> assign(:real_servers, ServerRegistry.list_servers())
     |> put_flash(:info, "Registered #{server.name} — #{length(server.tools)} tool(s) discovered")}
  end

  def handle_info({:server_registered, {:error, reason}}, socket) do
    {:noreply,
     socket
     |> assign(:registering, false)
     |> put_flash(:error, "Couldn't register server: #{reason}")}
  end

  defp call_real_tool(server_id, tool_name, arguments, session_id) do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]

    body = %{
      "jsonrpc" => "2.0",
      "id" => System.unique_integer([:positive]),
      "method" => "tools/call",
      "params" => %{"name" => tool_name, "arguments" => arguments}
    }

    Req.post("http://127.0.0.1:#{port}/mcp/proxy/#{server_id}",
      json: body,
      headers: [{"mcp-session-id", session_id}]
    )
  end

  defp tag_atom("sensitive_read"), do: :sensitive_read
  defp tag_atom("network_egress"), do: :network_egress

  # Fixed commands, not user-supplied — the dashboard form only ever passes a
  # preset key, never a raw command string, so there's no arbitrary-command
  # injection surface here.
  defp stdio_preset("filesystem") do
    node = System.find_executable("node")

    entry =
      Path.expand(
        "priv/mcp_servers/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
        File.cwd!()
      )

    cond do
      is_nil(node) ->
        {:error, "node not found on PATH — install Node.js to run the real filesystem server"}

      not File.exists?(entry) ->
        {:error,
         "#{entry} not found — run: npm install --prefix priv/mcp_servers @modelcontextprotocol/server-filesystem"}

      true ->
        sandbox = Path.expand("priv/mcp_sandbox", File.cwd!())
        {:ok, "real-filesystem (stdio)", node, [entry, sandbox]}
    end
  end

  defp stdio_preset("fetch") do
    python = Path.expand(".venv/Scripts/python.exe", File.cwd!())

    if File.exists?(python) do
      {:ok, "real-fetch (stdio)", python, ["-m", "mcp_server_fetch"]}
    else
      {:error,
       "#{python} not found — run: python -m venv .venv && .venv/Scripts/python -m pip install mcp-server-fetch"}
    end
  end

  defp generate_manual_session_id do
    "manual-" <> (:crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower))
  end

  defp apply_event(socket, %{status: :session_start} = event) do
    socket
    |> assign(scenario: event.scenario, running: true)
    |> stream(:events, [event], reset: true)
    |> push_event("mcp_graph_reset", %{})
  end

  defp apply_event(socket, %{status: status} = event) when status in [:ok, :blocked] do
    socket = stream_insert(socket, :events, event, at: 0)

    if event.server_id in ToolCatalog.servers() do
      push_event(socket, "mcp_graph_event", %{
        server_id: event.server_id,
        tool_name: event.tool_name,
        status: to_string(event.status),
        reason: event.reason
      })
    else
      socket
    end
  end

  defp apply_event(socket, %{status: :session_complete} = event) do
    socket
    |> stream_insert(:events, event, at: 0)
    |> assign(:running, false)
  end

  defp format_time(%DateTime{} = ts) do
    Calendar.strftime(ts, "%H:%M:%S")
  end

  defp status_label(:session_start), do: "session started"
  defp status_label(:ok), do: "allowed"
  defp status_label(:blocked), do: "blocked"
  defp status_label(:session_complete), do: "session complete"

  defp status_badge_class(:ok), do: "bg-success/15 text-success"
  defp status_badge_class(:blocked), do: "bg-error/15 text-error"
  defp status_badge_class(_), do: "bg-base-300 text-base-content/70"
end
