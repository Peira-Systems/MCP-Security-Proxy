defmodule PhoenixElxirBeamWeb.MCPDashboardLive do
  @moduledoc """
  Live dashboard visualizing MCP tool calls flowing through the policy
  proxy: a small tool graph that lights up as calls are made and turns red
  when a dangerous tool-chain is detected and blocked, a console-style
  event log (live session feed, or the durable history browser), and
  real-server registration/testing.
  """

  use PhoenixElxirBeamWeb, :live_view

  alias PhoenixElxirBeam.MCP.{Demo, EventLog, ServerRegistry, ToolCatalog}

  @topic "mcp:events"
  @history_page_size 20

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @topic)
    end

    graph =
      for server_id <- ToolCatalog.servers(),
          do: %{id: server_id, tools: ToolCatalog.tools(server_id)}

    socket =
      socket
      |> assign(:page_title, "MCP Dashboard")
      |> assign(:graph, graph)
      |> assign(:positions, layout_positions(graph))
      |> assign(:running, false)
      |> assign(:scenario, nil)
      |> assign(:real_servers, ServerRegistry.list_servers())
      |> assign(:registering, false)
      |> assign(:manual_session_id, generate_manual_session_id())
      |> assign(:expanded_server_ids, MapSet.new())
      |> assign(:console_mode, "live")
      |> assign(:history_status, "all")
      |> assign(:history_server_id, "all")
      |> assign(:history_from, "")
      |> assign(:history_to, "")
      |> assign(:history_page, 1)
      |> assign(:history_sort_by, "time")
      |> assign(:history_sort_dir, "desc")
      |> assign(:server_options, EventLog.distinct_server_ids())
      |> stream(:events, [])

    {:ok, refresh_history(socket)}
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

  def handle_event("set_console_mode", %{"mode" => mode}, socket)
      when mode in ["live", "history"] do
    socket = assign(socket, :console_mode, mode)
    {:noreply, if(mode == "history", do: refresh_history(socket), else: socket)}
  end

  def handle_event("history_filter", params, socket) do
    socket =
      socket
      |> assign(:history_server_id, params["server_id"] || "all")
      |> assign(:history_from, params["from"] || "")
      |> assign(:history_to, params["to"] || "")
      |> assign(:history_page, 1)

    {:noreply, refresh_history(socket)}
  end

  def handle_event("history_set_status", %{"status" => status}, socket) do
    {:noreply,
     socket |> assign(:history_status, status) |> assign(:history_page, 1) |> refresh_history()}
  end

  def handle_event("history_sort", %{"by" => by}, socket) do
    {sort_by, sort_dir} =
      if socket.assigns.history_sort_by == by do
        {by, if(socket.assigns.history_sort_dir == "asc", do: "desc", else: "asc")}
      else
        {by, "asc"}
      end

    {:noreply,
     socket
     |> assign(:history_sort_by, sort_by)
     |> assign(:history_sort_dir, sort_dir)
     |> assign(:history_page, 1)
     |> refresh_history()}
  end

  def handle_event("history_remove_filter", %{"key" => "status"}, socket) do
    {:noreply,
     socket |> assign(:history_status, "all") |> assign(:history_page, 1) |> refresh_history()}
  end

  def handle_event("history_remove_filter", %{"key" => "server"}, socket) do
    {:noreply,
     socket |> assign(:history_server_id, "all") |> assign(:history_page, 1) |> refresh_history()}
  end

  def handle_event("history_remove_filter", %{"key" => "from"}, socket) do
    {:noreply,
     socket |> assign(:history_from, "") |> assign(:history_page, 1) |> refresh_history()}
  end

  def handle_event("history_remove_filter", %{"key" => "to"}, socket) do
    {:noreply, socket |> assign(:history_to, "") |> assign(:history_page, 1) |> refresh_history()}
  end

  def handle_event("history_clear_filters", _params, socket) do
    socket =
      socket
      |> assign(:history_status, "all")
      |> assign(:history_server_id, "all")
      |> assign(:history_from, "")
      |> assign(:history_to, "")
      |> assign(:history_page, 1)

    {:noreply, refresh_history(socket)}
  end

  def handle_event("history_paginate", %{"page" => page}, socket) do
    page =
      case Integer.parse(page) do
        {n, _} when n > 0 -> n
        _ -> 1
      end

    {:noreply, refresh_history(assign(socket, :history_page, page))}
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

    {:noreply,
     socket
     |> assign(:real_servers, ServerRegistry.list_servers())
     |> assign(:expanded_server_ids, MapSet.delete(socket.assigns.expanded_server_ids, server_id))}
  end

  def handle_event("toggle_server_drawer", %{"server_id" => server_id}, socket) do
    expanded_server_ids =
      if MapSet.member?(socket.assigns.expanded_server_ids, server_id) do
        MapSet.delete(socket.assigns.expanded_server_ids, server_id)
      else
        MapSet.put(socket.assigns.expanded_server_ids, server_id)
      end

    {:noreply, assign(socket, :expanded_server_ids, expanded_server_ids)}
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
     |> assign(:expanded_server_ids, MapSet.put(socket.assigns.expanded_server_ids, server.id))
     |> put_flash(:info, "Registered #{server.name} — #{length(server.tools)} tool(s) discovered")}
  end

  def handle_info({:server_registered, {:error, reason}}, socket) do
    {:noreply,
     socket
     |> assign(:registering, false)
     |> put_flash(:error, "Couldn't register server: #{reason}")}
  end

  defp refresh_history(socket) do
    filters = %{
      status: socket.assigns.history_status,
      server_id: socket.assigns.history_server_id,
      from: parse_date(socket.assigns.history_from, :beginning),
      to: parse_date(socket.assigns.history_to, :end),
      page: socket.assigns.history_page,
      page_size: @history_page_size,
      sort_by: socket.assigns.history_sort_by,
      sort_dir: socket.assigns.history_sort_dir
    }

    socket
    |> assign(:history_result, EventLog.list(filters))
    |> assign(:server_options, EventLog.distinct_server_ids())
  end

  defp parse_date("", _edge), do: nil

  defp parse_date(date_string, edge) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        time = if edge == :beginning, do: ~T[00:00:00.000000], else: ~T[23:59:59.999999]
        DateTime.new!(date, time, "Etc/UTC")

      {:error, _reason} ->
        nil
    end
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
  #
  # Each preset can be overridden with an env var holding the full command line
  # (`MCP_FILESYSTEM_CMD` / `MCP_FETCH_CMD`), which is how a containerized
  # deployment points at servers baked into its own image. Without an override
  # we fall back to the local-dev layout (a project-root `.venv` / a
  # `priv/mcp_servers` npm install), probing both the POSIX (`bin/`) and
  # Windows (`Scripts/`) venv layouts.
  defp stdio_preset("filesystem") do
    sandbox = sandbox_dir()

    case env_cmd("MCP_FILESYSTEM_CMD") do
      {:ok, cmd, args} ->
        {:ok, "real-filesystem (stdio)", cmd, args ++ [sandbox]}

      :none ->
        node = System.find_executable("node")

        entry =
          Path.expand(
            "priv/mcp_servers/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
            File.cwd!()
          )

        cond do
          is_nil(node) ->
            {:error, preset_unavailable("filesystem", "node not found on PATH")}

          not File.exists?(entry) ->
            {:error,
             preset_unavailable(
               "filesystem",
               "#{entry} not found — run: npm install --prefix priv/mcp_servers @modelcontextprotocol/server-filesystem"
             )}

          true ->
            {:ok, "real-filesystem (stdio)", node, [entry, sandbox]}
        end
    end
  end

  defp stdio_preset("fetch") do
    case env_cmd("MCP_FETCH_CMD") do
      {:ok, cmd, args} ->
        {:ok, "real-fetch (stdio)", cmd, args}

      :none ->
        case venv_python() do
          {:ok, python} ->
            {:ok, "real-fetch (stdio)", python, ["-m", "mcp_server_fetch"]}

          :none ->
            {:error,
             preset_unavailable(
               "fetch",
               "no .venv found — run: python -m venv .venv && .venv/bin/python -m pip install mcp-server-fetch " <>
                 "(.venv\\Scripts\\python on Windows)"
             )}
        end
    end
  end

  # Splits an env-var command line on whitespace: `"python -m mcp_server_fetch"`
  # -> `{:ok, "/usr/bin/python", ["-m", "mcp_server_fetch"]}`. Good enough for
  # the fixed commands we expect here — no shell quoting is supported. The
  # executable is resolved to an absolute path because `StdioServer` spawns it
  # via `:spawn_executable`, which does not search `PATH`.
  defp env_cmd(var) do
    case System.get_env(var) do
      value when is_binary(value) and value != "" ->
        case String.split(value, ~r/\s+/, trim: true) do
          [cmd | args] -> {:ok, resolve_executable(cmd), args}
          [] -> :none
        end

      _ ->
        :none
    end
  end

  defp resolve_executable(cmd) do
    expanded = Path.expand(cmd, File.cwd!())

    cond do
      Path.type(cmd) == :absolute -> cmd
      File.regular?(expanded) -> expanded
      true -> System.find_executable(cmd) || cmd
    end
  end

  # The filesystem server's one allowed directory. In a release `priv` is under
  # the versioned app dir (not the cwd), so resolve it through `app_dir/2` and
  # only fall back to a cwd-relative path for `mix phx.server` dev.
  defp sandbox_dir do
    release_path = Application.app_dir(:phoenix_elxir_beam, "priv/mcp_sandbox")

    if File.dir?(release_path) do
      release_path
    else
      Path.expand("priv/mcp_sandbox", File.cwd!())
    end
  end

  defp venv_python do
    candidates =
      [".venv/bin/python", ".venv/bin/python3", ".venv/Scripts/python.exe"]
      |> Enum.map(&Path.expand(&1, File.cwd!()))

    case Enum.find(candidates, &File.exists?/1) do
      nil -> :none
      python -> {:ok, python}
    end
  end

  # In a packaged release (e.g. the Docker image) the local-dev toolchains
  # aren't present; tell the operator to set the override rather than showing a
  # path that only makes sense on a dev machine.
  defp preset_unavailable(preset, detail) do
    if System.get_env("RELEASE_NAME") do
      "the '#{preset}' demo server isn't available in this deployment — " <>
        "set MCP_#{String.upcase(preset)}_CMD to a command that launches it (#{detail})"
    else
      detail
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

  defp format_datetime(%DateTime{} = ts) do
    Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  end

  defp status_label(:session_start), do: "started"
  defp status_label(:ok), do: "allowed"
  defp status_label(:blocked), do: "blocked"
  defp status_label(:session_complete), do: "complete"
  defp status_label("ok"), do: "allowed"
  defp status_label("blocked"), do: "blocked"
  defp status_label("session_start"), do: "started"
  defp status_label("session_complete"), do: "complete"
  defp status_label(other), do: other

  defp console_status_class(status) when status in [:ok, "ok"], do: "text-success"
  defp console_status_class(status) when status in [:blocked, "blocked"], do: "text-error"

  defp console_status_class(status) when status in [:session_start, "session_start"],
    do: "text-info"

  defp console_status_class(_), do: "text-base-content/50"

  defp sort_caret_class(sort_by, column) when sort_by == column, do: "text-primary"
  defp sort_caret_class(_sort_by, _column), do: "text-neutral-content/30"

  defp sort_caret_symbol(sort_by, sort_dir, column) when sort_by == column do
    if sort_dir == "asc", do: "▲", else: "▼"
  end

  defp sort_caret_symbol(_sort_by, _sort_dir, _column), do: "▾"

  defp tag_pill_class("sensitive_read"), do: "bg-warning/20 text-warning"
  defp tag_pill_class("network_egress"), do: "bg-error/20 text-error"
  defp tag_pill_class(_), do: "bg-base-300 text-base-content/50"

  defp tag_label("sensitive_read"), do: "sensitive"
  defp tag_label("network_egress"), do: "egress"
  defp tag_label(other), do: other
end
