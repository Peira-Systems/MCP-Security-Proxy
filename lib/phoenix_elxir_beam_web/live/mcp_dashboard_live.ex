defmodule PhoenixElxirBeamWeb.MCPDashboardLive do
  @moduledoc """
  Live dashboard for the policy proxy: a tool graph that lights up as real
  `tools/call`s flow through and turns red when a call is blocked, a
  console-style event log (live feed or the durable history browser), the
  plugin pipeline, and real-server registration / tag curation.
  """

  use PhoenixElxirBeamWeb, :live_view

  alias PhoenixElxirBeam.MCP.{
    ApiKey,
    AuditIntegrity,
    EventLog,
    HoldRegistry,
    ServerRegistry,
    SessionStore
  }

  alias PhoenixElxirBeam.MCP.Plugin.{Registry, SidecarRunner}

  @topic "mcp:events"
  @servers_topic "mcp:servers"
  @holds_topic "mcp:holds"
  @audit_topic "mcp:audit"
  @alerts_topic "mcp:alerts"
  @history_page_size 20

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @servers_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @holds_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @audit_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @alerts_topic)
      # Sidecar plugin health drifts and MCP sessions come and go with no
      # broadcast; a light poll keeps the Plugins panel + session count current.
      :timer.send_interval(5_000, :refresh_plugins)
    end

    graph = build_graph()

    socket =
      socket
      |> assign(:page_title, "MCP Dashboard")
      |> assign(:graph, graph)
      |> assign(:positions, layout_positions(graph))
      |> assign(:real_servers, ServerRegistry.list_servers())
      |> assign(:registering, false)
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
      |> assign(:plugins, plugin_rows())
      |> assign(:session_count, safe_session_count())
      |> assign(:integrity, safe_integrity())
      |> assign(:alerts, safe_alerts())
      |> assign(:api_keys, safe_api_keys())
      |> assign(:new_token, nil)
      |> assign(:pending_holds, safe_pending_holds())
      |> stream(:events, [])

    {:ok, refresh_history(socket)}
  end

  # The graph's server + tool nodes come from the live ServerRegistry —
  # `%{id, name, tools}` per registered server.
  defp build_graph do
    for server <- ServerRegistry.list_servers() do
      %{id: server.id, name: server.name, tools: server.tools}
    end
  end

  defp graph_server_ids(graph), do: Enum.map(graph, & &1.id)

  # Fixed four-tier layout — agent, policy gate, server, tool — left to
  # right. Positions are final, not a seed for client-side relaxation.
  defp layout_positions(graph) do
    server_count = max(length(graph), 1)
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

  def handle_event("verify_audit_chain", _params, socket) do
    {level, msg, integrity} =
      case AuditIntegrity.check_now() do
        :ok ->
          {:info, "Audit chain intact — #{socket.assigns.history_result.total_count} event(s)",
           :ok}

        {:broken, detail} ->
          {:error, "Audit chain BROKEN: #{detail}", {:broken, detail}}
      end

    {:noreply, socket |> assign(:integrity, integrity) |> put_flash(level, msg)}
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

  def handle_event("rehandshake", %{"server_id" => server_id}, socket) do
    {:noreply, start_rehandshake(socket, server_id)}
  end

  def handle_event(
        "clear_tool_block",
        %{"server_id" => server_id, "tool_name" => tool_name},
        socket
      ) do
    {:ok, _server} = ServerRegistry.clear_tool_block(server_id, tool_name)
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

    Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
      call_real_tool(server_id, tool_name, arguments)
    end)

    {:noreply, socket}
  end

  def handle_event("clear_feed", _params, socket) do
    {:noreply,
     socket
     |> stream(:events, [], reset: true)
     |> push_event("mcp_graph_reset", %{})}
  end

  def handle_event("resolve_hold", %{"hold_id" => hold_id, "decision" => decision}, socket)
      when decision in ["approve", "deny"] do
    HoldRegistry.resolve(hold_id, String.to_existing_atom(decision))
    {:noreply, update(socket, :pending_holds, &Enum.reject(&1, fn h -> h.id == hold_id end))}
  end

  def handle_event("issue_key", params, socket) do
    principal = String.trim(params["principal"] || "")
    agent_id = String.trim(params["agent_id"] || "")
    all_servers = params["all_servers"] == "true"
    server_ids = params |> Map.get("servers", %{}) |> Map.keys()

    cond do
      principal == "" or agent_id == "" ->
        {:noreply, put_flash(socket, :error, "Principal and agent id are required")}

      not all_servers and server_ids == [] ->
        {:noreply, put_flash(socket, :error, "Grant at least one server, or check 'all servers'")}

      true ->
        case ApiKey.issue(%{
               principal: principal,
               agent_id: agent_id,
               all_servers: all_servers,
               granted_server_ids: server_ids
             }) do
          {:ok, _key, token} ->
            {:noreply,
             socket
             |> assign(:api_keys, safe_api_keys())
             |> assign(:new_token, token)
             |> put_flash(:info, "Key issued — copy the token now, it won't be shown again")}

          {:error, _cs} ->
            {:noreply, put_flash(socket, :error, "Couldn't issue key")}
        end
    end
  end

  def handle_event("dismiss_token", _params, socket) do
    {:noreply, assign(socket, :new_token, nil)}
  end

  def handle_event("revoke_key", %{"key_id" => key_id}, socket) do
    ApiKey.revoke(key_id)
    {:noreply, assign(socket, :api_keys, safe_api_keys())}
  end

  @impl true
  def handle_info({:mcp_event, event}, socket) do
    {:noreply, apply_event(socket, event)}
  end

  # Any ServerRegistry mutation (from this or another dashboard) — refetch
  # the server list and rebuild the graph.
  def handle_info({:servers_changed}, socket) do
    graph = build_graph()

    {:noreply,
     socket
     |> assign(:graph, graph)
     |> assign(:positions, layout_positions(graph))
     |> assign(:real_servers, ServerRegistry.list_servers())
     |> assign(:server_options, EventLog.distinct_server_ids())}
  end

  def handle_info({:audit_integrity, :broken, detail}, socket) do
    {:noreply, assign(socket, :integrity, {:broken, detail})}
  end

  def handle_info({:alert, alert}, socket) do
    {:noreply, assign(socket, :alerts, Enum.take([alert | socket.assigns.alerts], 20))}
  end

  def handle_info(:refresh_plugins, socket) do
    {:noreply,
     socket
     |> assign(:plugins, plugin_rows())
     |> assign(:session_count, safe_session_count())
     |> assign(:api_keys, safe_api_keys())}
  end

  def handle_info({:hold_pending, hold}, socket) do
    socket =
      update(socket, :pending_holds, &[hold | Enum.reject(&1, fn h -> h.id == hold.id end)])

    socket =
      if hold.server_id in graph_server_ids(socket.assigns.graph) do
        push_event(socket, "mcp_graph_event", %{
          server_id: hold.server_id,
          tool_name: hold.tool_name,
          status: "held",
          reason: hold.prompt
        })
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_info({:hold_resolved, hold_id, _outcome}, socket) do
    {:noreply, update(socket, :pending_holds, &Enum.reject(&1, fn h -> h.id == hold_id end))}
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

  def handle_info({:rehandshake_done, {:ok, server}}, socket) do
    drift = Enum.count(server.findings, &(&1.type == "rug_pull"))

    flash =
      if drift > 0 do
        {:error, "Re-handshake: #{drift} tool(s) changed since registration — quarantined"}
      else
        {:info, "Re-handshake of #{server.name}: no drift"}
      end

    {:noreply,
     socket
     |> assign(:registering, false)
     |> assign(:real_servers, ServerRegistry.list_servers())
     |> assign(:expanded_server_ids, MapSet.put(socket.assigns.expanded_server_ids, server.id))
     |> put_flash(elem(flash, 0), elem(flash, 1))}
  end

  def handle_info({:rehandshake_done, {:error, reason}}, socket) do
    {:noreply,
     socket
     |> assign(:registering, false)
     |> put_flash(:error, "Re-handshake failed: #{inspect(reason)}")}
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

  defp start_rehandshake(socket, server_id) do
    liveview = self()

    Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
      send(liveview, {:rehandshake_done, ServerRegistry.rehandshake(server_id)})
    end)

    socket |> assign(:registering, true) |> clear_flash()
  end

  defp safe_pending_holds do
    HoldRegistry.pending()
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp safe_session_count do
    length(SessionStore.list())
  rescue
    _ -> 0
  catch
    :exit, _ -> 0
  end

  defp safe_api_keys do
    ApiKey.list()
  rescue
    _ -> []
  end

  # `:ok` | `{:broken, detail}` | `:unknown`
  defp safe_integrity do
    case AuditIntegrity.status() do
      %{last_check: %{result: :ok}} -> :ok
      %{last_check: %{result: {:broken, detail}}} -> {:broken, detail}
      _ -> :unknown
    end
  rescue
    _ -> :unknown
  catch
    :exit, _ -> :unknown
  end

  defp safe_alerts do
    PhoenixElxirBeam.MCP.Alerts.recent()
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp held_ago(%DateTime{} = ts) do
    case DateTime.diff(DateTime.utc_now(), ts) do
      s when s < 1 -> "just now"
      1 -> "1s ago"
      s -> "#{s}s ago"
    end
  end

  # Rows for the read-only Plugins panel: name, kind, source, enabled, and
  # (sidecar only) live health from the SidecarRunner.
  defp plugin_rows do
    Registry.list()
    |> Enum.map(fn entry ->
      {source, health} =
        case entry.impl do
          {:sidecar, runner} -> {"sidecar", SidecarRunner.health(runner)}
          _ -> {"in-process", nil}
        end

      %{
        name: entry.name,
        version: entry.version,
        kind: to_string(entry.kind),
        source: source,
        enabled: entry.enabled,
        health: health,
        note: plugin_note(entry)
      }
    end)
  rescue
    _ -> []
  end

  defp plugin_note(%{name: "rule-engine", config: %{"rules" => rules}}) when is_list(rules) do
    "#{length(rules)} rule#{if length(rules) == 1, do: "", else: "s"}"
  end

  defp plugin_note(_entry), do: nil

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

  # Runs a full one-shot MCP session against the proxy — handshake, the tool
  # call, teardown — exactly as an external client would, authenticating with
  # the internal dashboard key. The proxy mints the session id; we read it
  # back off the initialize response.
  defp call_real_tool(server_id, tool_name, arguments) do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]
    base = "http://127.0.0.1:#{port}/mcp/proxy/#{server_id}"
    auth = [{"authorization", "Bearer #{ApiKey.dashboard_token()}"}]

    init =
      Req.post(base,
        headers: auth,
        json: %{
          "jsonrpc" => "2.0",
          "id" => 1,
          "method" => "initialize",
          "params" => %{
            "protocolVersion" => "2025-06-18",
            "clientInfo" => %{"name" => "dashboard", "version" => "1"}
          }
        }
      )

    with {:ok, resp} <- init,
         [session_id | _] <- Req.Response.get_header(resp, "mcp-session-id") do
      headers = [{"mcp-session-id", session_id} | auth]

      Req.post(base,
        json: %{"jsonrpc" => "2.0", "method" => "notifications/initialized"},
        headers: headers
      )

      Req.post(base,
        json: %{
          "jsonrpc" => "2.0",
          "id" => 2,
          "method" => "tools/call",
          "params" => %{"name" => tool_name, "arguments" => arguments}
        },
        headers: headers
      )

      Req.delete(base, headers: headers)
    end
  end

  defp tag_atom("sensitive_read"), do: :sensitive_read
  defp tag_atom("network_egress"), do: :network_egress

  defp apply_event(socket, %{status: status} = event) when status in [:ok, :blocked] do
    socket = stream_insert(socket, :events, event, at: 0)

    if event.server_id in graph_server_ids(socket.assigns.graph) do
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

  defp apply_event(socket, %{status: :held} = event) do
    # The graph "held" pulse is driven by the {:hold_pending, _} message; here
    # we just add the row to the feed.
    stream_insert(socket, :events, event, at: 0)
  end

  defp apply_event(socket, _event), do: socket

  defp format_time(%DateTime{} = ts) do
    Calendar.strftime(ts, "%H:%M:%S")
  end

  # "agent://ci-runner" -> "ci-runner" for the compact feed / history views.
  defp short_agent("agent://" <> rest), do: rest
  defp short_agent(agent) when is_binary(agent), do: agent
  defp short_agent(_), do: nil

  defp format_datetime(%DateTime{} = ts) do
    Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  end

  defp status_label(:ok), do: "allowed"
  defp status_label(:blocked), do: "blocked"
  defp status_label(:held), do: "held"
  defp status_label("ok"), do: "allowed"
  defp status_label("blocked"), do: "blocked"
  defp status_label("held"), do: "held"
  defp status_label(other), do: other

  defp console_status_class(status) when status in [:ok, "ok"], do: "text-success"
  defp console_status_class(status) when status in [:blocked, "blocked"], do: "text-error"
  defp console_status_class(status) when status in [:held, "held"], do: "text-warning"
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

  # A finding is a `Finding` struct on the live feed (broadcast straight from
  # the pipeline) and a string-keyed map in the history table (round-tripped
  # through the audit log).
  defp finding_field(%{__struct__: _} = finding, key), do: Map.get(finding, key)
  defp finding_field(finding, key) when is_map(finding), do: Map.get(finding, to_string(key))

  defp finding_pill_class(finding) do
    case finding_field(finding, :severity) do
      s when s in [:critical, :high, "critical", "high"] -> "bg-error/20 text-error"
      s when s in [:medium, "medium"] -> "bg-warning/20 text-warning"
      _ -> "bg-base-300 text-base-content/60"
    end
  end
end
