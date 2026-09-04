defmodule PhoenixElxirBeamWeb.MCPDashboardLive do
  @moduledoc """
  Live dashboard for the policy proxy: a tool graph that lights up as real
  `tools/call`s flow through and turns red when a call is blocked, a
  console-style event log (live feed or the durable history browser), the
  plugin pipeline, and real-server registration / tag curation.
  """

  use PhoenixElxirBeamWeb, :live_view

  alias PhoenixElxirBeam.Accounts

  alias PhoenixElxirBeam.MCP.{
    ApiKey,
    AuditIntegrity,
    EventLog,
    HoldRegistry,
    PolicyChange,
    ServerRegistry,
    SessionStore
  }

  alias PhoenixElxirBeam.MCP.Plugin.{Registry, SidecarRunner}

  @topic "mcp:events"
  @servers_topic "mcp:servers"
  @holds_topic "mcp:holds"
  @audit_topic "mcp:audit"
  @alerts_topic "mcp:alerts"
  @policy_topic "mcp:policy"
  @history_page_size 20

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @servers_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @holds_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @audit_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @alerts_topic)
      Phoenix.PubSub.subscribe(PhoenixElxirBeam.PubSub, @policy_topic)
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
      |> assign(:can_operate, Accounts.role_at_least?(socket.assigns.current_user, :operator))
      |> assign(:policy_changes, PolicyChange.recent(15))
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

  def handle_event("toggle_plugin", %{"name" => name, "enabled" => enabled}, socket) do
    with_operator(socket, fn user ->
      want = enabled == "true"
      current = Enum.find(socket.assigns.plugins, &(&1.name == name))

      if current && current.enabled != want do
        result = if want, do: Registry.enable(name), else: Registry.disable(name)

        if result == :ok do
          PolicyChange.record(%{
            kind: :plugin_enabled,
            target: name,
            actor: user.email,
            before: current.enabled,
            after: want
          })
        end
      end

      assign(socket, :plugins, plugin_rows())
    end)
  end

  def handle_event("move_plugin", %{"name" => name, "dir" => dir}, socket)
      when dir in ["up", "down"] do
    with_operator(socket, fn user ->
      names = Enum.map(socket.assigns.plugins, & &1.name)
      idx = Enum.find_index(names, &(&1 == name))
      swap = if dir == "up", do: idx && idx - 1, else: idx && idx + 1

      if idx && swap && swap >= 0 && swap < length(names) do
        reordered = names |> List.delete_at(idx) |> List.insert_at(swap, name)
        :ok = Registry.reorder(reordered)

        PolicyChange.record(%{
          kind: :plugin_order,
          target: name,
          actor: user.email,
          before: names,
          after: reordered
        })
      end

      assign(socket, :plugins, plugin_rows())
    end)
  end

  def handle_event("revert_policy_change", %{"event_id" => event_id}, socket) do
    with_operator(socket, fn user ->
      case Enum.find(socket.assigns.policy_changes, &(&1.event_id == event_id)) do
        %{kind: "plugin_enabled", target: name, before: before} ->
          want = before in [true, "true"]
          if want, do: Registry.enable(name), else: Registry.disable(name)

          PolicyChange.record(%{
            kind: :plugin_enabled,
            target: name,
            actor: user.email,
            before: not want,
            after: want,
            summary:
              "#{user.email} reverted #{event_id}: plugin #{name} " <>
                "#{if want, do: "enabled", else: "disabled"}"
          })

          assign(socket, :plugins, plugin_rows())

        %{kind: "plugin_order", before: before} when is_list(before) ->
          :ok = Registry.reorder(before)

          PolicyChange.record(%{
            kind: :plugin_order,
            target: "pipeline",
            actor: user.email,
            before: Enum.map(socket.assigns.plugins, & &1.name),
            after: before,
            summary: "#{user.email} reverted #{event_id}: pipeline order restored"
          })

          assign(socket, :plugins, plugin_rows())

        _ ->
          put_flash(socket, :error, "That change can't be reverted from here.")
      end
    end)
  end

  def handle_event("history_paginate", %{"page" => page}, socket) do
    page =
      case Integer.parse(page) do
        {n, _} when n > 0 -> n
        _ -> 1
      end

    {:noreply, refresh_history(assign(socket, :history_page, page))}
  end

  def handle_event("register_server", %{"name" => name, "base_url" => base_url} = params, socket) do
    name = String.trim(name)
    base_url = String.trim(base_url)

    if name == "" or base_url == "" do
      {:noreply, put_flash(socket, :error, "Name and base URL are both required")}
    else
      opts = registration_opts(params)
      liveview = self()

      Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
        send(
          liveview,
          {:server_registered, ServerRegistry.register_server(name, base_url, opts)}
        )
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
    with_operator(socket, fn user ->
      tag = tag_atom(tag_str)
      server = ServerRegistry.get_server(server_id)
      tool = Enum.find(server.tools, &(&1.name == tool_name))
      new_tags = if tag in tool.tags, do: List.delete(tool.tags, tag), else: [tag | tool.tags]

      {:ok, _server} = ServerRegistry.set_tool_tags(server_id, tool_name, new_tags)

      PolicyChange.record(%{
        kind: :tool_tags,
        target: "#{server_id}/#{tool_name}",
        actor: user.email,
        before: Enum.map(tool.tags, &to_string/1),
        after: Enum.map(new_tags, &to_string/1),
        server_id: server_id
      })

      assign(socket, :real_servers, ServerRegistry.list_servers())
    end)
  end

  def handle_event("rehandshake", %{"server_id" => server_id}, socket) do
    {:noreply, start_rehandshake(socket, server_id)}
  end

  def handle_event(
        "clear_tool_block",
        %{"server_id" => server_id, "tool_name" => tool_name},
        socket
      ) do
    with_operator(socket, fn user ->
      {:ok, _server} = ServerRegistry.clear_tool_block(server_id, tool_name)

      PolicyChange.record(%{
        kind: :tool_quarantine,
        target: "#{server_id}/#{tool_name}",
        actor: user.email,
        before: "quarantined",
        after: "cleared",
        server_id: server_id
      })

      assign(socket, :real_servers, ServerRegistry.list_servers())
    end)
  end

  def handle_event(
        "apply_suggested_tags",
        %{"server_id" => server_id, "tool_name" => tool_name},
        socket
      ) do
    with_operator(socket, fn user ->
      server = ServerRegistry.get_server(server_id)
      tool = server && Enum.find(server.tools, &(&1.name == tool_name))
      suggested = (tool && Map.get(tool, :suggested_tags, [])) || []

      if tool && suggested != [] do
        new_tags = Enum.uniq(tool.tags ++ suggested)
        {:ok, _} = ServerRegistry.set_tool_tags(server_id, tool_name, new_tags)

        PolicyChange.record(%{
          kind: :tool_tags,
          target: "#{server_id}/#{tool_name}",
          actor: user.email,
          before: Enum.map(tool.tags, &to_string/1),
          after: Enum.map(new_tags, &to_string/1),
          server_id: server_id
        })
      end

      assign(socket, :real_servers, ServerRegistry.list_servers())
    end)
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

  def handle_info({:policy_change, _change}, socket) do
    {:noreply,
     socket
     |> assign(:policy_changes, PolicyChange.recent(15))
     |> assign(:plugins, plugin_rows())}
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

  # Optional per-server overrides from the register-server form (M1.5
  # follow-up). Blank/absent = inherit the proxy-wide default.
  defp registration_opts(params) do
    []
    |> put_timeout_ms(params["timeout_ms"])
    |> put_skip_tls_verify(params["skip_tls_verify"])
  end

  defp put_timeout_ms(opts, str) when is_binary(str) do
    case Integer.parse(String.trim(str)) do
      {ms, _} when ms > 0 -> Keyword.put(opts, :timeout_ms, ms)
      _ -> opts
    end
  end

  defp put_timeout_ms(opts, _), do: opts

  defp put_skip_tls_verify(opts, "true"), do: Keyword.put(opts, :tls_verify, false)
  defp put_skip_tls_verify(opts, _), do: opts

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

  # Runs `fun.(user)` only when the current user is at least an operator;
  # otherwise flashes and returns the socket unchanged. `fun` returns a socket.
  defp with_operator(socket, fun) do
    user = socket.assigns.current_user

    if user && Accounts.role_at_least?(user, :operator) do
      {:noreply, fun.(user)}
    else
      {:noreply, put_flash(socket, :error, "That action requires the operator role.")}
    end
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
        note: plugin_note(entry),
        description: plugin_description(entry.name)
      }
    end)
  rescue
    _ -> []
  end

  defp plugin_note(%{name: "rule-engine", config: %{"rules" => rules}}) when is_list(rules) do
    "#{length(rules)} rule#{if length(rules) == 1, do: "", else: "s"}"
  end

  defp plugin_note(_entry), do: nil

  # Detailed "what it does and how it works" copy for the Plugins panel's
  # info popup. Distilled from each plugin module's own @moduledoc, so this
  # is a summary for operators — the moduledoc stays the source of truth.
  defp plugin_description("approval-gate") do
    "Human-in-the-loop counterpart to chain-exfil: instead of hard-blocking " <>
      "network egress after a sensitive read, it returns a \"hold\" verdict, " <>
      "so the proxy parks the call and the dashboard shows an Approve / Deny " <>
      "card. If the operator takes no action within the configured timeout " <>
      "(config \"timeout_ms\", default 120s), the on-timeout action applies " <>
      "(deny)."
  end

  defp plugin_description("baseline-guard") do
    "Behavioural baselining: a pre-call policy that denies a call once the " <>
      "session has made too many calls of a watched kind inside a short " <>
      "window — e.g. reading secrets six times in ten seconds. It reads the " <>
      "session's recent-calls window that the proxy threads into every " <>
      "pre-call context, then applies its own window and threshold from " <>
      "operator config: \"window_ms\" (look-back window), \"max_calls\" " <>
      "(allowed within the window), and \"watch_tags\" (which call tags to " <>
      "count). It's heuristic by nature, so it fails open on errors."
  end

  defp plugin_description("chain-exfil") do
    "The original tool-chaining rule, as a policy plugin: a call tagged " <>
      "network_egress is denied if and only if a sensitive_read occurred " <>
      "earlier in the same session. Order matters — egress before any " <>
      "sensitive read is allowed. Its manifest scopes it to " <>
      "tool_tags: [network_egress], so the pipeline only consults it for " <>
      "egress-tagged calls."
  end

  defp plugin_description("event-log") do
    "The built-in audit sink: persists every audit event to the local, " <>
      "hash-chained policy_events table. It runs alongside the " <>
      "structured-log sink (JSON log lines for SIEM / OTel ingestion) — two " <>
      "sinks, no core changes required, just two entries in the plugin list."
  end

  defp plugin_description("response-size-guard") do
    "A post-call policy that withholds a tool response whose text content " <>
      "exceeds a byte budget — a blunt bulk-exfiltration guard: a tool " <>
      "asked to dump a whole table, directory, or file returns far more " <>
      "than a normal call, and the proxy refuses to relay it (JSON-RPC " <>
      "error -32002). The budget is configurable via config \"max_bytes\" " <>
      "(default 4000)."
  end

  defp plugin_description("rug-pull") do
    "Rug-pull / tool-drift detector: a discovery-phase scanner that pins " <>
      "each tool's description hash at registration and, on every " <>
      "re-handshake, flags any tool whose definition changed. This catches " <>
      "the classic attack where a server passes review with a benign " <>
      "tools/list, then later swaps in a poisoned description. A changed " <>
      "hash on a previously-seen tool produces a rug_pull finding and a " <>
      "quarantine update that holds the tool until an operator clears it; a " <>
      "tool with no previous hash is treated as new, not drift."
  end

  defp plugin_description("rule-engine") do
    "A policy plugin whose verdicts come from operator-written rules, not " <>
      "code. Rules live in the plugin's config block and are evaluated in " <>
      "order — the first rule whose match conditions are satisfied decides " <>
      "the verdict; a rule with no predicates matches every call. Match " <>
      "predicates (all must hold): agent / agent_prefix, tool / server, " <>
      "tool_tags_any, after_sensitive_read, and if_tainted. Actions: deny, " <>
      "allow (an explicit exception that short-circuits later rules), or " <>
      "hold (with an optional timeout, default 120s). No matching rule " <>
      "defaults to allow."
  end

  defp plugin_description("secret-leak") do
    "A post-call scanner that finds credentials in a tool's response and " <>
      "proposes redactions so the secret never reaches the agent — " <>
      "advisory, not blocking: the proxy applies the redactions before " <>
      "returning the response. When it finds something it also tags the " <>
      "session with HMAC taint markers for the secret and its common " <>
      "encodings (the raw secret itself is never stored or broadcast), plus " <>
      "a redacted hint. taint-guard uses this to block later egress " <>
      "coarsely; tainted-arg-guard matches the markers against later calls' " <>
      "arguments to catch base64/hex/URL-encoded copies."
  end

  defp plugin_description("stream-guard") do
    "The streaming counterpart to response-size-guard: a chunk-phase " <>
      "policy that watches the running byte count of a streamed tool " <>
      "response and denies once it passes a budget, telling the proxy to " <>
      "cut the stream mid-flight. Chunks already delivered stay delivered, " <>
      "so this is containment rather than prevention. The budget is " <>
      "configurable via \"max_bytes\" (running total across delivered and " <>
      "current chunk)."
  end

  defp plugin_description("structured-log") do
    "A second audit sink, alongside event-log: emits every audit event as " <>
      "a single-line JSON object on the logger at info level, prefixed " <>
      "mcp.audit. A log shipper (Vector, Fluent Bit, the OTel Collector's " <>
      "filelog receiver, a Splunk forwarder) tails stdout and forwards " <>
      "these to a SIEM. The line carries verdict metadata only — never raw " <>
      "finding evidence or the tracked secret."
  end

  defp plugin_description("taint-guard") do
    "The provenance counterpart to chain-exfil: a call tagged " <>
      "network_egress is denied when the session's taint list is " <>
      "non-empty — i.e. a post-call scanner (secret-leak) has already seen " <>
      "a secret flow through a response in this session. Where chain-exfil " <>
      "keys off the operator's sensitive_read tag on the tool definition, " <>
      "taint-guard keys off what actually came back over the wire, so it " <>
      "catches exfil even when the leaking tool was never tagged."
  end

  defp plugin_description("tainted-arg-guard") do
    "Marker-level taint enforcement: blocks a tools/call whose arguments " <>
      "carry a secret that a post-call scanner saw earlier in the same " <>
      "session. secret-leak records HMAC taint markers for the secret and " <>
      "its common encodings; this plugin tokenises the outbound arguments, " <>
      "marks each token and its plausible decodings, and denies on any " <>
      "collision — so a base64- or hex-encoded copy of the secret is " <>
      "caught, not just the raw bytes. Unlike taint-guard, it isn't scoped " <>
      "to egress tags, so it inspects every call's arguments."
  end

  defp plugin_description("unclassified-guard") do
    "Default-deny for unclassified tools. A freshly discovered tool starts " <>
      "with no operator tags, so every tag-scoped policy (chain-exfil, " <>
      "taint-guard, approval-gate, …) is inert on it — without this plugin, " <>
      "an un-curated proxy is effectively allow-all. When enabled, a " <>
      "tools/call to a tool the operator hasn't tagged is either denied " <>
      "(JSON-RPC error -32001) or held for operator sign-off, depending on " <>
      "config \"mode\" (off | deny | hold; default off, so it can ship " <>
      "enabled-but-inert)."
  end

  defp plugin_description("prompt-injection-scanner") do
    "The reference polyglot plugin: a Python sidecar, run out of process and " <>
      "spoken to over the newline-delimited JSON-RPC Plugin Protocol, so the " <>
      "proxy treats it exactly like an in-process Elixir plugin. Detection " <>
      "is a maintained ruleset (injection_rules.json) — labelled regex rules " <>
      "across instruction-override, secrecy, exfiltration, and " <>
      "tool-poisoning categories; precision/recall against the labelled " <>
      "corpus is measured and gated in CI. Two phases: discovery inspects " <>
      "tool descriptions at server registration / re-handshake and, on a " <>
      "hit, emits a prompt_injection finding and (with operator grant) a " <>
      "tool-quarantine update; post_call inspects tool responses before the " <>
      "agent sees them, reporting a hidden instruction and stripping it via " <>
      "a redact-response mutation."
  end

  defp plugin_description(name) do
    "No detailed description is registered for \"#{name}\" yet — see the " <>
      "plugin's own module for what it does and how it works."
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
