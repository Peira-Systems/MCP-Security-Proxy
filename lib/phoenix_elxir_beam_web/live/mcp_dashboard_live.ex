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

  alias PhoenixElxirBeam.MCP.Plugin.{ConfigSchema, Registry, SidecarRunner, WasmRunner}

  @topic "mcp:events"
  @servers_topic "mcp:servers"
  @holds_topic "mcp:holds"
  @audit_topic "mcp:audit"
  @alerts_topic "mcp:alerts"
  @policy_topic "mcp:policy"
  @history_page_size 20

  # A blank rule-engine editor row (see the rules editor section below).
  @blank_rule %{
    "agent" => "",
    "agent_prefix" => "",
    "tool" => "",
    "server" => "",
    "tool_tags_any" => "",
    "after_sensitive_read" => false,
    "if_tainted" => false,
    "action" => "deny",
    "severity" => "high",
    "reason" => "",
    "prompt" => "",
    "timeout_ms" => ""
  }

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
    plugins = plugin_rows()

    socket =
      socket
      |> assign(:page_title, "MCP Dashboard")
      |> assign(:app_version, Application.spec(:phoenix_elxir_beam, :vsn) |> to_string())
      |> assign(:config_tab, "plugins")
      |> assign(:graph, graph)
      |> assign(:positions, layout_positions(graph))
      |> assign(:real_servers, ServerRegistry.list_servers())
      |> assign(:registering, false)
      |> assign(:register_transport, "http")
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
      |> assign(:plugins, plugins)
      |> assign(:open_plugin, nil)
      |> assign(:rules_draft, load_rules_draft(plugins))
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

  @config_tabs ~w(plugins policy_changes client_keys servers)

  @impl true
  def handle_params(params, _uri, socket) do
    page = if params["page"] == "config", do: "config", else: "executive"

    socket = assign(socket, :page, page)

    socket =
      if params["config_tab"] in @config_tabs do
        assign(socket, :config_tab, params["config_tab"])
      else
        socket
      end

    {:noreply, socket}
  end

  # The graph's server + tool nodes come from the live ServerRegistry —
  # `%{id, name, tools}` per registered server.
  defp build_graph do
    for server <- ServerRegistry.list_servers() do
      %{id: server.id, name: server.name, tools: server.tools}
    end
  end

  defp graph_server_ids(graph), do: Enum.map(graph, & &1.id)

  # Fixed four-tier layout — agent, policy gate, server, tool — top to
  # bottom. Positions are final, not a seed for client-side relaxation.
  defp layout_positions(graph) do
    server_count = max(length(graph), 1)
    server_spacing = 170
    first_server_x = 240 - server_spacing * (server_count - 1) / 2

    graph
    |> Enum.with_index()
    |> Enum.reduce(%{"agent" => {240, 70}, "gate" => {240, 240}}, fn
      {%{id: server_id, tools: tools}, i}, acc ->
        server_x = first_server_x + i * server_spacing
        acc = Map.put(acc, "server-" <> server_id, {server_x, 450})

        tool_spacing = 110
        first_tool_x = server_x - tool_spacing * (length(tools) - 1) / 2

        tools
        |> Enum.with_index()
        |> Enum.reduce(acc, fn {tool, j}, acc2 ->
          Map.put(acc2, "tool-" <> tool.name, {first_tool_x + j * tool_spacing, 700})
        end)
    end)
  end

  @impl true
  def handle_event("nav", %{"page" => page}, socket) do
    {:noreply, push_patch(socket, to: ~p"/mcp/dashboard?page=#{page}")}
  end

  def handle_event("nav_config_tab", %{"tab" => tab}, socket) when tab in @config_tabs do
    {:noreply, push_patch(socket, to: ~p"/mcp/dashboard?page=config&config_tab=#{tab}")}
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

  def handle_event("update_plugin_config", %{"name" => name, "raw_config" => raw}, socket) do
    with_operator(socket, fn user ->
      case Jason.decode(raw) do
        {:ok, config} when is_map(config) ->
          current = Enum.find(socket.assigns.plugins, &(&1.name == name))

          case Registry.update_config(name, config) do
            :ok ->
              PolicyChange.record(%{
                kind: :plugin_config,
                target: name,
                actor: user.email,
                before: current && current.config,
                after: config
              })

              socket
              |> assign(:plugins, plugin_rows())
              |> put_flash(:info, "Updated config for #{name}")

            {:error, :not_found} ->
              put_flash(socket, :error, "Plugin #{name} not found")
          end

        {:ok, _not_an_object} ->
          put_flash(socket, :error, "Config must be a JSON object, e.g. {\"max_bytes\": 4000}")

        {:error, _} ->
          put_flash(socket, :error, "That isn't valid JSON — config was not changed")
      end
    end)
  end

  def handle_event("save_plugin_config", %{"name" => name} = params, socket) do
    with_operator(socket, fn user ->
      current = Enum.find(socket.assigns.plugins, &(&1.name == name))
      existing = (current && current.config) || %{}
      field_params = Map.get(params, "config", %{})

      case ConfigSchema.build(name, existing, field_params) do
        {:ok, config} ->
          case Registry.update_config(name, config) do
            :ok ->
              PolicyChange.record(%{
                kind: :plugin_config,
                target: name,
                actor: user.email,
                before: current && current.config,
                after: config
              })

              socket
              |> assign(:plugins, plugin_rows())
              |> put_flash(:info, "Updated config for #{name}")

            {:error, :not_found} ->
              put_flash(socket, :error, "Plugin #{name} not found")
          end

        {:error, message} ->
          put_flash(socket, :error, "#{message} — config was not changed")
      end
    end)
  end

  def handle_event("reset_plugin_config", %{"name" => name}, socket) do
    with_operator(socket, fn user ->
      case Enum.find(socket.assigns.plugins, &(&1.name == name)) do
        nil ->
          put_flash(socket, :error, "Plugin #{name} not found")

        current ->
          default = current.default_config || %{}
          :ok = Registry.update_config(name, default)

          PolicyChange.record(%{
            kind: :plugin_config,
            target: name,
            actor: user.email,
            before: current.config,
            after: default,
            summary: "#{user.email} reset config for plugin #{name} to its default"
          })

          plugins = plugin_rows()

          socket
          |> assign(:plugins, plugins)
          |> then(
            &if(name == "rule-engine",
              do: assign(&1, :rules_draft, load_rules_draft(plugins)),
              else: &1
            )
          )
          |> put_flash(:info, "Reset config for #{name} to its default")
      end
    end)
  end

  def handle_event("open_plugin", %{"name" => name}, socket) do
    socket = assign(socket, :open_plugin, name)

    socket =
      if name == "rule-engine",
        do: assign(socket, :rules_draft, load_rules_draft(socket.assigns.plugins)),
        else: socket

    {:noreply, socket}
  end

  def handle_event("close_plugin", _params, socket) do
    {:noreply, assign(socket, :open_plugin, nil)}
  end

  def handle_event("rules_change", params, socket) do
    {:noreply, assign(socket, :rules_draft, params_to_rows(params))}
  end

  def handle_event("rule_add", _params, socket) do
    {:noreply, assign(socket, :rules_draft, socket.assigns.rules_draft ++ [@blank_rule])}
  end

  def handle_event("rule_remove", %{"idx" => idx}, socket) do
    {:noreply, update(socket, :rules_draft, &List.delete_at(&1, to_int(idx)))}
  end

  def handle_event("rule_move", %{"idx" => idx, "dir" => dir}, socket)
      when dir in ["up", "down"] do
    i = to_int(idx)
    rows = socket.assigns.rules_draft
    j = if dir == "up", do: i - 1, else: i + 1

    rows =
      if j >= 0 and j < length(rows) do
        moved = Enum.at(rows, i)
        rows |> List.delete_at(i) |> List.insert_at(j, moved)
      else
        rows
      end

    {:noreply, assign(socket, :rules_draft, rows)}
  end

  def handle_event("reload_rules", _params, socket) do
    {:noreply,
     socket
     |> assign(:rules_draft, load_rules_draft(socket.assigns.plugins))
     |> put_flash(:info, "Reloaded rules from the saved config")}
  end

  def handle_event("save_rules", params, socket) do
    with_operator(socket, fn user ->
      rules = params |> params_to_rows() |> rows_to_rules()
      current = Enum.find(socket.assigns.plugins, &(&1.name == "rule-engine"))
      existing = (current && current.config) || %{}
      config = Map.put(existing, "rules", rules)

      case Registry.update_config("rule-engine", config) do
        :ok ->
          PolicyChange.record(%{
            kind: :plugin_config,
            target: "rule-engine",
            actor: user.email,
            before: current && current.config,
            after: config
          })

          socket
          |> assign(:plugins, plugin_rows())
          |> assign(:rules_draft, Enum.map(rules, &rule_to_row/1))
          |> put_flash(:info, "Saved #{length(rules)} rule(s) for rule-engine")

        {:error, :not_found} ->
          put_flash(socket, :error, "rule-engine plugin not found")
      end
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

        %{kind: "plugin_config", target: name, before: before} when is_map(before) ->
          :ok = Registry.update_config(name, before)
          current = Enum.find(socket.assigns.plugins, &(&1.name == name))

          PolicyChange.record(%{
            kind: :plugin_config,
            target: name,
            actor: user.email,
            before: current && current.config,
            after: before,
            summary: "#{user.email} reverted #{event_id}: config for plugin #{name} restored"
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

  def handle_event("set_register_transport", %{"transport" => transport}, socket)
      when transport in ["http", "stdio"] do
    {:noreply, assign(socket, :register_transport, transport)}
  end

  def handle_event(
        "register_stdio_server",
        %{"name" => name, "command" => command} = params,
        socket
      ) do
    name = String.trim(name)
    command = String.trim(command)

    if name == "" or command == "" do
      {:noreply, put_flash(socket, :error, "Name and command are both required")}
    else
      args =
        params
        |> Map.get("args", "")
        |> String.split("\n", trim: true)
        |> Enum.map(&String.trim/1)

      liveview = self()

      Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
        send(
          liveview,
          {:server_registered, ServerRegistry.register_stdio_server(name, command, args)}
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

  # ISO-8601 deadline for the client-side countdown ring — `created_at` plus
  # the hold's own `timeout_ms`, read once into a `data-deadline` attribute.
  defp hold_deadline(%{created_at: %DateTime{} = created_at, timeout_ms: timeout_ms}) do
    created_at
    |> DateTime.add(timeout_ms, :millisecond)
    |> DateTime.to_iso8601()
  end

  defp held_ago(%DateTime{} = ts) do
    case DateTime.diff(DateTime.utc_now(), ts) do
      s when s < 1 -> "just now"
      1 -> "1s ago"
      s -> "#{s}s ago"
    end
  end

  # Rows for the read-only Plugins panel: name, kind, source, enabled, and
  # (sidecar/wasm only) live health from the SidecarRunner/WasmRunner.
  defp plugin_rows do
    Registry.list()
    |> Enum.map(fn entry ->
      {source, health} =
        case entry.impl do
          {:sidecar, runner} -> {"sidecar", SidecarRunner.health(runner)}
          {:wasm, runner} -> {"wasm", WasmRunner.health(runner)}
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
        description: plugin_description(entry.name),
        config: entry.config,
        default_config: entry.default_config
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

  defp plugin_description("rule-engine-wasm") do
    "The W4 reference Wasm plugin (docs/wasm-plugin-plan.md): a wasm32-wasip1 port of " <>
      "rule-engine's exact match/decision logic, run in-process but sandboxed by " <>
      "Wasmtime — no filesystem or network capability, a runaway call interrupted by " <>
      "the runtime rather than merely abandoned (docs/plugin-protocol.md §5.4). Ships " <>
      "alongside rule-engine, not instead of it, disabled by default; its verdicts are " <>
      "checked against the Elixir original call-for-call by " <>
      "rule_engine_wasm_parity_test.exs, not just spot-checked. Enable it here with the " <>
      "same operator rules rule-engine already has to compare them live."
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

  # The per-plugin config form (schema, field reference, and param coercion)
  # lives in `PhoenixElxirBeam.MCP.Plugin.ConfigSchema`.

  # Seeds a config field's input: the live config value, else the plugin's
  # code-level default. `:string_list` and `:json` fields render as text, so
  # they get a string here; everything else passes its native value through.
  defp config_field_value(%{type: :string_list} = field, config) do
    field |> ConfigSchema.value_for(config) |> List.wrap() |> Enum.join(", ")
  end

  defp config_field_value(%{type: :json} = field, config) do
    Jason.encode!(ConfigSchema.value_for(field, config), pretty: true)
  end

  defp config_field_value(field, config), do: ConfigSchema.value_for(field, config)

  defp config_field_id(plugin_name, key), do: "cfg-#{plugin_name}-#{key}"

  # One config input, rendered from a `ConfigSchema` field. `value` is
  # already display-shaped (see `config_field_value/2`).
  attr :plugin, :string, required: true
  attr :field, :map, required: true
  attr :value, :any, default: nil

  def config_field_input(%{field: %{type: :select}} = assigns) do
    ~H"""
    <select
      id={config_field_id(@plugin, @field.key)}
      name={"config[#{@field.key}]"}
      class="select select-bordered select-sm w-full max-w-md text-xs"
    >
      <option :for={{val, label} <- @field.options} value={val} selected={to_string(@value) == val}>
        {label}
      </option>
    </select>
    """
  end

  def config_field_input(%{field: %{type: :boolean}} = assigns) do
    ~H"""
    <input type="hidden" name={"config[#{@field.key}]"} value="false" />
    <input
      type="checkbox"
      id={config_field_id(@plugin, @field.key)}
      name={"config[#{@field.key}]"}
      value="true"
      checked={@value in [true, "true"]}
      class="checkbox checkbox-sm"
    />
    """
  end

  def config_field_input(%{field: %{type: :integer}} = assigns) do
    ~H"""
    <label class="input input-bordered input-sm flex w-40 items-center gap-1 text-xs">
      <input
        type="number"
        min={Map.get(@field, :min, 0)}
        id={config_field_id(@plugin, @field.key)}
        name={"config[#{@field.key}]"}
        value={@value}
        placeholder={to_string(@field.default)}
        class="w-full"
      />
      <span :if={Map.get(@field, :unit)} class="text-base-content/40">{@field.unit}</span>
    </label>
    """
  end

  def config_field_input(%{field: %{type: :json}} = assigns) do
    ~H"""
    <textarea
      id={config_field_id(@plugin, @field.key)}
      name={"config[#{@field.key}]"}
      rows="8"
      spellcheck="false"
      class="textarea textarea-bordered w-full font-mono text-xs"
    >{@value}</textarea>
    """
  end

  def config_field_input(assigns) do
    ~H"""
    <input
      type="text"
      id={config_field_id(@plugin, @field.key)}
      name={"config[#{@field.key}]"}
      value={@value}
      placeholder={to_string(@field.default)}
      class="input input-bordered input-sm w-full max-w-md text-xs"
    />
    """
  end

  # --- rule-engine visual rules editor -------------------------------------
  #
  # `rule-engine`'s `config["rules"]` is an ordered list of rule objects — too
  # nested for a flat field form, so it gets its own editor backed by
  # `@rules_draft`. A draft "row" is the rule flattened for form binding:
  # every `match.*` key hoisted to the top level, `tool_tags_any` joined to a
  # comma string, the two boolean predicates as real booleans. `rule_to_row/1`
  # normalizes a stored rule into a row; `rows_to_rules/1` rebuilds stored
  # rules from form params, dropping blank keys so a catch-all rule stays
  # `match`-less. `@blank_rule` (a fresh row) is at the top of the module so
  # `rule_add` can see it.

  defp load_rules_draft(plugins) do
    case Enum.find(plugins, &(&1.name == "rule-engine")) do
      %{config: %{"rules" => rules}} when is_list(rules) -> Enum.map(rules, &rule_to_row/1)
      _ -> []
    end
  end

  defp rule_to_row(rule) when is_map(rule) do
    match = Map.get(rule, "match", %{}) || %{}

    %{
      "agent" => rule_str(match["agent"]),
      "agent_prefix" => rule_str(match["agent_prefix"]),
      "tool" => rule_str(match["tool"]),
      "server" => rule_str(match["server"]),
      "tool_tags_any" => match |> Map.get("tool_tags_any", []) |> List.wrap() |> Enum.join(", "),
      "after_sensitive_read" => match["after_sensitive_read"] == true,
      "if_tainted" => match["if_tainted"] == true,
      "action" => rule_action(rule["action"]),
      "severity" => rule_severity(rule["severity"]),
      "reason" => rule_str(rule["reason"]),
      "prompt" => rule_str(rule["prompt"]),
      "timeout_ms" => (rule["timeout_ms"] && to_string(rule["timeout_ms"])) || ""
    }
  end

  defp rule_to_row(_), do: @blank_rule

  defp params_to_rows(%{"rules" => rules}) when is_map(rules) do
    rules
    |> Enum.sort_by(fn {k, _} -> to_int(k) end)
    |> Enum.map(fn {_k, row} -> row_from_params(row) end)
  end

  defp params_to_rows(_), do: []

  defp row_from_params(row) when is_map(row) do
    %{
      "agent" => rule_str(row["agent"]),
      "agent_prefix" => rule_str(row["agent_prefix"]),
      "tool" => rule_str(row["tool"]),
      "server" => rule_str(row["server"]),
      "tool_tags_any" => rule_str(row["tool_tags_any"]),
      "after_sensitive_read" => row["after_sensitive_read"] == "true",
      "if_tainted" => row["if_tainted"] == "true",
      "action" => rule_action(row["action"]),
      "severity" => rule_severity(row["severity"]),
      "reason" => rule_str(row["reason"]),
      "prompt" => rule_str(row["prompt"]),
      "timeout_ms" => rule_str(row["timeout_ms"])
    }
  end

  defp row_from_params(_), do: @blank_rule

  defp rows_to_rules(rows), do: Enum.map(rows, &row_to_rule/1)

  defp row_to_rule(row) do
    match =
      %{}
      |> rule_put("agent", row["agent"])
      |> rule_put("agent_prefix", row["agent_prefix"])
      |> rule_put("tool", row["tool"])
      |> rule_put("server", row["server"])
      |> rule_put_list("tool_tags_any", row["tool_tags_any"])
      |> rule_put_flag("after_sensitive_read", row["after_sensitive_read"])
      |> rule_put_flag("if_tainted", row["if_tainted"])

    %{"action" => rule_action(row["action"])}
    |> then(&if(match == %{}, do: &1, else: Map.put(&1, "match", match)))
    |> rule_put("reason", row["reason"])
    |> rule_action_fields(row)
  end

  defp rule_action_fields(rule, %{"action" => "deny"} = row),
    do: rule_put(rule, "severity", row["severity"])

  defp rule_action_fields(rule, %{"action" => "hold"} = row) do
    rule
    |> rule_put("prompt", row["prompt"])
    |> rule_put_pos_int("timeout_ms", row["timeout_ms"])
  end

  defp rule_action_fields(rule, _row), do: rule

  defp rule_put(map, _key, value) when value in [nil, ""], do: map
  defp rule_put(map, key, value), do: Map.put(map, key, String.trim(value))

  defp rule_put_list(map, key, csv) do
    list =
      csv
      |> rule_str()
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    if list == [], do: map, else: Map.put(map, key, list)
  end

  defp rule_put_flag(map, key, flag) when flag in [true, "true"], do: Map.put(map, key, true)
  defp rule_put_flag(map, _key, _flag), do: map

  defp rule_put_pos_int(map, key, value) do
    case Integer.parse(rule_str(value)) do
      {n, _} when n > 0 -> Map.put(map, key, n)
      _ -> map
    end
  end

  defp rule_str(nil), do: ""
  defp rule_str(s) when is_binary(s), do: s
  defp rule_str(other), do: to_string(other)

  defp rule_action(a) when a in ["deny", "allow", "hold"], do: a
  defp rule_action(_), do: "deny"

  defp rule_severity(s) when s in ["low", "medium", "high", "critical"], do: s
  defp rule_severity(_), do: "high"

  defp to_int(n) when is_integer(n), do: n

  defp to_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, _} -> n
      _ -> 0
    end
  end

  defp to_int(_), do: 0

  defp rule_summary(row) do
    preds =
      [
        row["agent"] != "" && "agent #{row["agent"]}",
        row["agent_prefix"] != "" && "agent ~ #{row["agent_prefix"]}",
        row["tool"] != "" && "tool #{row["tool"]}",
        row["server"] != "" && "server #{row["server"]}",
        row["tool_tags_any"] != "" && "tags: #{row["tool_tags_any"]}",
        row["after_sensitive_read"] && "after sensitive read",
        row["if_tainted"] && "if tainted"
      ]
      |> Enum.filter(& &1)

    case preds do
      [] -> "#{row["action"]} · any call"
      list -> "#{row["action"]} · #{Enum.join(list, ", ")}"
    end
  end

  attr :rules, :list, required: true
  attr :can_operate, :boolean, required: true

  def rules_editor(assigns) do
    ~H"""
    <div>
      <p :if={not @can_operate} class="text-xs text-base-content/50">
        Operator role required to edit rules.
      </p>

      <.form
        :if={@can_operate}
        for={to_form(%{})}
        id="rule-engine-rules-form"
        phx-change="rules_change"
        phx-submit="save_rules"
        class="space-y-3"
      >
        <p
          :if={@rules == []}
          class="rounded-box border border-dashed border-base-300 px-3 py-4 text-center text-xs text-base-content/50"
        >
          No rules — every call is allowed. Add a rule to start denying or holding calls.
        </p>

        <div
          :for={{row, idx} <- Enum.with_index(@rules)}
          class="space-y-2 rounded-box border border-base-300 bg-base-200/40 p-3"
        >
          <div class="flex items-center gap-2">
            <span class="text-xs font-semibold">Rule {idx + 1}</span>
            <span class="rounded-full bg-base-300 px-2 py-0.5 text-[10px] text-base-content/60">
              {rule_summary(row)}
            </span>
            <div class="ml-auto flex items-center gap-1">
              <button
                type="button"
                class="btn btn-ghost btn-xs px-1"
                phx-click="rule_move"
                phx-value-idx={idx}
                phx-value-dir="up"
                title="move earlier"
              >
                ▲
              </button>
              <button
                type="button"
                class="btn btn-ghost btn-xs px-1"
                phx-click="rule_move"
                phx-value-idx={idx}
                phx-value-dir="down"
                title="move later"
              >
                ▼
              </button>
              <button
                type="button"
                class="btn btn-ghost btn-xs px-1 text-error"
                phx-click="rule_remove"
                phx-value-idx={idx}
                title="delete rule"
              >
                ✕
              </button>
            </div>
          </div>

          <div class="text-[10px] font-semibold uppercase tracking-wide text-base-content/40">
            Match — every field you set must hold (leave all blank for a catch-all)
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="flex flex-col gap-0.5 text-[11px]">
              Agent id — exact
              <input
                type="text"
                name={"rules[#{idx}][agent]"}
                value={row["agent"]}
                placeholder="agent://ci-runner"
                class="input input-bordered input-xs font-mono"
              />
            </label>
            <label class="flex flex-col gap-0.5 text-[11px]">
              Agent id — prefix
              <input
                type="text"
                name={"rules[#{idx}][agent_prefix]"}
                value={row["agent_prefix"]}
                placeholder="agent://acme-"
                class="input input-bordered input-xs font-mono"
              />
            </label>
            <label class="flex flex-col gap-0.5 text-[11px]">
              Tool name
              <input
                type="text"
                name={"rules[#{idx}][tool]"}
                value={row["tool"]}
                class="input input-bordered input-xs font-mono"
              />
            </label>
            <label class="flex flex-col gap-0.5 text-[11px]">
              Server id
              <input
                type="text"
                name={"rules[#{idx}][server]"}
                value={row["server"]}
                class="input input-bordered input-xs font-mono"
              />
            </label>
            <label class="flex flex-col gap-0.5 text-[11px] sm:col-span-2">
              Tool tags — matches if the call carries any of these (comma-separated)
              <input
                type="text"
                name={"rules[#{idx}][tool_tags_any]"}
                value={row["tool_tags_any"]}
                placeholder="network_egress, sensitive_read"
                class="input input-bordered input-xs font-mono"
              />
            </label>
          </div>
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-1.5 text-[11px]">
              <input
                type="checkbox"
                name={"rules[#{idx}][after_sensitive_read]"}
                value="true"
                checked={row["after_sensitive_read"]}
                class="checkbox checkbox-xs"
              /> after a sensitive read this session
            </label>
            <label class="flex items-center gap-1.5 text-[11px]">
              <input
                type="checkbox"
                name={"rules[#{idx}][if_tainted]"}
                value="true"
                checked={row["if_tainted"]}
                class="checkbox checkbox-xs"
              /> a secret has flowed through this session
            </label>
          </div>

          <div class="text-[10px] font-semibold uppercase tracking-wide text-base-content/40">
            Then
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="flex flex-col gap-0.5 text-[11px]">
              Action
              <select name={"rules[#{idx}][action]"} class="select select-bordered select-xs">
                <option value="deny" selected={row["action"] == "deny"}>deny</option>
                <option value="allow" selected={row["action"] == "allow"}>
                  allow — exception, stops later rules
                </option>
                <option value="hold" selected={row["action"] == "hold"}>hold for approval</option>
              </select>
            </label>
            <label :if={row["action"] == "deny"} class="flex flex-col gap-0.5 text-[11px]">
              Severity
              <select name={"rules[#{idx}][severity]"} class="select select-bordered select-xs">
                <option
                  :for={s <- ~w(low medium high critical)}
                  value={s}
                  selected={row["severity"] == s}
                >
                  {s}
                </option>
              </select>
            </label>
            <label class="flex flex-col gap-0.5 text-[11px] sm:col-span-2">
              Reason — shown to the agent and operator
              <input
                type="text"
                name={"rules[#{idx}][reason]"}
                value={row["reason"]}
                class="input input-bordered input-xs"
              />
            </label>
            <label :if={row["action"] == "hold"} class="flex flex-col gap-0.5 text-[11px]">
              Approval prompt
              <input
                type="text"
                name={"rules[#{idx}][prompt]"}
                value={row["prompt"]}
                class="input input-bordered input-xs"
              />
            </label>
            <label :if={row["action"] == "hold"} class="flex flex-col gap-0.5 text-[11px]">
              Timeout (ms) — auto-denies after this
              <input
                type="number"
                min="1"
                name={"rules[#{idx}][timeout_ms]"}
                value={row["timeout_ms"]}
                placeholder="120000"
                class="input input-bordered input-xs"
              />
            </label>
          </div>
        </div>

        <div class="flex items-center justify-between">
          <button type="button" class="btn btn-outline btn-xs" phx-click="rule_add">
            + Add rule
          </button>
          <div class="flex gap-1.5">
            <button
              type="button"
              class="btn btn-ghost btn-xs"
              phx-click="reset_plugin_config"
              phx-value-name="rule-engine"
            >
              Reset to default
            </button>
            <button type="button" class="btn btn-ghost btn-xs" phx-click="reload_rules">
              Reload saved
            </button>
            <button type="submit" class="btn btn-xs btn-primary">Save rules</button>
          </div>
        </div>
        <p class="text-[10px] text-base-content/40">
          Rules run top to bottom — the first whose match holds decides. No match → allow.
          Applies on the next call, no restart.
        </p>
      </.form>
    </div>
    """
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
