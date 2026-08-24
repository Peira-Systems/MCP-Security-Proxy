defmodule PhoenixElxirBeamWeb.MCPLogLive do
  @moduledoc """
  Durable, paged, filterable browser over `PhoenixElxirBeam.MCP.EventLog` —
  every policy verdict PolicyEngine has ever recorded, independent of
  whether a dashboard was open to see it live. Filters and page live in
  the URL query string so a filtered view is linkable and survives a
  reload.
  """

  use PhoenixElxirBeamWeb, :live_view

  alias PhoenixElxirBeam.MCP.EventLog

  @page_size 25

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, :server_options, EventLog.distinct_server_ids())}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filters = parse_filters(params)
    page = parse_page(params)

    result = EventLog.list(Map.merge(filters, %{page: page, page_size: @page_size}))

    {:noreply,
     socket
     |> assign(:page_title, "MCP Event Log")
     |> assign(:params, params)
     |> assign(:status, params["status"] || "all")
     |> assign(:server_id, params["server_id"] || "all")
     |> assign(:from, params["from"] || "")
     |> assign(:to, params["to"] || "")
     |> assign(:result, result)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    query =
      %{
        "status" => params["status"],
        "server_id" => params["server_id"],
        "from" => params["from"],
        "to" => params["to"]
      }
      |> Enum.reject(fn {_k, v} -> v in [nil, "", "all"] end)
      |> Map.new()

    {:noreply, push_patch(socket, to: ~p"/mcp/logs?#{query}")}
  end

  def handle_event("paginate", %{"page" => page}, socket) do
    query = socket.assigns.params |> Map.delete("page") |> Map.put("page", page)
    {:noreply, push_patch(socket, to: ~p"/mcp/logs?#{query}")}
  end

  defp parse_filters(params) do
    %{
      status: params["status"],
      server_id: params["server_id"],
      from: parse_date(params["from"], :beginning),
      to: parse_date(params["to"], :end)
    }
  end

  defp parse_page(params) do
    case Integer.parse(params["page"] || "1") do
      {n, _} when n > 0 -> n
      _ -> 1
    end
  end

  defp parse_date(nil, _edge), do: nil
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

  defp status_label("ok"), do: "allowed"
  defp status_label("blocked"), do: "blocked"
  defp status_label("session_start"), do: "session started"
  defp status_label("session_complete"), do: "session complete"
  defp status_label(other), do: other

  defp status_badge_class("ok"), do: "bg-success/15 text-success"
  defp status_badge_class("blocked"), do: "bg-error/15 text-error"
  defp status_badge_class(_), do: "bg-base-300 text-base-content/70"

  defp format_time(%DateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp format_time(_), do: "—"
end
