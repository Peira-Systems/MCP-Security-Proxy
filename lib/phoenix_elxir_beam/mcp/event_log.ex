defmodule PhoenixElxirBeam.MCP.EventLog do
  @moduledoc """
  Durable storage and querying for `PhoenixElxirBeam.MCP.PolicyEvent`
  rows — the persisted counterpart of the live events PolicyEngine
  broadcasts over PubSub. `record/1` is the write side, called from
  PolicyEngine after a verdict is already final; `list/1` is the read
  side, used by the log browser for paged, filtered queries.
  """

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{Event, PolicyEvent}
  alias PhoenixElxirBeam.Repo

  @default_page_size 25

  @doc "Persists a `PhoenixElxirBeam.MCP.Event` as a durable log row."
  def record(%Event{} = event) do
    %PolicyEvent{}
    |> PolicyEvent.changeset(%{
      event_id: event.id,
      session_id: event.session_id,
      scenario: event.scenario && to_string(event.scenario),
      server_id: event.server_id,
      tool_name: event.tool_name,
      tags: Enum.map(event.tags, &to_string/1),
      status: to_string(event.status),
      reason: event.reason,
      occurred_at: event.timestamp
    })
    |> Repo.insert()
  end

  @doc """
  Pages through the log, most recent first.

  Accepted filters (all optional):

    * `:from` / `:to` — `DateTime`, inclusive bounds on `occurred_at`.
    * `:status` — `"ok"`, `"blocked"`, or any other status string; omit
      or pass `"all"` for no filter.
    * `:server_id` — exact match; omit or pass `"all"` for no filter.
    * `:page` — 1-indexed, defaults to 1.
    * `:page_size` — defaults to #{@default_page_size}.

  Returns `%{entries:, page:, page_size:, total_count:, total_pages:}`.
  """
  def list(filters \\ %{}) do
    page = max(Map.get(filters, :page, 1), 1)
    page_size = Map.get(filters, :page_size, @default_page_size)

    base = filtered_query(filters)
    total_count = Repo.aggregate(base, :count, :id)
    total_pages = max(ceil_div(total_count, page_size), 1)

    entries =
      base
      |> order_by(desc: :occurred_at)
      |> limit(^page_size)
      |> offset(^((page - 1) * page_size))
      |> Repo.all()

    %{
      entries: entries,
      page: page,
      page_size: page_size,
      total_count: total_count,
      total_pages: total_pages
    }
  end

  @doc "Every distinct `server_id` seen in the log, for populating a filter."
  def distinct_server_ids do
    PolicyEvent
    |> where([e], not is_nil(e.server_id))
    |> distinct(true)
    |> select([e], e.server_id)
    |> order_by([e], asc: e.server_id)
    |> Repo.all()
  end

  defp filtered_query(filters) do
    PolicyEvent
    |> filter_from(Map.get(filters, :from))
    |> filter_to(Map.get(filters, :to))
    |> filter_status(Map.get(filters, :status))
    |> filter_server(Map.get(filters, :server_id))
  end

  defp filter_from(query, nil), do: query
  defp filter_from(query, %DateTime{} = from), do: where(query, [e], e.occurred_at >= ^from)

  defp filter_to(query, nil), do: query
  defp filter_to(query, %DateTime{} = to), do: where(query, [e], e.occurred_at <= ^to)

  defp filter_status(query, status) when status in [nil, "", "all"], do: query
  defp filter_status(query, status), do: where(query, [e], e.status == ^status)

  defp filter_server(query, server_id) when server_id in [nil, "", "all"], do: query
  defp filter_server(query, server_id), do: where(query, [e], e.server_id == ^server_id)

  defp ceil_div(a, b), do: div(a + b - 1, b)
end
