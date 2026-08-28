defmodule PhoenixElxirBeam.MCP.EventLog do
  @moduledoc """
  Durable storage and querying for `PhoenixElxirBeam.MCP.PolicyEvent`
  rows — the persisted counterpart of the live events PolicyEngine
  broadcasts over PubSub, wrapped as the `event-log` `AuditSink`
  (`PhoenixElxirBeam.MCP.Plugins.EventLogSink`). `record/1` is the write
  side; `list/1` is the read side, used by the log browser.

  Rows form a hash chain: `record/1` reads the previous row's `hash` and
  stores `hash = sha256(prev_hash <> canonical(row))`. `verify_chain/0`
  replays the whole log and reports the first tampered or missing row.
  This is only sound because every write goes through the single
  `PhoenixElxirBeam.MCP.PolicyEngine` GenServer, serially.
  """

  import Ecto.Query

  alias PhoenixElxirBeam.MCP.{AuditEvent, PolicyEvent}
  alias PhoenixElxirBeam.Repo

  @default_page_size 25

  # Fields covered by the chain hash (everything meaningful except the
  # chain columns themselves and the row id / inserted_at).
  @hashed_keys ~w(event_id session_id scenario server_id tool_name tags status
                  reason occurred_at decisions findings)a

  @doc "Persists an `AuditEvent` as a durable, hash-chained log row."
  def record(%AuditEvent{} = event) do
    attrs = base_attrs(event)
    prev = last_hash()
    hash = chain_hash(prev, attrs)

    %PolicyEvent{}
    |> PolicyEvent.changeset(Map.merge(attrs, %{prev_hash: prev, hash: hash}))
    |> Repo.insert()
  end

  @doc "The `hash` of the most recent row, or `nil` for an empty log."
  def last_hash do
    PolicyEvent
    |> order_by(desc: :id)
    |> limit(1)
    |> select([e], e.hash)
    |> Repo.one()
  end

  @doc """
  Replays the log in insert order, recomputing each row's `hash` from the
  previous row's. Returns `:ok`, or `{:error, %{event_id:, occurred_at:}}`
  for the first row whose stored `prev_hash` / `hash` doesn't line up — i.e.
  a row was altered, inserted, or deleted.

  Rows written before the chain migration (`hash IS NULL`) are pre-chain and
  skipped; verification starts at the first hashed row.
  """
  @spec verify_chain() :: :ok | {:error, %{event_id: String.t(), occurred_at: DateTime.t()}}
  def verify_chain do
    PolicyEvent
    |> order_by(asc: :id)
    |> Repo.all()
    |> Enum.drop_while(&is_nil(&1.hash))
    |> Enum.reduce_while({:ok, nil}, fn row, {:ok, prev} ->
      expected = chain_hash(prev, row_attrs(row))

      if row.prev_hash == prev and row.hash == expected do
        {:cont, {:ok, row.hash}}
      else
        {:halt, {:error, %{event_id: row.event_id, occurred_at: row.occurred_at}}}
      end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp base_attrs(%AuditEvent{} = e) do
    %{
      event_id: e.event_id,
      session_id: e.session_id,
      scenario: e.scenario && to_string(e.scenario),
      server_id: e.server_id,
      tool_name: e.tool_name,
      tags: Enum.map(e.tags, &to_string/1),
      status: to_string(e.status),
      reason: e.reason,
      occurred_at: e.occurred_at,
      decisions: Enum.map(e.decisions, &to_plain/1),
      findings: Enum.map(e.findings, &to_plain/1)
    }
  end

  defp row_attrs(%PolicyEvent{} = r) do
    %{
      event_id: r.event_id,
      session_id: r.session_id,
      scenario: r.scenario,
      server_id: r.server_id,
      tool_name: r.tool_name,
      tags: r.tags,
      status: r.status,
      reason: r.reason,
      occurred_at: r.occurred_at,
      decisions: r.decisions,
      findings: r.findings
    }
  end

  defp chain_hash(prev, attrs) do
    payload = attrs |> Map.take(@hashed_keys) |> canonical_json()
    digest = :crypto.hash(:sha256, "#{prev}\n#{payload}")
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  # Deterministic JSON: keys sorted recursively, atoms/DateTimes stringified.
  defp canonical_json(term), do: term |> canonicalize() |> Jason.encode!()

  defp canonicalize(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), canonicalize(v)} end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Jason.OrderedObject.new()
  end

  defp canonicalize(list) when is_list(list), do: Enum.map(list, &canonicalize/1)

  defp canonicalize(atom) when is_atom(atom) and not is_nil(atom) and not is_boolean(atom),
    do: to_string(atom)

  defp canonicalize(other), do: other

  # Struct/atom-free plain data for JSON columns.
  defp to_plain(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp to_plain(%_{} = struct), do: struct |> Map.from_struct() |> to_plain()

  defp to_plain(map) when is_map(map),
    do: Map.new(map, fn {k, v} -> {to_string(k), to_plain(v)} end)

  defp to_plain(list) when is_list(list), do: Enum.map(list, &to_plain/1)

  defp to_plain(atom) when is_atom(atom) and not is_nil(atom) and not is_boolean(atom),
    do: to_string(atom)

  defp to_plain(other), do: other

  @doc """
  Pages through the log, most recent first.

  Accepted filters (all optional):

    * `:from` / `:to` — `DateTime`, inclusive bounds on `occurred_at`.
    * `:status` — `"ok"`, `"blocked"`, or any other status string; omit
      or pass `"all"` for no filter.
    * `:server_id` — exact match; omit or pass `"all"` for no filter.
    * `:page` — 1-indexed, defaults to 1.
    * `:page_size` — defaults to #{@default_page_size}.
    * `:sort_by` — `"time"` (default), `"status"`, or `"who"` (server_id, then tool_name).
    * `:sort_dir` — `"asc"` or `"desc"` (default).

  Returns `%{entries:, page:, page_size:, total_count:, total_pages:}`.
  """
  def list(filters \\ %{}) do
    page = max(Map.get(filters, :page, 1), 1)
    page_size = Map.get(filters, :page_size, @default_page_size)
    sort_by = Map.get(filters, :sort_by, "time")
    sort_dir = Map.get(filters, :sort_dir, "desc")

    base = filtered_query(filters)
    total_count = Repo.aggregate(base, :count, :id)
    total_pages = max(ceil_div(total_count, page_size), 1)

    entries =
      base
      |> apply_sort(sort_by, sort_dir)
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

  defp apply_sort(query, "status", "asc"),
    do: order_by(query, [e], asc: e.status, desc: e.occurred_at)

  defp apply_sort(query, "status", _desc),
    do: order_by(query, [e], desc: e.status, desc: e.occurred_at)

  defp apply_sort(query, "who", "asc"),
    do: order_by(query, [e], asc: e.server_id, asc: e.tool_name)

  defp apply_sort(query, "who", _desc),
    do: order_by(query, [e], desc: e.server_id, desc: e.tool_name)

  defp apply_sort(query, _time, "asc"), do: order_by(query, [e], asc: e.occurred_at)
  defp apply_sort(query, _time, _desc), do: order_by(query, [e], desc: e.occurred_at)

  defp ceil_div(a, b), do: div(a + b - 1, b)
end
