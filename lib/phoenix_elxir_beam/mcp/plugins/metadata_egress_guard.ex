defmodule PhoenixElxirBeam.MCP.Plugins.MetadataEgressGuard do
  @moduledoc """
  Denies a `:network_egress`-tagged call whose arguments target the cloud
  metadata address, loopback, or an RFC1918 private range — the SSRF-via-agent
  class: a tool is tricked into fetching `http://169.254.169.254/...` or an
  internal host, not into chaining a prior sensitive read (that's
  `PhoenixElxirBeam.MCP.Plugins.ChainExfil`'s job). Scoped to `:network_egress`
  via `tool_tags` so the pipeline only consults it for egress-tagged calls.

  Checks every URL found in the call's arguments: an IP literal is checked
  directly; a hostname is resolved (bounded by the manifest's `timeout_ms`,
  which the pipeline enforces around the whole `evaluate/2` call) and its
  resolved address is checked. A hostname that fails to resolve is allowed —
  it will simply fail at the upstream server.
  """

  @behaviour PhoenixElxirBeam.MCP.Plugin.Policy

  alias PhoenixElxirBeam.MCP.{CallContext, Decision}
  alias PhoenixElxirBeam.MCP.Plugin.Manifest

  @impl true
  def manifest do
    Manifest.normalize(%{
      plugin: %{
        name: "metadata-egress-guard",
        version: "0.1.0",
        description:
          "Blocks egress calls whose arguments target a link-local/metadata/private address."
      },
      capabilities: %{
        policy: %{
          phases: [:pre_call],
          tool_tags: [:network_egress],
          data_needs: ["call.arguments"],
          timeout_ms: 500,
          fail_mode: :fail_closed
        }
      }
    })
  end

  @impl true
  def evaluate(:pre_call, %CallContext{call: call}) do
    call
    |> Map.get(:arguments, %{})
    |> extract_hosts()
    |> Enum.find_value(&forbidden_target/1)
    |> case do
      nil -> Decision.allow()
      {host, ip_string} -> deny(host, ip_string)
    end
  end

  defp deny(host, ip_string) do
    Decision.deny(
      :high,
      "network egress blocked: target #{host} resolves to #{ip_string}, a disallowed address"
    )
  end

  # Walks every string value in the (possibly nested) arguments map/list and
  # pulls out a candidate host from any http(s) URL found in it.
  defp extract_hosts(value) when is_map(value),
    do: value |> Map.values() |> Enum.flat_map(&extract_hosts/1)

  defp extract_hosts(value) when is_list(value), do: Enum.flat_map(value, &extract_hosts/1)

  defp extract_hosts(value) when is_binary(value) do
    ~r/https?:\/\/([^\/\s:]+)/
    |> Regex.scan(value)
    |> Enum.map(fn [_, host] -> host end)
  end

  defp extract_hosts(_), do: []

  defp forbidden_target(host) do
    with {:ok, [{ip_tuple, _ttl} | _rest]} <- resolve_all(host),
         true <- forbidden_ip?(ip_tuple) do
      {host, :inet.ntoa(ip_tuple) |> to_string()}
    else
      _ -> nil
    end
  end

  @doc false
  @spec resolve_all(String.t(), (charlist() -> {:ok, [{tuple(), non_neg_integer()}]} | :error)) ::
          {:ok, [{tuple(), non_neg_integer()}]} | :error
  def resolve_all(host, resolver \\ &default_resolver/1) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, ip_tuple} -> {:ok, [{ip_tuple, 0}]}
      {:error, :einval} -> resolver.(charlist)
    end
  end

  @doc false
  @spec default_resolver(charlist()) :: {:ok, [{tuple(), non_neg_integer()}]} | :error
  def default_resolver(charlist) do
    case :inet_res.resolve(charlist, :in, :a) do
      {:ok, dns_rec} ->
        answers =
          dns_rec
          |> :inet_dns.msg(:anlist)
          |> Enum.map(fn rr ->
            {:inet_dns.rr(rr, :data), :inet_dns.rr(rr, :ttl)}
          end)

        case answers do
          [] -> :error
          _ -> {:ok, answers}
        end

      {:error, _} ->
        :error
    end
  end

  defp forbidden_ip?({169, 254, _, _}), do: true
  defp forbidden_ip?({127, _, _, _}), do: true
  defp forbidden_ip?({10, _, _, _}), do: true
  defp forbidden_ip?({172, b, _, _}) when b in 16..31, do: true
  defp forbidden_ip?({192, 168, _, _}), do: true
  defp forbidden_ip?(_), do: false
end
