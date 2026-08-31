defmodule PhoenixElxirBeam.MCP.TagInference do
  @moduledoc """
  Name/description heuristics that suggest policy tags for a freshly discovered
  tool (M4.2). Suggestions are surfaced on the dashboard for an operator to
  accept — they are **never** applied automatically and never enforced.
  `PhoenixElxirBeam.MCP.Plugins.UnclassifiedGuard` gates calls on the operator's
  assigned `tags`, not on these.

  The proxy has two tags today:

    * `:sensitive_read` — the tool returns credentials / config / private data.
    * `:network_egress` — the tool sends data somewhere the operator can't see.
  """

  @sensitive_read ~r/(secret|credential|token|passwd|password|api[_\- ]?key|access[_\- ]?key|private[_\- ]?key|\bssh\b|dotenv|vault|keychain|read[_\- ]?secret|get[_\- ]?config|read[_\- ]?config|\benv\b|environment variable)/i

  @network_egress ~r/(https?:?\/?\/?|\bfetch|\bcurl|webhook|\bpost\b|posts |\bsend|upload|publish|\bemail|\bsmtp|\bslack|discord|telegram|\bsms\b|\bnotify|outbound|egress|endpoint|\burl\b|api[_\- ]?call|http request)/i

  @doc "Suggested tags for a tool. `[]` when nothing matches."
  @spec infer(String.t() | nil, String.t() | nil) :: [atom()]
  def infer(name, description) do
    haystack = String.downcase(to_string(name) <> " " <> to_string(description))

    []
    |> add_if(:sensitive_read, Regex.match?(@sensitive_read, haystack))
    |> add_if(:network_egress, Regex.match?(@network_egress, haystack))
  end

  defp add_if(tags, tag, true), do: [tag | tags]
  defp add_if(tags, _tag, _), do: tags
end
