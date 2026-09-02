defmodule PhoenixElxirBeam.MCP.RateLimiterTest do
  use ExUnit.Case, async: true

  alias PhoenixElxirBeam.MCP.RateLimiter

  defp key, do: "rl-#{System.unique_integer([:positive])}"

  test "allows up to the limit, then denies with a retry-after" do
    k = key()
    opts = [max_per_window: 3, window_ms: 10_000]

    for _ <- 1..3, do: assert(:ok == RateLimiter.check(k, opts))

    assert {:error, retry_after} = RateLimiter.check(k, opts)
    assert retry_after >= 1
  end

  test "separate keys have separate budgets" do
    a = key()
    b = key()
    opts = [max_per_window: 1, window_ms: 10_000]

    assert :ok == RateLimiter.check(a, opts)
    assert {:error, _} = RateLimiter.check(a, opts)
    assert :ok == RateLimiter.check(b, opts)
  end

  test "a new window resets the count" do
    k = key()

    # window_ms: 1 rolls the window forward almost immediately
    assert :ok == RateLimiter.check(k, max_per_window: 1, window_ms: 1)
    Process.sleep(3)
    assert :ok == RateLimiter.check(k, max_per_window: 1, window_ms: 1)
  end
end
