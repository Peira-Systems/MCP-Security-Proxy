defmodule Mix.Tasks.Git.Hooks.Install do
  @moduledoc "Points git at the repo's checked-in hooks in scripts/git-hooks."
  @shortdoc "Installs the repo's git hooks (core.hooksPath)"

  use Mix.Task

  @hooks_path "scripts/git-hooks"

  @impl Mix.Task
  def run(_args) do
    case System.cmd("git", ["config", "core.hooksPath", @hooks_path]) do
      {_, 0} -> Mix.shell().info("git hooks installed (core.hooksPath=#{@hooks_path})")
      {output, _} -> Mix.raise("failed to set core.hooksPath: #{output}")
    end
  end
end
