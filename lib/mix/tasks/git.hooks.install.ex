defmodule Mix.Tasks.Git.Hooks.Install do
  @moduledoc """
  Points git at the repo's checked-in hooks in scripts/git-hooks.

  core.hooksPath is local, per-checkout git config — it lives in
  `.git/config` and is never copied by `git clone`, and a `git worktree add`
  for a separate clone (as opposed to a worktree of *this* repo) won't have
  it either. Idempotent and cheap, so it's safe to run on every
  `mix setup` and `mix precommit`, which is how a checkout that skipped
  `mix setup` still ends up protected.
  """
  @shortdoc "Installs the repo's git hooks (core.hooksPath)"

  use Mix.Task

  @hooks_path "scripts/git-hooks"
  @hook_files ~w(commit-msg pre-commit lib-watermark.sh)

  @impl Mix.Task
  def run(_args) do
    case System.cmd("git", ["config", "core.hooksPath", @hooks_path]) do
      {_, 0} -> Mix.shell().info("git hooks installed (core.hooksPath=#{@hooks_path})")
      {output, _} -> Mix.raise("failed to set core.hooksPath: #{output}")
    end

    ensure_executable()
  end

  defp ensure_executable do
    root = File.cwd!()

    Enum.each(@hook_files, fn file ->
      path = Path.join([root, @hooks_path, file])

      case File.stat(path) do
        {:ok, %File.Stat{mode: mode}} ->
          # Owner-execute bit (0o100).
          if Bitwise.band(mode, 0o100) == 0 do
            File.chmod!(path, Bitwise.bor(mode, 0o111))
            Mix.shell().info("made #{Path.relative_to(path, root)} executable")
          end

        {:error, reason} ->
          Mix.raise("git hook file missing or unreadable: #{path} (#{reason})")
      end
    end)
  end
end
