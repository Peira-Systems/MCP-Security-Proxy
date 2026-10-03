defmodule PhoenixElxirBeam.MixProject do
  use Mix.Project

  def project do
    [
      app: :phoenix_elxir_beam,
      version: "0.1.0",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader],
      dialyzer: dialyzer(),
      package: package()
    ]
  end

  # Apache-2.0 with the Commons Clause restriction (see LICENSE) — not
  # published to Hex, but this keeps license metadata discoverable via
  # `mix hex.info` / tooling that reads project metadata.
  defp package do
    [
      licenses: ["Apache-2.0", "Commons-Clause"]
    ]
  end

  # PLT lives in a fixed, cacheable path so CI can restore it across runs
  # (see .github/workflows/ci.yml). :mix and :ex_unit are pulled in so the
  # aliases / test support compile clean under dialyzer. Default flag set —
  # the fire-and-forget Task style in the dashboard trips :unmatched_returns
  # by design, so that stricter flag is left off for now.
  defp dialyzer do
    [
      plt_local_path: "priv/plts",
      plt_core_path: "priv/plts",
      plt_add_apps: [:mix, :ex_unit]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {PhoenixElxirBeam.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.8.9"},
      {:phoenix_html, "~> 4.1"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, "~> 0.19"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.2.0"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:phoenix_live_dashboard, "~> 0.8.3"},
      {:esbuild, "~> 0.10", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.5", runtime: Mix.env() == :dev},
      {:heroicons,
       github: "tailwindlabs/heroicons",
       tag: "v2.2.0",
       sparse: "optimized",
       app: false,
       compile: false,
       depth: 1},
      {:daisyui,
       github: "saadeghi/daisyui",
       tag: "v5.5.20",
       sparse: "packages/bundle",
       app: false,
       compile: false,
       depth: 1},
      {:swoosh, "~> 1.16"},
      {:req, "~> 0.5"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_metrics_prometheus_core, "~> 1.1"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:dns_cluster, "~> 0.2.0"},
      {:bandit, "~> 1.5"},
      {:pbkdf2_elixir, "~> 2.2"},
      # Wasmtime NIF for the Wasm plugin sandbox (docs/adr/0003-wasm-plugin-sandbox.md,
      # docs/wasm-plugin-plan.md). Added ahead of W2's WasmRunner per the W0 spike; no
      # code depends on it yet.
      {:wasmex, "~> 0.15"},
      {:ueberauth, "~> 0.10"},
      {:ueberauth_oidcc, "~> 0.3"},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ecto.setup", "assets.setup", "assets.build", "git.hooks.install"],
      "ecto.setup": ["ecto.create", "ecto.migrate"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      "assets.setup": ["tailwind.install --if-missing", "esbuild.install --if-missing"],
      "assets.build": ["compile", "tailwind phoenix_elxir_beam", "esbuild phoenix_elxir_beam"],
      "assets.deploy": [
        "tailwind phoenix_elxir_beam --minify",
        "esbuild phoenix_elxir_beam --minify",
        "phx.digest"
      ],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      # mix mcp.rules.check (CI-only, needs a real staging DB with real
      # server registrations — see .github/workflows/rule-coverage.yml and
      # docs/superpowers/specs/2026-09-30-rule-coverage-gate-design.md)
      # deliberately isn't in this list.
      precommit: [
        "compile --warnings-as-errors",
        "deps.unlock --unused",
        "format",
        "test",
        "cmd MIX_ENV=prod mix compile --warnings-as-errors"
      ],
      # The full gate CI runs on every PR. `deps.audit` + `dialyzer` on top of
      # precommit; `format --check-formatted` instead of rewriting in place.
      ci: [
        "deps.unlock --check-unused",
        "format --check-formatted",
        "compile --warnings-as-errors",
        "deps.audit",
        "hex.audit",
        "test",
        "dialyzer"
      ]
    ]
  end
end
