defmodule Secp256k1.MixProject do
  use Mix.Project

  @version "0.7.1"

  def project do
    [
      # Library
      app: :lib_secp256k1,
      version: @version,

      # Elixir
      elixir: "~> 1.15",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),

      # Elixir make
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["distclean"],

      # Docs
      name: "secp256k1",
      source_url: "https://github.com/Sgiath/secp256k1",
      homepage_url: "https://sgiath.dev/libraries#secp256k1",
      description: """
      Library wrapping around secp256k1 Bitcoin library
      """,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # C compilation
      {:elixir_make, "~> 0.9", runtime: false},

      # Development
      {:ex_check, "~> 0.16", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.40", only: [:dev], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.4", only: [:dev], runtime: false}
    ]
  end

  defp package do
    [
      name: "lib_secp256k1",
      maintainers: ["Sgiath <secp256k1@sgiath.dev>"],
      files: ~w(lib LICENSE mix.exs README* CHANGELOG* c_src/*.[ch] Makefile),
      licenses: ["WTFPL"],
      links: %{
        "C library" => "https://github.com/bitcoin-core/secp256k1",
        "GitHub" => "https://github.com/Sgiath/secp256k1"
      }
    ]
  end

  defp docs do
    [
      authors: ["sgiath <secp256k1@sgiath.dev>"],
      main: "readme",
      api_reference: false,
      extras: [
        "README.md": [filename: "readme", title: "Overview"],
        "docs/usage.md": [filename: "usage", title: "Usage Guide"],
        "docs/musig.md": [filename: "musig", title: "MuSig Guide"],
        "CHANGELOG.md": [filename: "changelog", title: "Changelog"],
        LICENSE: [filename: "license", title: "License"]
      ],
      formatters: ["html"],
      source_ref: "v#{@version}",
      source_url: "https://github.com/Sgiath/secp256k1",
      groups_for_modules: groups_for_modules()
    ]
  end

  defp groups_for_modules do
    [
      "Private API": [Secp256k1.ECDSA, Secp256k1.Extrakeys, Secp256k1.Schnorr, Secp256k1.MuSig]
    ]
  end
end
