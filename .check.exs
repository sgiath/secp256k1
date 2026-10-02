[
  tools: [
    {:compiler, true},
    {:formatter, true},
    {:unused_deps, true},
    {:credo, true},
    {:markdown,
     command: "prettier **/*.md --check --log-level warn",
     fix: "prettier **/*.md --write --log-level warn"},
    {:ex_unit,
     command: "mix test --include expensive", retry: "mix test --include expensive --failed"}
  ]
]
