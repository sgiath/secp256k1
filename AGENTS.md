# PROJECT KNOWLEDGE BASE

## OVERVIEW

Elixir bindings for bitcoin-core `secp256k1` v0.7.1. The public Elixir facade delegates to feature modules, and the private `Secp256k1.NIF` module loads the single `priv/secp256k1_nif.so` shared object.

## STRUCTURE

```text
./
|-- lib/              # Elixir facade, feature wrappers, size guards
|-- c_src/            # first-party C NIF glue; see c_src/AGENTS.md
|-- test/             # ExUnit helpers, protocol tests, vectors; see test/AGENTS.md
|-- docs/             # ExDoc source pages, not generated output
|-- Makefile          # fetch/configure/build upstream secp256k1 + one NIF .so
`-- usage-rules.md    # user-facing API rules and common mistakes
```

## WHERE TO LOOK

| Task           | Location                                          | Notes                                          |
| -------------- | ------------------------------------------------- | ---------------------------------------------- |
| Public API     | `lib/secp256k1.ex`                                | User-facing facade and typedocs                |
| ECDSA          | `lib/secp256k1/ecdsa.ex`, `c_src/ecdsa.c`         | Compact 64-byte signatures, compressed pubkeys |
| Schnorr/BIP340 | `lib/secp256k1/schnorr.ex`, `c_src/schnorrsig.c`  | 32-byte x-only pubkeys                         |
| ECDH           | `lib/secp256k1/ecdh.ex`, `c_src/ecdh.c`           | libsecp256k1 default hashed shared secret      |
| X-only keys    | `lib/secp256k1/extrakeys.ex`, `c_src/extrakeys.c` | seckey -> x-only pubkey                        |
| MuSig2         | `lib/secp256k1/musig.ex`, `c_src/musig.c`         | Experimental resource-backed protocol          |
| Guards         | `lib/secp256k1/guards.ex`                         | Size checks only; C still validates            |
| Tests          | `test/AGENTS.md`                                  | Helpers, vectors, subprocess patterns          |
| Private NIF    | `lib/secp256k1/nif.ex`, `c_src/nif.c`             | Private loader and unified NIF entrypoints     |
| Native state   | `c_src/utils.h`, `c_src/utils.c`                  | Per-instance context and resource state        |
| Native build   | `Makefile`, `mix.exs`                             | `elixir_make` invokes Makefile                 |
| Docs           | `README.md`, `docs/*.md`, `usage-rules.md`        | Edit source docs; ignore generated `doc/`      |

## CODE MAP

| Symbol                | Type        | Location                       | Role                                                 |
| --------------------- | ----------- | ------------------------------ | ---------------------------------------------------- |
| `Secp256k1`           | module      | `lib/secp256k1.ex`             | Public facade: keypair, pubkey, ECDSA, Schnorr, ECDH |
| `Secp256k1.Guards`    | module      | `lib/secp256k1/guards.ex`      | Shared binary-size guards                            |
| `Secp256k1.MuSig`     | module      | `lib/secp256k1/musig.ex`       | Process-local resource API for MuSig2                |
| `load/upgrade/unload` | C callbacks | `c_src/nif.c`, `c_src/utils.c` | `priv_data` state allocation and lifecycle           |
| `secnonce_wrapper`    | C resource  | `c_src/musig.c`                | Mutexed one-use secret nonce resource                |

## CONVENTIONS

- App/package name is `:lib_secp256k1`; Elixir namespace is `Secp256k1`.
- Top-level API delegates to `Secp256k1.*` feature modules. Feature modules are pure wrappers with shape guards; only private `Secp256k1.NIF` has `@on_load` and loads `priv/secp256k1_nif`.
- Use `Secp256k1.Guards` before calling NIF stubs. Guards are cheap binary-size prechecks, not full cryptographic validation.
- NIF stubs return `:erlang.nif_error({:error, :not_loaded})` until native code is loaded.
- Feature guard shape failures raise `FunctionClauseError`; valid-shape invalid content reaches the NIF and raises `ArgumentError` through `enif_make_badarg`. Operation, allocation, and crypto failures return `{:error, reason}`.
- Formatter covers only `*.exs` and `{lib,test}/**/*.{ex,exs}`. Credo line length is 120 and intentionally disables some noisy checks.
- `mix check` runs compiler, formatter, unused deps, credo, markdown prettier, and ExUnit.
- Add an entry to `CHANGELOG.md` for every change that could be interesting to library users.

## ANTI-PATTERNS

- Never reuse MuSig2 nonces. Call `Secp256k1.MuSig.nonce_gen/5` fresh for every signing attempt.
- Never serialize, copy, or send MuSig `secnonce`, `session`, or `keyagg_cache` as if they were binaries. They are process-local NIF resources.
- Do not use custom AUX APIs (`ECDSA.sign/3`, `Schnorr.sign32/3`, `Schnorr.sign_custom/3`) unless a test vector explicitly requires it. Prefer 2-arg signers.
- Do not mix pubkey formats: ECDSA verifies compressed 33-byte pubkeys; Schnorr verifies x-only 32-byte pubkeys.
- Do not edit `c_src/secp256k1/`, `_build/`, `deps/`, `doc/`, or `priv/*.so` as source. They are fetched, generated, or build output.
- Do not weaken vector tests or delete failing cases. Fix implementation or update vectors only with provenance.

## COMMANDS

```bash
mix deps.get
mix compile
mix test
mix test test/secp256k1/ecdsa_test.exs:20
mix check
make clean
make distclean
```

## NOTES

- `Makefile` clones upstream `bitcoin-core/secp256k1` at `v0.7.1`, configures `--enable-experimental --enable-module-musig`, builds a static lib, then links one `priv/secp256k1_nif.so` from all first-party native objects.
- `ERTS_INCLUDE_DIR` must be set for native compilation; `elixir_make` usually supplies it.
- `mix clean` maps to native `distclean`, deleting fetched `c_src/secp256k1/`.
- Backlog.md MCP is the project task system. Use MCP tools for task creation/editing; do not edit backlog markdown directly.
