# PROJECT KNOWLEDGE BASE

## OVERVIEW

Elixir bindings for bitcoin-core `secp256k1` v0.7.1. The public Elixir facade delegates to feature modules, and the private `Secp256k1.NIF` module loads the single `secp256k1_nif.so` shared object from the app's `priv/` build directory.

## STRUCTURE

```text
./
|-- lib/              # Elixir facade, feature wrappers, size guards
|-- c_src/            # first-party C NIF glue; see c_src/AGENTS.md
|-- test/             # ExUnit helpers, protocol tests, vectors; see test/AGENTS.md
|-- docs/             # Livebook guides (*.livemd) used as ExDoc extras, README banner + its generator; not generated output
|-- .clang-format     # style for first-party C (c_src/*.c, c_src/*.h)
|-- Makefile          # verify/extract vendored secp256k1 tarball + build one NIF .so
`-- usage-rules.md    # user-facing API rules and common mistakes
```

## WHERE TO LOOK

| Task           | Location                                          | Notes                                                                            |
| -------------- | ------------------------------------------------- | -------------------------------------------------------------------------------- |
| Public API     | `lib/secp256k1.ex`                                | User-facing facade and typedocs                                                  |
| ECDSA          | `lib/secp256k1/ecdsa.ex`, `c_src/ecdsa.c`         | Compact 64-byte signatures, 33/65-byte pubkeys                                   |
| Schnorr/BIP340 | `lib/secp256k1/schnorr.ex`, `c_src/schnorrsig.c`  | 32-byte x-only pubkeys                                                           |
| ECDH           | `lib/secp256k1/ecdh.ex`, `c_src/ecdh.c`           | libsecp256k1 default hashed shared secret                                        |
| X-only keys    | `lib/secp256k1/extrakeys.ex`, `c_src/extrakeys.c` | seckey -> x-only pubkey                                                          |
| MuSig2         | `lib/secp256k1/musig.ex`, `c_src/musig.c`         | Experimental resource-backed protocol                                            |
| Guards         | `lib/secp256k1/guards.ex`                         | Size checks only; C still validates                                              |
| Tests          | `test/AGENTS.md`                                  | Helpers, vectors, subprocess patterns                                            |
| Private NIF    | `lib/secp256k1/nif.ex`, `c_src/nif.c`             | Private loader; entrypoints listed once in `c_src/nifs.h` (`SECP256K1_NIF_LIST`) |
| Native state   | `c_src/utils.h`, `c_src/utils.c`                  | Per-instance context, resource state, seckey helpers                             |
| Native build   | `Makefile`, `mix.exs`                             | `elixir_make` invokes Makefile                                                   |
| Docs           | `README.md`, `docs/*.livemd`, `usage-rules.md`    | Edit source docs; ignore generated `doc/`                                        |

## CODE MAP

| Symbol                | Type        | Location                       | Role                                                 |
| --------------------- | ----------- | ------------------------------ | ---------------------------------------------------- |
| `Secp256k1`           | module      | `lib/secp256k1.ex`             | Public facade: keypair, pubkey, ECDSA, Schnorr, ECDH |
| `Secp256k1.Guards`    | module      | `lib/secp256k1/guards.ex`      | Shared binary-size guards                            |
| `Secp256k1.MuSig`     | module      | `lib/secp256k1/musig.ex`       | Resource-backed experimental MuSig2 API              |
| `load/upgrade/unload` | C callbacks | `c_src/nif.c`, `c_src/utils.c` | `priv_data` state allocation and lifecycle           |
| `secnonce_wrapper`    | C resource  | `c_src/musig.h`                | One-use secret nonce bound to signer key, msg, cache |
| `session_wrapper`     | C resource  | `c_src/musig.h`                | Session plus the cache and msg it was processed from |

## CONVENTIONS

- App/package name is `:lib_secp256k1`; Elixir namespace is `Secp256k1`.
- Top-level API delegates to `Secp256k1.*` feature modules, using `defdelegate` for pure forwarders. Feature modules are pure wrappers with shape guards; only private `Secp256k1.NIF` has `@on_load` and loads `priv/secp256k1_nif`.
- Use `Secp256k1.Guards` before calling NIF stubs. Guards are cheap binary-size prechecks, not full cryptographic validation. MuSig wire formats use the named guards `is_musig_pubnonce/1`, `is_musig_aggnonce/1`, `is_musig_partial_sig/1`, and `is_musig_nonce_extra/1`; do not use literal `is_bin_size(x, 66|32)` for them.
- NIF stubs return `:erlang.nif_error({:error, :not_loaded})` until native code is loaded.
- Error contract (documented for users in the `Secp256k1` moduledoc and `usage-rules.md`; keep all three in sync):
  - Guard shape failures (wrong type or binary size) raise `FunctionClauseError`; `valid_seckey?/1` and `valid_pubkey?/1` (facade and `Extrakeys`) return `false` for any term instead. MuSig `pubkey_agg/1`, `nonce_agg/1`, and `partial_sig_agg/2` guard only the non-empty outer list; a list element of the wrong type or size raises `ArgumentError` from C.
  - Right-sized invalid secret scalars, malformed DER, unparsable compact signatures in DER serialization/normalization, wrong-kind or stale MuSig resources, and unparsable MuSig pubkeys/nonces/partial signatures raise `ArgumentError` through `enif_make_badarg`. So does a `MuSig.nonce_gen/2` `:seckey` that does not derive its pubkey, and an unknown `nonce_gen/2` option key; a wrong-shaped `nonce_gen/2` option value raises `FunctionClauseError`.
  - Malformed public-key encodings in ECDH, pubkey conversion, and pubkey tweaking return `{:error, reason}`.
  - Boolean predicates (`*valid?`, `*_check`) return `false` for invalid content. `MuSig.partial_sig_verify/5` returns `false` only for non-verifying signatures or a cache other than the session's, and raises for unparsable arguments.
  - Operation failures return `{:error, reason}` with a binary reason. `MuSig.partial_sign/4` transcript mismatches (`"keyagg cache does not match session"`, `"secnonce was generated for a different keyagg cache"`, `"secnonce was generated for a different message"`, `"secret key does not match secnonce public key"`) are operation failures and consume the nonce. `MuSig.nonce_gen/2` returns `{:error, "RNG failed"}` when the OS RNG fails. Every native allocation failure returns `{:error, :allocation_failed}`; `MuSig.partial_sign/4` can return it only after signing, when the result binary cannot be allocated, and that also consumes the nonce.
  - Every NIF is wrapped by a libsecp256k1 callback guard: the illegal-argument callback raises `ArgumentError`, the internal-error callback returns `{:error, "libsecp256k1 internal error"}`. Neither prints to stderr. Exception: libsecp256k1's self-test runs at NIF load before the callbacks are installed; on a miscompiled library it prints and aborts through the upstream default error callback.
  - Exception reports carry call arguments (`FunctionClauseError` lists them; NIF exception stacktraces include them), so they can contain secrets. User docs warn not to log them unredacted; keep this warning in the moduledoc and `usage-rules.md`.
- Formatter covers only `*.exs` and `{lib,test}/**/*.{ex,exs}`. Credo line length is 98 and intentionally disables some noisy checks.
- `mix check` runs compiler, formatter, unused deps, credo, markdown prettier, and ExUnit including `:expensive` tests. Plain `mix test` excludes `:expensive`.
- Add an entry to `CHANGELOG.md` for every change that could be interesting to library users. Do not add test or docs changes to the changelog.
- Follow upstream `libsecp256k1` instructions, docs, and examples in `c_src/secp256k1/`.

## ANTI-PATTERNS

- Never reuse MuSig2 nonces. Call `Secp256k1.MuSig.nonce_gen/2` fresh for every signing attempt.
- Pass `:msg` and `:cache` to `Secp256k1.MuSig.nonce_gen/2` when known; without them, `partial_sign/4` cannot check them against the session.
- Never persist or send MuSig `secnonce`, `session`, or `keyagg_cache` to another node. They are NIF resource references, usable by any process on the creating node only; `term_to_binary` keeps a handle, not their state.
- Do not use custom AUX APIs (`ECDSA.sign/3`, `Schnorr.sign32/3`, `Schnorr.sign_custom/3`) unless a test vector explicitly requires it. Prefer 2-arg signers.
- Do not mix pubkey formats: ECDSA verifies compressed 33-byte or uncompressed 65-byte pubkeys; Schnorr verifies x-only 32-byte pubkeys.
- Do not edit `c_src/secp256k1/`, `c_src/build/`, `_build/`, `deps/`, or `doc/` as source. They are extracted, generated, or build output.
- Do not add a top-level `priv/` directory. Mix would symlink it into every build path and all builds would share one NIF.
- Do not weaken vector tests or delete failing cases. Fix implementation or update vectors only with provenance.

## COMMANDS

```bash
mix deps.get
mix compile
mix test
mix test test/secp256k1/ecdsa_test.exs:20
mix check
clang-format --dry-run --Werror c_src/*.c c_src/*.h
make clean
make distclean
```

## NOTES

- `Makefile` verifies the SHA256 of the vendored `c_src/secp256k1-<version>.tar.gz` and extracts it into a unique `c_src/secp256k1.tmp.*` directory renamed into `c_src/secp256k1/`, which is never configured in place. Extraction holds the `c_src/build/extract.lock` directory lock (mkdir plus a `pid.<PID>` holder file; a dead holder's lock is broken, waiting gives up after 300 s). A build that waited reuses the tree the holder published instead of replacing it, and the stamp is `.PRECIOUS` so a failed waiter never deletes it. Each Mix app path (`MIX_APP_PATH`, set by `elixir_make`; one per `MIX_ENV`, target, ElixirLS build, or consumer project) builds in its own `c_src/build/<cksum of app path>/`: an out-of-tree upstream configure (`--enable-experimental --enable-module-musig`) and static lib, first-party objects, fingerprints, and the linked `secp256k1_nif.so`, which is then copied into `$MIX_APP_PATH/priv/` when it differs. Concurrent builds for different app paths therefore never share outputs. Objects and the `.so` are written to a per-process temp file and renamed into place. First-party objects depend on every `c_src/*.h`; objects and the `.so` also depend on the Makefile itself. Changed compilers, build flags, or the `c_src/*.c` source set trigger a rebuild through the `build-config*` fingerprints in the build directory. Upstream configure/make output goes to `libsecp256k1-{configure,make}.log` there and is printed on failure.
- Required NIF flags (`-fPIC`, the ERTS and libsecp256k1 include dirs, `-shared`, macOS `-undefined dynamic_lookup`) live in `NIF_REQUIRED_*` variables, separate from user `CFLAGS`/`CPPFLAGS`/`LDFLAGS`/`LIBS`, so `make CFLAGS=...` overrides keep them. Keep new required flags out of the user variables. Hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2` when optimizing and the compiler doesn't already define it, and `-Wl,-z,relro -Wl,-z,now` for non-Darwin targets) live in `NIF_HARDEN_*`, placed before the user flags so a later user flag can override them.
- `SECP256K1_NIF_WERROR=1` adds `-Werror` to first-party C compiles; `SECP256K1_NIF_SANITIZE=1` builds the NIF with AddressSanitizer and UBSan; `SECP256K1_NIF_FAULT_INJECTION=1` builds the test-only native fault-injection harness (`c_src/fault.h`), and the `:fault_injection` tests run only against such a NIF. All three switches are part of the build fingerprint, so toggling them rebuilds; use a separate build path to avoid rebuilding back and forth, e.g. `SECP256K1_NIF_FAULT_INJECTION=1 MIX_BUILD_PATH=_build/fault MIX_ENV=test mix test --include expensive`. Run sanitized tests with `LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 MIX_ENV=test mix test --include expensive`.
- Minimum Elixir is 1.16 (`mix.exs`). Jason is a dev/test dependency for loading JSON test vectors, because Elixir's built-in `JSON` needs 1.18. StreamData is a dev/test dependency for the property tests in `test/secp256k1/property_test.exs`; it is in `:dev` so `.formatter.exs` can `import_deps: [:stream_data]`.
- CI lives in `.github/workflows/ci.yml` (jobs `check`, `sanitizers`, `cross`, `package`), with actions pinned to commit SHAs. The `check` matrix runs Elixir 1.16-1.20 on every OTP release each supports (1.16: 24-26, 1.17 and 1.18: 25-27, 1.19: 26-28, 1.20: 27-29) on `ubuntu-24.04`, plus macOS rows for 1.16/OTP 25 and 1.20/OTP 29. Elixir 1.16 and 1.17 rows build and run `mix test --include expensive` only, because the dev tooling needs 1.17/1.18+; 1.18+ rows run `mix check`. One Linux row (1.20/OTP 29) also runs the `clang-format` gate. `sanitizers` builds with `SECP256K1_NIF_FAULT_INJECTION=1` and also runs `mix test --only fault_injection`, which fails if no fault test ran. `cross` builds the NIF for aarch64-linux-gnu (`CROSSCOMPILE=/usr/bin/aarch64-linux-gnu`, `CC=aarch64-linux-gnu-gcc`, `MIX_ENV=prod`) and checks the `.so` with `file` and `readelf`.
- First-party C is formatted by the repo-root `.clang-format`; check with `clang-format --dry-run --Werror c_src/*.c c_src/*.h` (also a devenv git hook). See `c_src/AGENTS.md`.
- `ERTS_INCLUDE_DIR` and `MIX_APP_PATH` must be set for native compilation; `elixir_make` supplies both.
- `mix clean` maps to native `distclean`, deleting every `c_src/build/` directory and the extracted `c_src/secp256k1/`. `make clean` removes only the current app path's build directory and installed NIF.
- Maintainers update the vendored release with `make vendor VERSION=vX.Y.Z`; the workflow verifies the signed upstream tag with GPG by default and requires the signing primary key to be listed in `scripts/secp256k1-release-signers.txt` (from upstream `SECURITY.md`). `--allow-unverified` is an explicit override.
