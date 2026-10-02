# NATIVE NIF GUIDANCE

## OVERVIEW

First-party C glue for Elixir NIFs. All first-party C sources link into one `priv/secp256k1_nif.so`; `c_src/secp256k1/` is upstream code extracted from the vendored tarball, not local source.

## WHERE TO LOOK

| Task             | Location         | Notes                                                                  |
| ---------------- | ---------------- | ---------------------------------------------------------------------- |
| State interface  | `utils.h`        | `priv_data` state, `nif_ctx(env)`, wire sizes, result/callback helpers |
| State lifecycle  | `utils.c`        | Preallocated context, randomization, destruction, errors, callbacks    |
| NIF declarations | `nifs.h`         | Unified entrypoint prototypes and MuSig resource setup                 |
| NIF registration | `nif.c`          | Callback guard wrappers, function table, load/upgrade/unload callbacks |
| Random bytes     | `random.h`       | OS-specific `fill_random`                                              |
| ECDSA            | `ecdsa.c`        | Pubkey conversion, compact sign/verify                                 |
| Schnorr          | `schnorrsig.c`   | BIP340 sign/verify, arbitrary-message signing                          |
| ECDH             | `ecdh.c`         | 32-byte hashed shared secret                                           |
| X-only keys      | `extrakeys.c`    | seckey to x-only pubkey, tweaks                                        |
| MuSig2 types     | `musig.h`        | Private wrapper structs with transcript copies, helper prototypes      |
| MuSig2 resources | `musig.c`        | Resource types, constructors, getters, cache compare, list allocation  |
| MuSig2 key agg   | `musig_keyagg.c` | `pubkey_agg`, `pubkey_get`, keyagg cache tweaks                        |
| MuSig2 nonces    | `musig_nonce.c`  | `nonce_gen`, `nonce_agg`, `nonce_process`                              |
| MuSig2 signing   | `musig_sign.c`   | `partial_sign`, `partial_sig_verify`, `partial_sig_agg`                |
| Build            | `../Makefile`    | All `c_src/*.c` -> `priv/secp256k1_nif.so`; objects depend on `*.h`    |

## CONVENTIONS

- Include `utils.h` in every first-party NIF file; MuSig files include the private `musig.h` instead, which includes `utils.h`.
- Register all C entrypoints only under `Elixir.Secp256k1.NIF` from `nif.c`. Feature C files do not define their own `ERL_NIF_INIT`. Every registered entrypoint goes through a `GUARDED_NIF(name)` wrapper; dirty-scheduler variants (`schnorr_sign_custom_dirty`, `schnorr_valid_dirty?`) reuse the same guarded implementation with `ERL_NIF_DIRTY_JOB_CPU_BOUND`. Keep `lib/secp256k1/nif.ex` stubs in sync with the table.
- libsecp256k1 illegal-argument and internal-error callbacks never print or abort. They set thread-local flags (`callback_flags_clear`, `callback_illegal_fired`, `callback_internal_fired` in `utils.h`). The NIF guard clears the flags before the call and afterwards discards the result: illegal argument raises badarg, internal error returns `{:error, "libsecp256k1 internal error"}`. An exception already raised by the NIF is returned unchanged. The callbacks are installed right after context creation, so the upstream self-test inside `secp256k1_context_preallocated_create` still reports a failure (a miscompiled library) through the upstream default error callback, which prints and aborts.
- Feature functions fetch the context with `nif_ctx(env)`, which reads the state from the NIF instance's `priv_data`.
- One `secp256k1_nif_state` and one secp256k1 context exist per loaded NIF library instance. The context lives in `ctx_memory`, allocated with `enif_alloc` and created with `secp256k1_context_preallocated_create`, so an allocation failure fails the load instead of aborting (`secp256k1_context_create` aborts). An upgrade creates fresh independent state; the old instance owns its state until its unload callback runs.
- `load` and `upgrade` publish `*priv_data` only after context setup and all MuSig resource types succeed and no libsecp256k1 callback fired during setup. Any failure destroys the fresh state with `secp256k1_nif_state_destroy`.
- Validate binary type and exact size with `enif_inspect_binary` before libsecp256k1 calls.
- Return `enif_make_badarg(env)` for invalid caller input. Return `error_result(env, "message")` for operation or libsecp256k1 failures and `allocation_failed(env)` (`{:error, :allocation_failed}`) for every BEAM binary, resource, mutex, or array allocation failure.
- Serialize into a stack buffer first, then build the output with `make_binary`; do not hand-build binaries with `enif_make_new_binary` or `enif_alloc_binary`.
- MuSig list NIFs allocate the pointer array and element array as one block with `musig_alloc_list`, which rejects `count * (ptr_size + elem_size)` overflow as an allocation failure; one `enif_free` of the pointer array frees both. Elixir guards only the outer list: an element of the wrong type or size must return badarg.
- Predicate NIFs return atoms `true` or `false`; parse failures in predicates usually return `false`.
- Use the named wire-size constants in `utils.h` (`SECKEY_SIZE`, `HASH_SIZE`, `COMPRESSED_PUBKEY_SIZE`, `MUSIG_PUBNONCE_SIZE`, ...) instead of numeric literals; add a constant there for any new fixed size.
- Functions that own secrets set `result` and `goto cleanup;` on every exit after the secret exists; a single `cleanup:` label erases the secrets and returns `result`.
- First-party C follows the repo-root `.clang-format`. Check with `clang-format --dry-run --Werror c_src/*.c c_src/*.h`; the devenv git hook and CI run the same check.
- MuSig resource types are stored in the per-instance state and opened with `ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER` so an upgraded instance can take over the established resource names.

## SECURITY RULES

- Always `secure_erase` secret keys, keypairs, nonces, randomizers, and temporary shared secrets before return or failure exit.
- MuSig `secnonce` is an Erlang resource with a mutex, `used` flag, the signer `secp256k1_pubkey` given to `nonce_gen`, and copies of the optional `msg` and keyagg `cache` given to `nonce_gen` (`has_msg`/`has_cache`). A `session` resource stores copies of the keyagg cache and message given to `nonce_process`. `nonce_gen` raises badarg when a provided seckey does not derive that pubkey. `partial_sign/4` rejects an invalid seckey or wrong-kind resource with badarg before touching the nonce, then marks the nonce used exactly once. It then erases the nonce and keypair and returns an error when the cache differs from the session's cache, the nonce's stored cache differs from the cache, the nonce's stored message differs from the session's message, or the keypair pubkey differs from the stored pubkey. Caches are compared by bytes with `keyagg_cache_equal`. `partial_sig_verify` returns `false` when the cache differs from the session's cache. Every path after claiming the nonce erases nonce bytes.
- Do not expose secret nonces, key aggregation caches, or sessions as binaries. Only public nonces, aggregate nonces, partial signatures, and final signatures are serialized. These resources are references owned by their NIF instance: any process on the same node may use them, but they cannot be serialized or used on another node.
- On load or upgrade failure after state creation, destroy the fresh state before returning failure. Do not publish partial `priv_data`.

## ANTI-PATTERNS

- Do not edit `c_src/secp256k1/` for wrapper changes. It is extracted from the vendored tarball by the Makefile.
- Do not add fallback parsing paths for malformed binaries. Reject with badarg unless the API is explicitly a boolean verifier.
- Do not print from native code or let libsecp256k1 callbacks reach stderr; record events through the callback flags.
- Do not bypass `random.h` for nonce/context randomization.

## VERIFY

```bash
mix compile
mix test test/secp256k1/musig_test.exs
mix test test/secp256k1/ecdsa_test.exs
clang-format --dry-run --Werror c_src/*.c c_src/*.h
```
