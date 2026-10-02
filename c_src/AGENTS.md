# NATIVE NIF GUIDANCE

## OVERVIEW

First-party C glue for Elixir NIFs. All first-party C sources link into one `secp256k1_nif.so`, installed into `$MIX_APP_PATH/priv/`; `c_src/secp256k1/` is upstream code extracted from the vendored tarball, not local source, and `c_src/build/` holds per-app-path build output.

## WHERE TO LOOK

| Task             | Location         | Notes                                                                         |
| ---------------- | ---------------- | ----------------------------------------------------------------------------- |
| State interface  | `utils.h`        | `priv_data` state, `nif_ctx(env)`, wire sizes, result/callback/seckey helpers |
| State lifecycle  | `utils.c`        | Preallocated context, randomization, destruction, errors, callbacks           |
| NIF list         | `nifs.h`         | `SECP256K1_NIF_LIST` X-macro, entrypoint prototypes, MuSig resource setup     |
| NIF registration | `nif.c`          | Generated guard wrappers and table, fault test NIFs, load/upgrade/unload      |
| Fault injection  | `fault.h`        | Test-only fault points, allocation and live-resource counters                 |
| Random bytes     | `random.h`       | OS-specific `fill_random`                                                     |
| ECDSA            | `ecdsa.c`        | Pubkey conversion, compact sign/verify                                        |
| Schnorr          | `schnorrsig.c`   | BIP340 sign/verify, arbitrary-message signing                                 |
| ECDH             | `ecdh.c`         | 32-byte hashed shared secret                                                  |
| X-only keys      | `extrakeys.c`    | seckey to x-only pubkey, tweaks                                               |
| MuSig2 types     | `musig.h`        | Private wrapper structs with transcript copies, helper prototypes             |
| MuSig2 resources | `musig.c`        | Resource types, constructors, getters, cache compare, list allocation         |
| MuSig2 key agg   | `musig_keyagg.c` | `pubkey_agg`, `pubkey_get`, keyagg cache tweaks                               |
| MuSig2 nonces    | `musig_nonce.c`  | `nonce_gen`, `nonce_agg`, `nonce_process`                                     |
| MuSig2 signing   | `musig_sign.c`   | `partial_sign`, `partial_sig_verify`, `partial_sig_agg`                       |
| Build            | `../Makefile`    | `c_src/*.c` -> `c_src/build/<id>/` -> `$MIX_APP_PATH/priv/`; `*.h` deps       |

## CONVENTIONS

- Include `utils.h` in every first-party NIF file; MuSig files include the private `musig.h` instead, which includes `utils.h`.
- Register all C entrypoints only under `Elixir.Secp256k1.NIF` from `nif.c`. Feature C files do not define their own `ERL_NIF_INIT`. `SECP256K1_NIF_LIST` in `nifs.h` is the only list of entrypoints: a `NIF("erl_name", fn, arity, flags)` row declares `secp256k1_nif_<fn>` and `nif.c` generates its `guarded_<fn>` callback-guard wrapper and table row from it; a `DIRTY_ALIAS(...)` row registers an existing `guarded_<fn>` under another name and flags (`schnorr_sign_custom_dirty`, `schnorr_valid_dirty?` with `ERL_NIF_DIRTY_JOB_CPU_BOUND`). Adding an entrypoint takes one list row, its C function, and its stub in `lib/secp256k1/nif.ex`.
- libsecp256k1 illegal-argument and internal-error callbacks never print or abort. They set thread-local flags (`callback_flags_clear`, `callback_illegal_fired`, `callback_internal_fired` in `utils.h`). The NIF guard clears the flags before the call and afterwards discards the result: illegal argument raises badarg, internal error returns `{:error, "libsecp256k1 internal error"}`. An exception already raised by the NIF is returned unchanged. The callbacks are installed right after context creation, so the upstream self-test inside `secp256k1_context_preallocated_create` still reports a failure (a miscompiled library) through the upstream default error callback, which prints and aborts.
- Feature functions fetch the context with `nif_ctx(env)`, which reads the state from the NIF instance's `priv_data`.
- One `secp256k1_nif_state` and one secp256k1 context exist per loaded NIF library instance. The context lives in `ctx_memory`, allocated with `enif_alloc` and created with `secp256k1_context_preallocated_create`, so an allocation failure fails the load instead of aborting (`secp256k1_context_create` aborts). An upgrade creates fresh independent state; the old instance owns its state until its unload callback runs.
- `load` and `upgrade` publish `*priv_data` only after context setup and all MuSig resource types succeed and no libsecp256k1 callback fired during setup. Any failure destroys the fresh state with `secp256k1_nif_state_destroy`.
- Validate binary type and exact size with `enif_inspect_binary` before libsecp256k1 calls. Take secret keys with `get_seckey` (32-byte valid scalar) or `get_keypair` (badarg for an invalid key, erased keypair on failure) from `utils.h`.
- Return `enif_make_badarg(env)` for invalid caller input. Return `error_result(env, "message")` for operation or libsecp256k1 failures and `allocation_failed(env)` (`{:error, :allocation_failed}`) for every BEAM binary, resource, mutex, or array allocation failure.
- Serialize into a stack buffer first, then build the output with `make_binary`; do not hand-build binaries with `enif_make_new_binary` or `enif_alloc_binary`.
- MuSig list NIFs allocate the pointer array and element array as one block with `musig_alloc_list`, which rejects `count * (ptr_size + elem_size)` overflow as an allocation failure; one `enif_free` of the pointer array frees both. Elixir guards only the outer list: an element of the wrong type or size must return badarg.
- Predicate NIFs return atoms `true` or `false`; parse failures in predicates usually return `false`.
- Use the named wire-size constants in `utils.h` (`SECKEY_SIZE`, `HASH_SIZE`, `COMPRESSED_PUBKEY_SIZE`, `MUSIG_PUBNONCE_SIZE`, ...) instead of numeric literals; add a constant there for any new fixed size.
- Functions that own secrets set `result` and `goto cleanup;` (or fall through one `if`/`else if` chain) on every exit after the secret exists; a single cleanup erases the secrets and returns `result`.
- First-party C follows the repo-root `.clang-format`. Check with `clang-format --dry-run --Werror c_src/*.c c_src/*.h`; the devenv git hook and CI run the same check.
- MuSig resource types are stored in the per-instance state and opened with `ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER` under names suffixed with `MUSIG_RESOURCE_ABI` (`musig.h`), so an upgraded instance takes over live resources only from a library with the same wrapper layout. Bump `MUSIG_RESOURCE_ABI` whenever `keyagg_cache_wrapper`, `session_wrapper`, or `secnonce_wrapper` changes, or when the vendored libsecp256k1 version changes; otherwise a cross-version hot upgrade runs new destructors and accessors on old-layout memory. Hot upgrades across versions with live MuSig resources are unsupported: old resources stay with the old library and raise `ArgumentError`.
- Fault injection (`fault.h`, `fault.c`) exists only with `-DSECP256K1_NIF_FAULT_INJECTION` (`SECP256K1_NIF_FAULT_INJECTION=1` in the Makefile); normal builds contain none of it. Under the flag, `utils.h` redefines `enif_alloc`, `enif_free`, `enif_alloc_binary`, `enif_alloc_resource`, and `enif_mutex_create`, and `random.h` redefines `fill_random`, as thread-local counted fault points; call those names normally in first-party code so new call sites are covered. `musig.c` counts live resources with `FAULT_RESOURCE_LIVE` in each constructor and destructor. `nif.c` registers the test NIFs `fault_call/3`, `fault_call_with_callback/3`, and `fault_live_resources/0` (stubs in `lib/secp256k1/nif.ex`) and reads `SECP256K1_NIF_FAULT_LOAD` during `load`, aborting if a failed load leaks a first-party allocation.

## SECURITY RULES

- Always `secure_erase` secret keys, keypairs, nonces, randomizers, MuSig sessions on the stack, and temporary shared secrets before return or failure exit.
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
SECP256K1_NIF_FAULT_INJECTION=1 MIX_BUILD_PATH=_build/fault MIX_ENV=test mix test --include expensive
```
