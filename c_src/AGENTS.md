# NATIVE NIF GUIDANCE

## OVERVIEW

First-party C glue for Elixir NIFs. All first-party C sources link into one `priv/secp256k1_nif.so`; `c_src/secp256k1/` is fetched upstream code, not local source.

## WHERE TO LOOK

| Task             | Location       | Notes                                                  |
| ---------------- | -------------- | ------------------------------------------------------ |
| State interface  | `utils.h`      | `priv_data` state, `nif_ctx(env)`, shared declarations |
| State lifecycle  | `utils.c`      | Context creation, randomization, destruction, errors   |
| NIF declarations | `nifs.h`       | Unified entrypoint prototypes and MuSig resource setup |
| NIF registration | `nif.c`        | One function table and load/upgrade/unload callbacks   |
| Random bytes     | `random.h`     | OS-specific `fill_random`                              |
| ECDSA            | `ecdsa.c`      | Pubkey conversion, compact sign/verify                 |
| Schnorr          | `schnorrsig.c` | BIP340 sign/verify, arbitrary-message signing          |
| ECDH             | `ecdh.c`       | 32-byte hashed shared secret                           |
| X-only keys      | `extrakeys.c`  | seckey to x-only pubkey                                |
| MuSig2           | `musig.c`      | Resources, nonce lifecycle, aggregation/signing        |
| Build            | `../Makefile`  | All `c_src/*.c` -> `priv/secp256k1_nif.so`             |

## CONVENTIONS

- Include `utils.h` in every first-party NIF file.
- Register all C entrypoints only under `Elixir.Secp256k1.NIF` from `nif.c`. Feature C files do not define their own `ERL_NIF_INIT`.
- Feature functions fetch the context with `nif_ctx(env)`, which reads the state from the NIF instance's `priv_data`.
- One `secp256k1_nif_state` and one secp256k1 context exist per loaded NIF library instance. An upgrade creates fresh independent state; the old instance owns its state until its unload callback runs.
- `load` and `upgrade` publish `*priv_data` only after context setup and all MuSig resource types succeed. Any failure destroys the fresh state with `secp256k1_nif_state_destroy`.
- Validate binary type and exact size with `enif_inspect_binary` before libsecp256k1 calls.
- Return `enif_make_badarg(env)` for invalid caller input. Return `error_result(env, "message")` for operation, allocation, or libsecp256k1 failures.
- Predicate NIFs return atoms `true` or `false`; parse failures in predicates usually return `false`.
- Use fixed wire sizes: ECDSA/Schnorr sig 64, hash/seckey/x-only/partial sig 32, compressed pubkey 33, uncompressed pubkey 65, MuSig nonce 66.
- MuSig resource types are stored in the per-instance state and opened with `ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER` so an upgraded instance can take over the established resource names.

## SECURITY RULES

- Always `secure_erase` secret keys, keypairs, nonces, randomizers, and temporary shared secrets before return or failure exit.
- MuSig `secnonce` is an Erlang resource with a mutex and `used` flag. `partial_sign/4` must mark it used once and erase nonce bytes.
- Do not expose secret nonces, key aggregation caches, or sessions as binaries. Only public nonces, aggregate nonces, partial signatures, and final signatures are serialized. These resource values are process-local and owned by their NIF instance.
- On load or upgrade failure after state creation, destroy the fresh state before returning failure. Do not publish partial `priv_data`.

## ANTI-PATTERNS

- Do not edit `c_src/secp256k1/` for wrapper changes. It is cloned from upstream `bitcoin-core/secp256k1` by the Makefile.
- Do not add fallback parsing paths for malformed binaries. Reject with badarg unless the API is explicitly a boolean verifier.
- Do not allocate BEAM binaries before all cheap validation succeeds unless every failure path releases them.
- Do not bypass `random.h` for nonce/context randomization.

## VERIFY

```bash
mix compile
mix test test/secp256k1/musig_test.exs
mix test test/secp256k1/ecdsa_test.exs
```
