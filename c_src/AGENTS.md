# NATIVE NIF GUIDANCE

## OVERVIEW

First-party C glue for Elixir NIFs. One `c_src/*.c` file builds to one `priv/*.so`; `c_src/secp256k1/` is fetched upstream code, not local source.

## WHERE TO LOOK

| Task           | Location       | Notes                                           |
| -------------- | -------------- | ----------------------------------------------- |
| Shared context | `utils.h`      | `ctx`, callbacks, load/upgrade/unload, errors   |
| Random bytes   | `random.h`     | OS-specific `fill_random`                       |
| ECDSA          | `ecdsa.c`      | Pubkey conversion, compact sign/verify          |
| Schnorr        | `schnorrsig.c` | BIP340 sign/verify, arbitrary-message signing   |
| ECDH           | `ecdh.c`       | 32-byte hashed shared secret                    |
| X-only keys    | `extrakeys.c`  | seckey to x-only pubkey                         |
| MuSig2         | `musig.c`      | Resources, nonce lifecycle, aggregation/signing |
| Build          | `../Makefile`  | `c_src/*.c` -> `priv/*.so`                      |

## CONVENTIONS

- Include `utils.h` in every first-party NIF file.
- Register the exact Elixir module with `ERL_NIF_INIT(Elixir.Secp256k1.<Module>, ...)`.
- Validate binary type and exact size with `enif_inspect_binary` before libsecp256k1 calls.
- Return `enif_make_badarg(env)` for invalid caller input. Return `error_result(env, "message")` for operation, allocation, or libsecp256k1 failures.
- Predicate NIFs return atoms `true` or `false`; parse failures in predicates usually return `false`.
- Use fixed wire sizes: ECDSA/Schnorr sig 64, hash/seckey/x-only/partial sig 32, compressed pubkey 33, uncompressed pubkey 65, MuSig nonce 66.
- `utils.h` creates and randomizes one secp256k1 context per loaded shared object and installs non-aborting callbacks that log to stderr.

## SECURITY RULES

- Always `secure_erase` secret keys, keypairs, nonces, randomizers, and temporary shared secrets before return or failure exit.
- MuSig `secnonce` is an Erlang resource with a mutex and `used` flag. `partial_sign/4` must mark it used once and erase nonce bytes.
- Do not expose secret nonces, key aggregation caches, or sessions as binaries. Only public nonces, aggregate nonces, partial signatures, and final signatures are serialized.
- On MuSig load/upgrade failure after context init, destroy `ctx` before returning failure.

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
