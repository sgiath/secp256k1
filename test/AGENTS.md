# TEST GUIDANCE

## OVERVIEW

ExUnit tests combine doctests, module tests, compile-time protocol vectors, and MuSig resource/concurrency regression tests.

## WHERE TO LOOK

| Task             | Location                      | Notes                                    |
| ---------------- | ----------------------------- | ---------------------------------------- | --- | --- |
| Test template    | `support/case.ex`             | Imports shared hex helpers               |
| Hex helpers      | `support/format.ex`           | `d/1` decode, `e/1` encode               |
| Vector loading   | `support/vectors.ex`          | BIP340 CSV, Wycheproof JSON, MuSig2 JSON |
| DER conversion   | `support/der.ex`              | Wycheproof DER -> compact `r             |     | s`  |
| MuSig subprocess | `support/musig_subprocess.ex` | Isolates crash/argument-error probes     |
| Public API tests | `secp256k1_test.exs`          | Facade doctest and basic behavior        |
| Feature tests    | `secp256k1/*_test.exs`        | Per-module coverage                      |
| Vector data      | `vectors/`                    | Snapshot fixtures with provenance README |

## CONVENTIONS

- Use `Secp256k1Test.Case, async: true` for test modules unless a test needs shared process state.
- `Secp256k1Test.Case` imports `Secp256k1Test.Format`; use `d/1` and `e/1` for hex fixtures instead of repeating `Base.decode16!/2`.
- Vector tests bind module attributes like `@vectors Vectors.load_bip340()` and generate tests at compile time with `for vector <- @vectors do`.
- Wycheproof ECDSA tests skip `BerEncodedSignature`, `InvalidEncoding`, and `InvalidTypesInSignature`; DER conversion lives in `support/der.ex`.
- MuSig tests cover happy path, nonce reuse protection, concurrent nonce reuse, exact serialized input sizes, forged resource rejection, and subprocess argument-error regressions.
- `mix.exs` compiles `test/support` only in `:test`; do not reference test helpers from library code.

## ANTI-PATTERNS

- Do not edit `vectors/*.csv` or `vectors/*.json` casually. Treat them as upstream snapshots; update `vectors/README.md` provenance if replacing them.
- Do not weaken vector expectations to fit implementation behavior.
- Do not remove subprocess tests around formerly aborting MuSig probes; they protect BEAM crash boundaries.
- Do not inline DER/vector parsing into individual tests. Keep shared parsing in `support/`.

## COMMANDS

```bash
mix test
mix test test/secp256k1/musig_test.exs
mix test test/secp256k1/ecdsa_wycheproof_test.exs
mix test test/secp256k1/schnorr_bip340_test.exs
mix test test/secp256k1/ecdsa_test.exs:20
```
