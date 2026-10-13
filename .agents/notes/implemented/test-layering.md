# Test layering

Implemented on branch `test/layering` (from `master` at `2828e03`): commits `50d7d4d`, `c148b2a`, `e4bfed8`,
`2f2ac7f`, and the commit adding this note. The resulting layer map and the placement rule for new regression
tests are in `AGENTS.md` ("TEST LAYERS"). No change to `lib/` or `c_src/`.

## Audit findings

Measured with Elixir 1.20.4 / OTP 29 before the change: `mix test` ran 182 tests in 0.4 s and
`mix test --include expensive` ran 185 in 1.7 s. The three child-BEAM tests took 1.6 s of that, because tests in
one module run serially. No test mocked a module; the only substitution was the fault-injection build replacing
allocation and OS randomness at the C boundary. Production code already took randomness as an argument where it
mattered: each randomized signer and `keypair/1` has a deterministic form taking it from the caller.

The problems were placement and duplication:

- Facade tests repeated feature behavior (DER and normalization, tweak arithmetic, predicates, guards), while the
  only `valid_pubkey?` content checks lived in the facade test. `property_test.exs` had an example test checking
  secret-key boundaries for every feature through the facade.
- MuSig wrapper tests were split between `musig_test.exs` and `nif_behavior_test.exs`, with two copies of
  `signing_state/0` and the signing flow written out again in `musig_test.exs` and `nif_lifecycle_test.exs`.
- The crash-boundary tests started one child BEAM per probe: 7 children, about 0.25 s each.

## What changed

1. `MuSigSubprocess.run/1` runs a list of `{setup, probe}` steps in one child and marks each probe's outcome
   with its index. `musig_subprocess_test.exs` starts 3 children instead of 7. Checks: replacing a probe with a
   valid call, raising in a setup, and passing a live resource instead of a stale one each fail the test.
2. MuSig guard and forged-resource rejections live in `musig_test.exs`, the guards as one table.
   `MuSigFlow` holds `signing_state/0` and `start_signing`/`finish_signing`, the halves of `sign_with`, used by
   the 3-of-3 flow and the upgrade test. The unparsable aggregate nonce and partial signature checks were
   dropped: with a throwaway C change that accepts any unparsable input as a valid all-zero encoding, BIP-327
   `sign_error` #2-#4 and `sig_agg_error` #0 fail as the dropped test did. (A first attempt that skipped the
   parse result left the struct uninitialized and gave stack-dependent outcomes, so it proved nothing.) Removing
   the `pubkey_get/1` guard fails the guard table. `nif_behavior_test.exs` kept only its concurrency test and is
   now `concurrency_test.exs`.
3. `secp256k1_test.exs` covers `keypair/1,2`, `pubkey/2`, `convert_pubkey/2`, and one table checking that every
   delegate returns its feature function's result. The table uses secret key 6, whose public key has odd Y: with
   the earlier even-Y key, pointing `xonly_seckey_tweak_add` at `ec_seckey_tweak_add` went unnoticed. The
   `valid_pubkey?` content cases, the `valid_seckey?` boundaries 1, n - 1, 0, n, and 2^256 - 1, and 2^256 - 1
   in each feature's invalid-scalar list moved into the feature tests.

Per-test signing with n - 1 is now covered only by the property generators, which draw it with probability 1/18
per secret key.

## Results

| Run (seed 0)                                | Before                | After                     |
| ------------------------------------------- | --------------------- | ------------------------- |
| `mix test --include expensive`              | 185 tests, 1.7 s (×3) | 179 tests, 0.7-0.8 s (×3) |
| wall time of the same                       | 2.45 s                | 1.5-1.6 s                 |
| `mix test`                                  | 182 tests, 0.4 s      | 176 tests, 0.3 s          |
| `musig_subprocess_test.exs`                 | 3 tests, 1.6 s        | 3 tests, 0.7 s            |
| fault build, `mix test --include expensive` | 193 tests, 1.8 s      | 187 tests, 1.2 s          |

After move 2 the suite varied between 0.7 and 1.0 s across six runs. The floor is the three serial child BEAMs.

## Not done

- MuSig nonce randomness stays in C (`musig_nonce.c`). Supplying it from Elixir would make nonce derivation
  testable against the BIP-327 `nonce_gen` vectors, but it would turn `{:error, "RNG failed"}` into a `:crypto`
  exception and leave secret randomness on the BEAM heap without erasure. Derivation is upstream code with
  upstream tests. Decided against.
- Crash-boundary probes stay in child BEAMs: in-process, a regression would abort the whole test run.
- The dirty-scheduler dispatch in `Secp256k1.Schnorr` has no test that would fail if it were removed; the
  scheduler is not observable through the interface.
- C helpers with no reach from Elixir, such as the overflow branch of `musig_alloc_list`, have no test; a C
  unit-test layer for one branch unreachable on 64-bit targets was not added.
