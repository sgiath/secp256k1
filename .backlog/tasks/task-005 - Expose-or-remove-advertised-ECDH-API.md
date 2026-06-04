---
id: TASK-005
title: Expose libsecp256k1 ECDH API
status: Done
assignee:
  - Codex
created_date: '2026-06-04 14:02'
updated_date: '2026-06-04 16:55'
labels:
  - bug
dependencies: []
references:
  - 'https://www.erlang.org/doc/apps/crypto/crypto.html'
  - c_src/ecdh.c
  - c_src/secp256k1/include/secp256k1_ecdh.h
  - c_src/secp256k1/src/modules/ecdh/main_impl.h
modified_files:
  - README.md
  - docs/usage.md
  - lib/secp256k1.ex
  - lib/secp256k1/ecdh.ex
  - c_src/ecdh.c
  - mix.exs
  - test/secp256k1/ecdh_test.exs
priority: medium
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Finding: ECDH is advertised in the README and there is already a C NIF implementation, but no Elixir module or public delegate exposes it. As shipped, users cannot call the advertised feature through the library API.

Decision: expose this as the libsecp256k1 ECDH API, not generic raw ECDH. Erlang `:crypto` already provides generic ECDH via `:crypto.compute_key(:ecdh, other_pubkey, private_key, :secp256k1)`, so this library should not reimplement that generic API. However, libsecp256k1's `secp256k1_ecdh(..., NULL, NULL)` has a distinct contract: it returns the library default hashed shared secret, currently SHA256 over the compressed shared point. That behavior is specific to the upstream C library and should be available from Elixir.

Scope:
- Add `Secp256k1.ECDH.ecdh/2` backed by the existing `c_src/ecdh.c` NIF.
- Add public `Secp256k1.ecdh/2` delegate.
- Validate 32-byte secret keys and compressed/uncompressed public keys before entering the NIF.
- Document that `Secp256k1.ecdh/2` returns libsecp256k1's default hashed ECDH output. For raw generic ECDH, direct users to `:crypto.compute_key/4`.

Related ECDSA decision: keep the existing ECDSA API. Erlang `:crypto` supports ECDSA, but its API is generic OpenSSL-style ECDSA and returns DER signatures. This library exposes Bitcoin/libsecp256k1-oriented compact 64-byte signatures, direct 32-byte message-hash signing, public-key serialization helpers, and libsecp256k1 validation behavior. That is a compatible project goal, not a duplicate of `:crypto`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `Secp256k1.ECDH` exists and loads `priv/ecdh` using the repo's NIF module pattern.
- [x] #2 `Secp256k1.ecdh/2` delegates to `Secp256k1.ECDH.ecdh/2`.
- [x] #3 ECDH accepts a valid 32-byte secret key and valid compressed or uncompressed secp256k1 public key, returning a 32-byte binary.
- [x] #4 Invalid secret keys and invalid public-key binaries are rejected before or at the NIF boundary with existing project error behavior.
- [x] #5 Tests cover successful shared-secret agreement from both participant directions using fixed keys.
- [x] #6 Tests cover the known libsecp256k1 default hashed output, distinguishing it from Erlang `:crypto` raw ECDH output.
- [x] #7 Tests cover invalid secret key and invalid public key handling.
- [x] #8 README or usage docs explain that this is libsecp256k1's hashed ECDH output and point users to `:crypto.compute_key/4` for raw generic ECDH.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add `lib/secp256k1/ecdh.ex` following existing NIF module pattern; guard 32-byte seckey and 33/65-byte pubkey inputs.
2. Add `Secp256k1.ecdh/2` public delegate and docs/type wording for libsecp256k1 default hashed output.
3. Add focused ECDH tests for fixed-key agreement, known hashed output vs raw `:crypto` ECDH, and invalid inputs.
4. Update README and usage docs to show ECDH and explain when to use `:crypto.compute_key/4` instead.
5. Run focused tests, then `mix check` if available/passing.

Implementation detail: rename the registered C NIF function to `ecdh_nif/2` so `Secp256k1.ECDH.ecdh/2` can stay as the guarded Elixir wrapper before entering native code.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision note: do not remove ECDH. `:crypto` covers raw generic ECDH, but not the libsecp256k1 default hashed ECDH contract. Expose the upstream C library behavior in Elixir and document the difference. Keep ECDSA for the same reason: `:crypto` has generic ECDSA, while this library's compact signature/hash-oriented API matches libsecp256k1/Bitcoin usage.

Implemented initial ECDH wrapper, public delegate, docs, tests, and NIF registration rename for guarded Elixir API. Validation pending.

Validation passed: `mix test test/secp256k1/ecdh_test.exs --trace` and `mix check`. `mix check` reported compiler, formatter, mix_audit, credo, ex_doc, ex_unit, markdown, and unused_deps success; optional dialyzer/doctor/gettext/sobelow checks were skipped because those packages are not installed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented the missing libsecp256k1 ECDH Elixir API.

Changes:
- Added `Secp256k1.ECDH.ecdh/2` with Elixir guards for 32-byte secret keys and compressed/uncompressed public keys.
- Renamed the native NIF entry to `ecdh_nif/2` so the public Elixir `ecdh/2` wrapper validates shape before entering native code.
- Added public `Secp256k1.ecdh/2` delegate and updated type/docs wording to call out libsecp256k1's default hashed ECDH output.
- Added focused ECDH tests using fixed secp256k1 keys for bidirectional agreement, compressed/uncompressed pubkeys, public delegate behavior, invalid inputs, and the distinction from raw `:crypto.compute_key/4` ECDH.
- Updated README and usage docs to explain `Secp256k1.ecdh/2` versus generic raw Erlang/OpenSSL ECDH.
- Added `Secp256k1.ECDH` to ExDoc's private API module group.

Validation:
- `mix test test/secp256k1/ecdh_test.exs --trace`
- `mix check`

Residual risk: none known. The ECDH output contract is intentionally tied to libsecp256k1's documented default hash function, currently SHA256 over the compressed shared point.
<!-- SECTION:FINAL_SUMMARY:END -->
