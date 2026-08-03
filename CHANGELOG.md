# Changelog

## v0.8.0 (2026-08-03)

- Ship the upstream libsecp256k1 source as a vendored tarball so user builds no longer need git or autotools
- Convert ECDSA signatures between compact and strict DER encodings and normalize high-S signatures for interoperability
- Add `Secp256k1.valid_seckey?/1` and `Secp256k1.valid_pubkey?/1` for validating externally received keys
- Convert received compressed public keys to x-only form through `Secp256k1.convert_pubkey/2` without requiring the secret key
- Expose full-key scalar tweaks for BIP-32 derivation and x-only key tweaks, parity checks, and signing keys for Taproot
- Consolidate five feature NIF shared objects into one `priv/secp256k1_nif.so`, reducing the native footprint by approximately 80% by embedding libsecp256k1 and its precomputed tables once instead of five times
- Move the secp256k1 context and MuSig resource types from C statics into per-instance `priv_data`, fixing hot-upgrade context leaks and use-after-free risks
- Add Elixir shape guards to MuSig2 public functions: malformed shapes raise `FunctionClauseError`, while valid-shape invalid content and forged resources raise `ArgumentError` from the NIF
- Remove internal `@doc false` `*_nif` stubs from feature modules without compatibility aliases
- Treat resources created by legacy per-feature NIF libraries as invalid when crossing into the consolidated library. Same-library hot upgrades preserve compatible resources through `ERL_NIF_RT_TAKEOVER`; cross-library resources are not migrated
- Run list-based MuSig2 key, nonce, and partial-signature aggregation on CPU-bound dirty schedulers
- Make invalid-sized binary arguments to stable APIs fail at public Elixir boundaries with `FunctionClauseError`
- Expose compressed and uncompressed ECDSA public-key conversion through `Secp256k1.convert_pubkey/2`
- Allow `Secp256k1.ECDSA.sign/3` to accept `nil` for deterministic RFC 6979 signatures without additional nonce data
- Accept compressed and uncompressed public keys in ECDSA signature verification
- Fix cross-compilation by applying macOS linker flags only to native builds and passing the target host triplet to Autotools ([#2](https://github.com/sgiath/secp256k1/pull/2), thanks [Kentaro Kuribayashi (@kentaro)](https://github.com/kentaro))
- Pin the fetched libsecp256k1 source to its full commit SHA and reject mismatched checkouts

## v0.7.2 (2026-06-04)

- Fix Elixir 1.20 type violations
- Make sure `ECDSA.valid?/3` and `Schnorr.valid?/3` always return a boolean
- Fix MuSig2 public nonce, aggregate nonce, and partial signature wire-size serialization to avoid returning uninitialized NIF memory tails
- Harden MuSig2 invalid-input handling by making key aggregation caches and signing sessions process-local resources instead of raw opaque binaries
- Make MuSig2 secret nonce consumption concurrency-safe so only one concurrent `partial_sign/4` call can use a secnonce resource
- Ensure Schnorr signing and x-only pubkey NIF error paths erase keypair stack data before returning
- Expose libsecp256k1's default hashed ECDH API through `Secp256k1.ecdh/2`
- Improve API documentation with ExDoc callouts explaining libsecp256k1-specific APIs versus Erlang `:crypto`

## v0.7.1 (2026-01-31)

- Fixed unchecked `enif_alloc_binary()` return values that could cause undefined behavior under memory pressure
- Fixed memory leaks on error paths in MuSig2 NIFs
- Hardened `secure_erase` to use memory barriers, preventing compiler optimization of secret wiping
- Fixed NIF hot upgrade support: context is now properly initialized and MuSig resource types are taken over
- Upgrade lib to version v0.7.1

## v0.7.0 (2025-11-22)

- Added experimental support for MuSig2 multi-signatures
- Improved security by implementing secure erasure of secrets in NIFs
- Fixed potential RNG failure handling in NIF loading
- Added comprehensive usage guides for general usage and MuSig2
- Expanded module documentation with code examples
- Added system dependency installation instructions
- Upgrade lib to version v0.7.0

## v0.6.1 (2025-03-31)

- Update dependencies
- Fix LDFLAGS on MacOS

## v0.6.0 (2024-11-08)

- Upgrade lib to version v0.6.0

## v0.5.1 (2024-10-21)

- Upgrade lib to version v0.5.1

## v0.5.0 (2024-10-20)

- Upgrade lib to version v0.5.0

## v0.4.1 (2023-12-29)

- Upgrade lib to version v0.4.1

## v0.4.0 (2023-09-05)

- Upgrade lib to version v0.4.0

## v0.3.3 (2023-06-07)

- Fixed issue with library name

## RETIRED! v0.3.2 (2023-06-07)

- Initial release on hex.pm
