# Changelog

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
