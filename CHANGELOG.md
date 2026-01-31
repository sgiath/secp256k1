# Changelog

## v0.7.1 (2026-01-31)

- Fixed unchecked `enif_alloc_binary()` return values that could cause undefined behavior under memory pressure
- Fixed memory leaks on error paths in MuSig2 NIFs

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
