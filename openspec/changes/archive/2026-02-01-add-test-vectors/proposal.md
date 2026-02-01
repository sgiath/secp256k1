## Why

Current test coverage is minimal - ECDSA has 1 test, Schnorr has 1 test, MuSig has 2 tests. The upstream bitcoin-core/secp256k1 library includes comprehensive test vectors (BIP-340 Schnorr, Wycheproof ECDSA, BIP-327 MuSig2) that validate cryptographic correctness and edge cases. Adding these vectors ensures the NIF bindings behave correctly across all standard test cases.

## What Changes

- Add test vector files (CSV, JSON) committed to the repository with source attribution
- Add support modules for loading vectors and converting DER signatures to compact format
- Add new test modules that dynamically generate tests from vectors at compile time
- Expected ~457 new tests covering Schnorr, ECDSA, and MuSig functionality

## Capabilities

### New Capabilities

- `test-vectors`: Runtime loading and parsing of cryptographic test vectors (BIP-340, Wycheproof, BIP-327) with support for CSV and JSON formats, DER-to-compact signature conversion, and dynamic test generation

### Modified Capabilities

<!-- None - this change only adds test infrastructure, no changes to library behavior -->

## Impact

- Test infrastructure only - no changes to library API or behavior
- New files in `test/vectors/` (vector data files)
- New files in `test/support/` (loader modules)
- New files in `test/secp256k1/` (test modules)
- No production code changes, no breaking changes
