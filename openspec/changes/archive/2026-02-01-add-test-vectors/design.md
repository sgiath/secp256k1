## Context

The secp256k1 library has minimal test coverage (4 tests total). The upstream bitcoin-core/secp256k1 C library includes comprehensive test vectors from multiple sources:

- BIP-340: Official Schnorr signature test vectors (19 cases)
- Wycheproof: Google's cryptographic testing project for ECDSA (463 cases)
- BIP-327: MuSig2 multi-signature test vectors

These vectors test edge cases, invalid inputs, and cryptographic correctness that would be difficult to construct manually.

## Goals / Non-Goals

**Goals:**

- Add ~457 new tests using standard cryptographic test vectors
- Runtime loading of vector files (no code generation)
- Support three vector formats: CSV (BIP-340), JSON (Wycheproof, MuSig2)
- Descriptive test names including vector comments
- Filter Wycheproof tests to skip DER-encoding-specific cases (library uses compact signatures)

**Non-Goals:**

- Adding new library functionality or API changes
- Testing MuSig partial signing (requires API additions for deterministic nonces)
- Supporting DER-encoded signatures in the library itself

## Decisions

### Decision 1: Runtime vector loading vs code generation

**Choice:** Runtime loading at test compilation time

**Alternatives considered:**

- Code generation via Mix task: More complex infrastructure, generated code needs review
- Manual copy-paste: Tedious for 463 Wycheproof vectors, error-prone updates

**Rationale:** Runtime loading is simplest. Elixir's compile-time `for` comprehension generates test cases from loaded data. Vector files can be updated by replacing files.

### Decision 2: Vector file storage

**Choice:** Commit vector files to `test/vectors/` with README attribution

**Alternatives considered:**

- Download at test time: Network dependency, reproducibility issues
- Symlink to c_src: Couples to C library structure, MuSig needs conversion anyway

**Rationale:** Committed files ensure reproducible tests, work offline, and allow controlled updates.

### Decision 3: Wycheproof filtering strategy

**Choice:** Skip tests with flags: BerEncodedSignature, InvalidEncoding, InvalidTypesInSignature

**Alternatives considered:**

- Add DER support to library: Out of scope, library uses compact format
- Convert all tests: DER-specific tests don't translate meaningfully

**Rationale:** These tests verify DER parsing robustness. Since the library uses 64-byte compact signatures, these tests aren't applicable. The ~50 skipped tests test encoding, not cryptography.

### Decision 4: JSON parsing

**Choice:** Built-in `JSON` module (Elixir 1.18+)

**Alternatives considered:**

- Jason: External dependency for test-only use

**Rationale:** Project requires Elixir 1.15+, and the built-in JSON module is available in the actual runtime (1.19.5). No need for external dependency.

### Decision 5: MuSig vector scope

**Choice:** Test only pubkey_agg and nonce_agg (no partial signing)

**Alternatives considered:**

- Add test-only NIF for secnonce_from_bytes: Security risk, adds complexity
- Skip MuSig vectors entirely: Loses valuable coverage

**Rationale:** The current API generates random nonces (correct for security), preventing deterministic testing of partial signing. Key and nonce aggregation are fully testable and cover the most common error cases.

## Risks / Trade-offs

**[Risk] Wycheproof tests may expose missing validation** → If tests fail, it reveals library gaps. This is valuable - fix the library or document the limitation.

**[Risk] MuSig JSON conversion is manual** → One-time effort. The C header structure is documented, and we only need key_agg and nonce_agg sections.

**[Trade-off] Skipping DER tests reduces coverage** → Acceptable since library doesn't support DER. The skipped tests wouldn't provide value.

**[Trade-off] Compile-time test generation** → Test count is fixed at compile time. If vectors change, recompilation is needed. This is standard ExUnit behavior.
