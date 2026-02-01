## ADDED Requirements

### Requirement: Vector files are committed with source attribution

Test vector files SHALL be committed to the repository in `test/vectors/` with a README.md documenting the source URL, license, and any conversion notes for each vector file.

#### Scenario: Source attribution exists

- **WHEN** examining `test/vectors/README.md`
- **THEN** each vector file has documented source URL, license, and retrieval/conversion date

### Requirement: BIP-340 Schnorr vectors are loadable

The system SHALL load BIP-340 test vectors from `test/vectors/bip340.csv` and parse them into structured test data including: index, secret_key (optional), public_key, aux_rand (optional), message, signature, verification_result, and comment.

#### Scenario: Load all BIP-340 vectors

- **WHEN** calling `Vectors.load_bip340()`
- **THEN** returns a list of 19 vector maps with all fields parsed from hex to binary

#### Scenario: Empty comments use default

- **WHEN** a vector has an empty comment field
- **THEN** the comment defaults to "vector N" where N is the index

### Requirement: Wycheproof ECDSA vectors are loadable with filtering

The system SHALL load Wycheproof ECDSA vectors from `test/vectors/wycheproof_ecdsa.json`, parse them, and filter out DER-encoding-specific tests (BerEncodedSignature, InvalidEncoding, InvalidTypesInSignature flags).

#### Scenario: Load filtered Wycheproof vectors

- **WHEN** calling `Vectors.load_wycheproof_ecdsa()`
- **THEN** returns test cases excluding those with DER-encoding flags

#### Scenario: DER signatures are converted to compact format

- **WHEN** processing a Wycheproof test case
- **THEN** the DER-encoded signature is converted to 64-byte compact (r || s) format

### Requirement: MuSig2 vectors are loadable

The system SHALL load MuSig2 test vectors from `test/vectors/musig2.json` including key aggregation and nonce aggregation test cases.

#### Scenario: Load MuSig2 key aggregation vectors

- **WHEN** calling `Vectors.load_musig2()`
- **THEN** returns key_agg section with pubkeys array, valid cases, and invalid cases

#### Scenario: Load MuSig2 nonce aggregation vectors

- **WHEN** calling `Vectors.load_musig2()`
- **THEN** returns nonce_agg section with pubnonces array, valid cases, and invalid cases

### Requirement: DER to compact signature conversion

The system SHALL provide a function to extract r and s values from DER-encoded ECDSA signatures and return a 64-byte compact signature.

#### Scenario: Convert valid DER signature

- **WHEN** calling `DER.to_compact/1` with a valid DER-encoded signature hex
- **THEN** returns a 64-byte binary with r (32 bytes) concatenated with s (32 bytes)

#### Scenario: Handle variable-length r and s

- **WHEN** the DER signature has r or s with leading zeros or values less than 32 bytes
- **THEN** the output is properly padded or trimmed to exactly 32 bytes each

### Requirement: Schnorr tests generated from BIP-340 vectors

Test module SHALL generate tests from BIP-340 vectors covering: signing (when secret_key present), pubkey derivation (when secret_key present), and signature verification.

#### Scenario: Test naming includes comment

- **WHEN** a test is generated from a vector
- **THEN** the test name includes the vector index and comment (e.g., "BIP-340 #5: public key not on the curve")

#### Scenario: Signing tests verify deterministic output

- **WHEN** a vector includes secret_key and aux_rand
- **THEN** signing with those inputs produces the expected signature

#### Scenario: Verification tests check expected result

- **WHEN** running verification test
- **THEN** `Schnorr.valid?/3` returns the expected verification_result from the vector

### Requirement: ECDSA tests generated from Wycheproof vectors

Test module SHALL generate tests from filtered Wycheproof vectors verifying that `ECDSA.valid?/3` returns the expected result for each test case.

#### Scenario: Valid signatures verify successfully

- **WHEN** test case has result "valid"
- **THEN** `ECDSA.valid?/3` returns true

#### Scenario: Invalid signatures are rejected

- **WHEN** test case has result "invalid"
- **THEN** `ECDSA.valid?/3` returns false

### Requirement: MuSig tests generated from BIP-327 vectors

Test module SHALL generate tests from MuSig2 vectors covering pubkey aggregation and nonce aggregation.

#### Scenario: Valid key aggregation produces expected output

- **WHEN** aggregating pubkeys from a valid test case
- **THEN** `MuSig.pubkey_agg/1` returns the expected aggregated xonly pubkey

#### Scenario: Invalid key aggregation returns error

- **WHEN** aggregating pubkeys from an invalid test case
- **THEN** `MuSig.pubkey_agg/1` returns an error tuple

#### Scenario: Valid nonce aggregation produces expected output

- **WHEN** aggregating pubnonces from a valid test case
- **THEN** `MuSig.nonce_agg/1` returns the expected aggregated nonce
