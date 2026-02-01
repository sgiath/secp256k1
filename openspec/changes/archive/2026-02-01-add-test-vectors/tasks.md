## 1. Vector Files

- [x] 1.1 Create `test/vectors/` directory structure
- [x] 1.2 Download BIP-340 test vectors CSV from bitcoin/bips repository
- [x] 1.3 Copy Wycheproof ECDSA JSON from c_src/secp256k1/src/wycheproof/
- [x] 1.4 Convert MuSig2 vectors from C header to JSON (key_agg and nonce_agg only)
- [x] 1.5 Create `test/vectors/README.md` with source attribution

## 2. Support Modules

- [x] 2.1 Create `test/support/vectors.ex` with `load_bip340/0` function
- [x] 2.2 Add `load_wycheproof_ecdsa/0` function with DER-flag filtering
- [x] 2.3 Add `load_musig2/0` function for MuSig2 vectors
- [x] 2.4 Create `test/support/der.ex` with `to_compact/1` function for DER conversion

## 3. BIP-340 Schnorr Tests

- [x] 3.1 Create `test/secp256k1/schnorr_bip340_test.exs` module structure
- [x] 3.2 Implement signing tests (vectors with secret_key and aux_rand)
- [x] 3.3 Implement pubkey derivation tests (vectors with secret_key)
- [x] 3.4 Implement verification tests (all vectors)

## 4. Wycheproof ECDSA Tests

- [x] 4.1 Create `test/secp256k1/ecdsa_wycheproof_test.exs` module structure
- [x] 4.2 Implement verification tests with DER-to-compact conversion
- [x] 4.3 Verify filtering excludes DER-encoding-specific test cases

## 5. MuSig2 Tests

- [x] 5.1 Create `test/secp256k1/musig_vectors_test.exs` module structure
- [x] 5.2 Implement key aggregation valid case tests
- [x] 5.3 Implement key aggregation error case tests
- [x] 5.4 Implement nonce aggregation valid case tests
- [x] 5.5 Implement nonce aggregation error case tests

## 6. Verification

- [x] 6.1 Run `mix test` and verify all new tests pass
- [x] 6.2 Run `mix check` to ensure code quality
