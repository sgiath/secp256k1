# Usage Rules & Quick Reference

Quick reference for `lib_secp256k1` library users. For detailed examples, see the [Usage Guide](https://lib-secp256k1.hexdocs.pm/usage.html) and [MuSig Guide](https://lib-secp256k1.hexdocs.pm/musig.html).

## Data Sizes

| Type                  | Size       | Description                       |
| --------------------- | ---------- | --------------------------------- |
| `seckey`              | 32 bytes   | Secret key (private key)          |
| `tweak`               | 32 bytes   | Big-endian scalar for key tweaks  |
| `hash`                | 32 bytes   | Message hash for ECDSA and MuSig2 |
| `compressed_pubkey`   | 33 bytes   | Standard Bitcoin pubkey format    |
| `uncompressed_pubkey` | 65 bytes   | Full pubkey with both coordinates |
| `xonly_pubkey`        | 32 bytes   | Schnorr/Taproot/Nostr format      |
| `ecdsa_sig`           | 64 bytes   | Compact ECDSA signature           |
| `ecdsa_der_sig`       | 8-72 bytes | Strict DER ECDSA signature        |
| `schnorr_sig`         | 64 bytes   | BIP-340 Schnorr signature         |

## Quick Reference

### Keypairs

```elixir
# Generate random keypair
{seckey, pubkey} = Secp256k1.keypair(:compressed)   # 33-byte pubkey
{seckey, pubkey} = Secp256k1.keypair(:xonly)        # 32-byte pubkey (Schnorr)
{seckey, pubkey} = Secp256k1.keypair(:uncompressed) # 65-byte pubkey

# Derive pubkey from existing seckey
pubkey = Secp256k1.pubkey(seckey, :compressed)

# Convert a received compressed pubkey without its seckey
xonly_pubkey = Secp256k1.convert_pubkey(pubkey, :xonly)

# Validate externally received keys, including their cryptographic encoding
true = Secp256k1.valid_seckey?(seckey)
true = Secp256k1.valid_pubkey?(pubkey)
```

### Key Tweaks (BIP-32 and Taproot)

```elixir
# Raw arithmetic example only. Derive this scalar according to BIP-32 or BIP-341.
tweak = <<1::256>>

tweaked_seckey = Secp256k1.ec_seckey_tweak_add(seckey, tweak)
tweaked_pubkey = Secp256k1.ec_pubkey_tweak_add(pubkey, tweak)

internal_pubkey = Secp256k1.pubkey(seckey, :xonly)
{:ok, output_pubkey, parity} = Secp256k1.xonly_pubkey_tweak_add(internal_pubkey, tweak)
true = Secp256k1.xonly_pubkey_tweak_add_check(output_pubkey, parity, internal_pubkey, tweak)
output_seckey = Secp256k1.xonly_seckey_tweak_add(seckey, tweak)
```

### ECDSA (Bitcoin legacy)

```elixir
msg_hash = :crypto.hash(:sha256, "message")  # MUST be 32 bytes
signature = Secp256k1.ecdsa_sign(msg_hash, seckey)
der_signature = Secp256k1.ecdsa_signature_serialize_der(signature)
signature = Secp256k1.ecdsa_signature_parse_der(der_signature)

# Only when the protocol deliberately accepts malleable high-S forms:
signature = Secp256k1.ecdsa_signature_normalize(signature)
true = Secp256k1.ecdsa_valid?(signature, msg_hash, pubkey)  # compressed or uncompressed pubkey
```

### Schnorr (BIP-340, Taproot, Nostr)

```elixir
# BIP-340 signs messages of any length; sign the exact bytes your protocol specifies.
# Taproot and Nostr sign a 32-byte hash.
msg_hash = :crypto.hash(:sha256, "message")
signature = Secp256k1.schnorr_sign(msg_hash, seckey)
true = Secp256k1.schnorr_valid?(signature, msg_hash, xonly_pubkey)  # x-only pubkey

# Messages over 65_536 bytes are signed and verified on dirty CPU schedulers
signature = Secp256k1.schnorr_sign(raw_message, seckey)
true = Secp256k1.schnorr_valid?(signature, raw_message, xonly_pubkey)
```

## Rules

### DO

- **Hash messages for ECDSA and MuSig2**: `ecdsa_sign/2`, `MuSig.nonce_gen/5`, and `MuSig.nonce_process/3` take exactly 32-byte messages. Schnorr signs messages of any length; pass whatever bytes your protocol signs.
- **Use secp256k1 pubkeys for ECDSA**: `ecdsa_valid?/3` accepts 33-byte compressed or 65-byte uncompressed pubkeys.
- **Reject high-S by default**: Normalize only when the protocol deliberately accepts malleable signature forms, then use the normalized bytes thereafter.
- **Separate Bitcoin sighash bytes**: DER conversion handles only the signature, not a trailing transaction sighash byte.
- **Use x-only pubkeys for Schnorr**: `schnorr_valid?/3` expects 32-byte x-only pubkeys.
- **Generate fresh keypairs securely**: `Secp256k1.keypair/1` uses `:crypto.strong_rand_bytes/1`.
- **Validate inputs early**: Use `valid_seckey?/1` and `valid_pubkey?/1` for externally received keys.
- **Keep x-only output parity**: Taproot tweak verification requires both the output key and parity.

### DON'T

- **Don't reuse nonces in MuSig2**: Call `nonce_gen/5` fresh for every signature attempt. Nonce reuse leaks the secret key.
- **Don't use custom Schnorr AUX values**: `sign32/3` exists but is NOT RECOMMENDED. Use the 2-arg version.
- **Don't mix pubkey formats**: ECDSA uses compressed (33 bytes) or uncompressed (65 bytes); Schnorr uses x-only (32 bytes).
- **Don't sign unhashed data with ECDSA or MuSig2**: Their signing APIs expect a 32-byte hash. This does not apply to Schnorr.
- **Don't persist or transport MuSig resources**: `keyagg_cache`, `session`, and `secnonce` are NIF resource references. Any process on the same node can use them, and sharing a `secnonce` reference does not duplicate the nonce, but `:erlang.term_to_binary/1` keeps only a handle that is stale on other nodes, in other VMs, or after garbage collection.
- **Don't vary the MuSig2 key order**: All signers must pass the same pubkey list in the same order to `pubkey_agg/1`.
- **Don't treat key tweaking as hashing**: Derive the scalar according to BIP-32 or BIP-341 before calling the tweak API.

## Error Handling

| Situation                                                                                                                                              | Result                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Wrong type or binary size                                                                                                                              | `FunctionClauseError`                                                              |
| `valid_seckey?/1`, `valid_pubkey?/1` with any invalid term                                                                                             | `false`                                                                            |
| Right-sized secret key that is not a valid scalar (including `MuSig.nonce_gen/5`)                                                                      | `ArgumentError`                                                                    |
| Malformed DER (8-72 bytes); unparsable compact signature in DER serialization or normalization                                                         | `ArgumentError`                                                                    |
| Unparsable MuSig pubkey, public nonce, aggregate nonce, or partial signature; wrong-kind or stale MuSig resource                                       | `ArgumentError`                                                                    |
| `MuSig.nonce_gen/5` secret key that does not derive the given pubkey                                                                                   | `ArgumentError`                                                                    |
| Right-sized but invalid pubkey in `ecdh/2`, `convert_pubkey/2`, `ec_pubkey_tweak_add/2`, `xonly_pubkey_tweak_add/2`                                    | `{:error, reason}`                                                                 |
| Invalid signature, key, or tweak in `ecdsa_valid?/3`, `schnorr_valid?/3`, `xonly_pubkey_tweak_add_check/4`; non-verifying `MuSig.partial_sig_verify/5` | `false`                                                                            |
| Rejected operation (out-of-range tweak, invalid result key, used MuSig nonce, ...)                                                                     | `{:error, reason}` with a binary reason                                            |
| Native allocation failure                                                                                                                              | `{:error, :allocation_failed}`                                                     |
| `MuSig.partial_sign/4` with a secret key not matching the nonce's pubkey                                                                               | `{:error, "secret key does not match secnonce public key"}`; the nonce is consumed |
| libsecp256k1 illegal-argument callback                                                                                                                 | `ArgumentError` (nothing is printed)                                               |
| libsecp256k1 internal-error callback                                                                                                                   | `{:error, "libsecp256k1 internal error"}`                                          |

```elixir
try do
  Secp256k1.ecdsa_sign(<<1, 2, 3>>, seckey)  # msg_hash too short
rescue
  FunctionClauseError -> # handle invalid size
end

false = Secp256k1.valid_seckey?(<<1, 2, 3>>)
false = Secp256k1.valid_pubkey?(:not_a_key)

case Secp256k1.ecdh(seckey, received_pubkey) do
  {:error, reason} -> # received_pubkey is not a curve point
  shared_secret -> # success
end
```

## Common Mistakes

| Mistake                 | Problem                                | Fix                                                        |
| ----------------------- | -------------------------------------- | ---------------------------------------------------------- |
| Hashless ECDSA/MuSig2   | These APIs expect a 32-byte hash       | Use `:crypto.hash(:sha256, msg)` first                     |
| Wrong pubkey type       | ECDSA/Schnorr use different formats    | ECDSA: `:compressed` or `:uncompressed`, Schnorr: `:xonly` |
| Reusing MuSig nonces    | Leaks secret key                       | Always call `nonce_gen/5` fresh                            |
| Invalid binary size     | Operations raise `FunctionClauseError` | Use documented sizes; key predicates return `false`        |
| Invalid key encoding    | Correct size does not imply validity   | Use `valid_seckey?/1` or `valid_pubkey?/1` before use      |
| Passing DER to verify   | Verification expects compact signature | Parse DER; normalize only if the protocol permits high-S   |
| Forgetting to aggregate | MuSig requires full protocol           | Follow all 7 steps in MuSig guide                          |
| Unordered MuSig keys    | Different order, different agg key     | All signers use the same ordered pubkey list               |

## MuSig2 Protocol (Summary)

```elixir
# 1. Aggregate pubkeys: every signer passes the same full pubkeys in the same order
{:ok, agg_pubkey, cache} = MuSig.pubkey_agg(pubkeys)

# 2. Generate nonces (each signer, with its own seckey and the matching pubkey from `pubkeys`)
{:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)

# 3. Aggregate all signers' public nonces
aggnonce = MuSig.nonce_agg(pubnonces)

# 4. Create session (each signer)
session = MuSig.nonce_process(aggnonce, msg, cache)

# 5. Partial sign (each signer; seckey must derive the pubkey given to nonce_gen)
partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)

# 6. Verify every received partial signature with that signer's pubnonce and pubkey
true = MuSig.partial_sig_verify(partial_sig, pubnonce, pubkey, cache, session)

# 7. Aggregate signatures
final_sig = MuSig.partial_sig_agg(session, partial_sigs)

# Verify as standard Schnorr
Secp256k1.schnorr_valid?(final_sig, msg, agg_pubkey)
```

## Security Checklist

- [ ] Secret keys generated from secure random source
- [ ] Externally received keys validated before use
- [ ] Secret keys never logged or exposed
- [ ] ECDSA and MuSig2 messages hashed to 32 bytes before signing
- [ ] MuSig nonces never reused
- [ ] MuSig public nonces exchanged before signing begins
- [ ] Signatures verified after receiving from external sources

## Platform Notes

- **Linux**: Primary platform, fully supported
- **macOS**: Supported with Xcode Command Line Tools (`xcode-select --install`)
- **Windows**: Not tested

## Version Compatibility

- Elixir: `~> 1.15`
- Underlying C library: bitcoin-core/secp256k1 v0.7.1
