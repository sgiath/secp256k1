# Usage Rules & Quick Reference

Quick reference for `lib_secp256k1` library users. For detailed examples, see [Usage Guide](usage.md) and [MuSig Guide](musig.md).

## Data Sizes

| Type | Size | Description |
|------|------|-------------|
| `seckey` | 32 bytes | Secret key (private key) |
| `hash` | 32 bytes | Message hash (SHA256) |
| `compressed_pubkey` | 33 bytes | Standard Bitcoin pubkey format |
| `uncompressed_pubkey` | 65 bytes | Full pubkey with both coordinates |
| `xonly_pubkey` | 32 bytes | Schnorr/Taproot/Nostr format |
| `ecdsa_sig` | 64 bytes | Compact ECDSA signature |
| `schnorr_sig` | 64 bytes | BIP-340 Schnorr signature |

## Quick Reference

### Keypairs

```elixir
# Generate random keypair
{seckey, pubkey} = Secp256k1.keypair(:compressed)   # 33-byte pubkey
{seckey, pubkey} = Secp256k1.keypair(:xonly)        # 32-byte pubkey (Schnorr)
{seckey, pubkey} = Secp256k1.keypair(:uncompressed) # 65-byte pubkey

# Derive pubkey from existing seckey
pubkey = Secp256k1.pubkey(seckey, :compressed)
```

### ECDSA (Bitcoin legacy)

```elixir
msg_hash = :crypto.hash(:sha256, "message")  # MUST be 32 bytes
signature = Secp256k1.ecdsa_sign(msg_hash, seckey)
true = Secp256k1.ecdsa_valid?(signature, msg_hash, pubkey)  # compressed pubkey
```

### Schnorr (BIP-340, Taproot, Nostr)

```elixir
msg_hash = :crypto.hash(:sha256, "message")
signature = Secp256k1.schnorr_sign(msg_hash, seckey)
true = Secp256k1.schnorr_valid?(signature, msg_hash, xonly_pubkey)  # x-only pubkey
```

## Rules

### DO

- **Hash messages before signing**: Always pass a 32-byte hash to signing functions, not raw messages.
- **Use compressed pubkeys for ECDSA**: `ecdsa_valid?/3` expects 33-byte compressed pubkeys.
- **Use x-only pubkeys for Schnorr**: `schnorr_valid?/3` expects 32-byte x-only pubkeys.
- **Generate fresh keypairs securely**: `Secp256k1.keypair/1` uses `:crypto.strong_rand_bytes/1`.
- **Validate inputs early**: Check binary sizes before passing to library functions.

### DON'T

- **Don't reuse nonces in MuSig2**: Call `nonce_gen/5` fresh for every signature attempt. Nonce reuse leaks the secret key.
- **Don't use custom AUX values**: `sign/3` and `sign32/3` exist but are NOT RECOMMENDED. Use 2-arg versions.
- **Don't mix pubkey formats**: ECDSA uses compressed (33 bytes), Schnorr uses x-only (32 bytes).
- **Don't sign unhashed data**: The library expects pre-hashed 32-byte messages for most operations.
- **Don't serialize MuSig secnonces**: They're Erlang resources, not binaries. Attempting to copy them will fail.

## Error Handling

```elixir
# Functions raise ArgumentError for invalid inputs
try do
  Secp256k1.ecdsa_sign(<<1, 2, 3>>, seckey)  # msg_hash too short
rescue
  ArgumentError -> # handle invalid input
end

# MuSig functions return {:error, reason} tuples
case Secp256k1.MuSig.pubkey_agg(pubkeys) do
  {:ok, agg_pubkey, cache} -> # success
  {:error, reason} -> # handle error
end
```

## Common Mistakes

| Mistake | Problem | Fix |
|---------|---------|-----|
| Signing raw message | Library expects 32-byte hash | Use `:crypto.hash(:sha256, msg)` first |
| Wrong pubkey type | ECDSA/Schnorr use different formats | ECDSA: `:compressed`, Schnorr: `:xonly` |
| Reusing MuSig nonces | Leaks secret key | Always call `nonce_gen/5` fresh |
| Invalid binary size | Functions raise ArgumentError | Validate sizes: seckey=32, hash=32, etc. |
| Forgetting to aggregate | MuSig requires full protocol | Follow all 6 steps in MuSig guide |

## MuSig2 Protocol (Summary)

```elixir
# 1. Aggregate pubkeys
{:ok, agg_pubkey, cache} = MuSig.pubkey_agg(pubkeys)

# 2. Generate nonces (each signer)
{:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)

# 3. Aggregate nonces
aggnonce = MuSig.nonce_agg(pubnonces)

# 4. Create session
session = MuSig.nonce_process(aggnonce, msg, cache)

# 5. Partial sign (each signer)
partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)

# 6. Aggregate signatures
final_sig = MuSig.partial_sig_agg(session, partial_sigs)

# Verify as standard Schnorr
Secp256k1.schnorr_valid?(final_sig, msg, agg_pubkey)
```

## Security Checklist

- [ ] Secret keys generated from secure random source
- [ ] Secret keys never logged or exposed
- [ ] Messages hashed before signing
- [ ] MuSig nonces never reused
- [ ] MuSig public nonces exchanged before signing begins
- [ ] Signatures verified after receiving from external sources

## Platform Notes

- **Linux**: Primary platform, fully supported
- **macOS**: Supported with Homebrew dependencies (`brew install autoconf automake libtool`)
- **Windows**: Not tested

## Version Compatibility

- Elixir: `~> 1.15`
- Underlying C library: bitcoin-core/secp256k1 v0.7.1
