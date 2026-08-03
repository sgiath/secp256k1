# Usage Rules & Quick Reference

Quick reference for `lib_secp256k1` library users. For detailed examples, see [Usage Guide](usage.md) and [MuSig Guide](musig.md).

## Data Sizes

| Type                  | Size     | Description                       |
| --------------------- | -------- | --------------------------------- |
| `seckey`              | 32 bytes | Secret key (private key)          |
| `tweak`               | 32 bytes | Big-endian scalar for key tweaks  |
| `hash`                | 32 bytes | Message hash (SHA256)             |
| `compressed_pubkey`   | 33 bytes | Standard Bitcoin pubkey format    |
| `uncompressed_pubkey` | 65 bytes | Full pubkey with both coordinates |
| `xonly_pubkey`        | 32 bytes | Schnorr/Taproot/Nostr format      |
| `ecdsa_sig`           | 64 bytes | Compact ECDSA signature           |
| `schnorr_sig`         | 64 bytes | BIP-340 Schnorr signature         |

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
true = Secp256k1.ecdsa_valid?(signature, msg_hash, pubkey)  # compressed or uncompressed pubkey
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
- **Use secp256k1 pubkeys for ECDSA**: `ecdsa_valid?/3` accepts 33-byte compressed or 65-byte uncompressed pubkeys.
- **Use x-only pubkeys for Schnorr**: `schnorr_valid?/3` expects 32-byte x-only pubkeys.
- **Generate fresh keypairs securely**: `Secp256k1.keypair/1` uses `:crypto.strong_rand_bytes/1`.
- **Validate inputs early**: Check binary sizes before passing to library functions.
- **Keep x-only output parity**: Taproot tweak verification requires both the output key and parity.

### DON'T

- **Don't reuse nonces in MuSig2**: Call `nonce_gen/5` fresh for every signature attempt. Nonce reuse leaks the secret key.
- **Don't use custom Schnorr AUX values**: `sign32/3` exists but is NOT RECOMMENDED. Use the 2-arg version.
- **Don't mix pubkey formats**: ECDSA uses compressed (33 bytes) or uncompressed (65 bytes); Schnorr uses x-only (32 bytes).
- **Don't sign unhashed data**: The library expects pre-hashed 32-byte messages for most operations.
- **Don't serialize MuSig secnonces**: They're Erlang resources, not binaries. Attempting to copy them will fail.
- **Don't treat key tweaking as hashing**: Derive the scalar according to BIP-32 or BIP-341 before calling the tweak API.

## Error Handling

```elixir
# Stable APIs raise FunctionClauseError for invalid-sized binary inputs
try do
  Secp256k1.ecdsa_sign(<<1, 2, 3>>, seckey)  # msg_hash too short
rescue
  FunctionClauseError -> # handle invalid size
end

# MuSig functions return {:error, reason} tuples
case Secp256k1.MuSig.pubkey_agg(pubkeys) do
  {:ok, agg_pubkey, cache} -> # success
  {:error, reason} -> # handle error
end
```

## Common Mistakes

| Mistake                 | Problem                               | Fix                                                        |
| ----------------------- | ------------------------------------- | ---------------------------------------------------------- |
| Signing raw message     | Library expects 32-byte hash          | Use `:crypto.hash(:sha256, msg)` first                     |
| Wrong pubkey type       | ECDSA/Schnorr use different formats   | ECDSA: `:compressed` or `:uncompressed`, Schnorr: `:xonly` |
| Reusing MuSig nonces    | Leaks secret key                      | Always call `nonce_gen/5` fresh                            |
| Invalid binary size     | Stable APIs raise FunctionClauseError | Use documented sizes: seckey=32, hash=32, etc.             |
| Forgetting to aggregate | MuSig requires full protocol          | Follow all 6 steps in MuSig guide                          |

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
