# Secp256k1

[![Hex.pm](https://img.shields.io/hexpm/v/lib_secp256k1.svg?style=flat&color=blue)](https://hex.pm/packages/lib_secp256k1)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/lib_secp256k1)
[![License](https://img.shields.io/badge/license-WTFPL-brightgreen)](LICENSE)

Elixir NIF bindings for the [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) cryptographic library. Used extensively in Bitcoin, Ethereum, Nostr, and other blockchain/cryptocurrency applications.

> #### Scope {: .info}
>
> This package exposes libsecp256k1 behavior in Elixir. It intentionally relies
> on Erlang's `:crypto` module for generic cryptographic building blocks such
> as hashing, random bytes, generic ECDSA, and raw ECDH.

## Features

- **Keypair generation** - secure random secret keys with compressed, uncompressed, or x-only public keys
- **Key validation** - validate externally received secret and public keys before use
- **Key tweaks** - BIP-32-style full-key derivation and x-only Taproot commitments
- **ECDSA signatures** - sign, verify, normalize low-S, and convert compact signatures to and from DER
- **Schnorr signatures** - BIP-340 compatible, used in Taproot and Nostr
- **MuSig2** - BIP-327 multi-party Schnorr signatures (experimental)
- **ECDH** - Diffie-Hellman shared secret computation

## Installation

### System Dependencies

The package includes the upstream libsecp256k1 source as a vendored tarball with a pre-generated configure script. Users need `make`, a C compiler, and standard Unix tools `tar` plus either `sha256sum` or `shasum`, which are present in standard Unix userland. No network, git, autoconf, automake, or libtool is required to compile the package.

**Linux (Ubuntu/Debian)**

```bash
sudo apt-get install build-essential
```

**macOS**

Install Xcode Command Line Tools:

```bash
xcode-select --install
```

### Elixir Dependency

Add to your `mix.exs`:

```elixir
def deps do
  [
    {:lib_secp256k1, "~> 0.8"}
  ]
end
```

## Quick Start

### Generate a Keypair

```elixir
# Compressed pubkey (33 bytes) - standard Bitcoin format
{seckey, pubkey} = Secp256k1.keypair(:compressed)

# X-only pubkey (32 bytes) - for Schnorr/Taproot/Nostr
{seckey, pubkey} = Secp256k1.keypair(:xonly)

# Derive pubkey from existing secret key
pubkey = Secp256k1.pubkey(seckey, :compressed)

# Convert a received compressed pubkey without owning its secret key
xonly_pubkey = Secp256k1.convert_pubkey(pubkey, :xonly)

# Validate externally received key material
true = Secp256k1.valid_seckey?(seckey)
true = Secp256k1.valid_pubkey?(pubkey)
```

### Derive Tweaked Keys

```elixir
# Raw arithmetic example only. Derive this scalar according to BIP-32 or BIP-341.
tweak = <<1::256>>

# BIP-32-style private/public derivation
tweaked_seckey = Secp256k1.ec_seckey_tweak_add(seckey, tweak)
tweaked_pubkey = Secp256k1.ec_pubkey_tweak_add(pubkey, tweak)

# Taproot-style x-only output key and the parity needed to verify it
internal_pubkey = Secp256k1.pubkey(seckey, :xonly)
{:ok, output_pubkey, parity} = Secp256k1.xonly_pubkey_tweak_add(internal_pubkey, tweak)
true = Secp256k1.xonly_pubkey_tweak_add_check(output_pubkey, parity, internal_pubkey, tweak)

# Secret key that signs for output_pubkey
tweaked_seckey = Secp256k1.xonly_seckey_tweak_add(seckey, tweak)
```

The caller is responsible for deriving BIP-32 child tweaks or BIP-341 Taproot
commitment tweaks. Correctly sized tweaks can still be invalid scalars; tweak-add
functions return `{:error, reason}` when libsecp256k1 rejects one.

### ECDSA Signatures

```elixir
{seckey, pubkey} = Secp256k1.keypair(:compressed)

# Sign a message hash
msg_hash = :crypto.hash(:sha256, "Hello Bitcoin!")
signature = Secp256k1.ecdsa_sign(msg_hash, seckey)

# Convert the compact signature to strict DER for wire protocols
der_signature = Secp256k1.ecdsa_signature_serialize_der(signature)

# Parse a signature received from the wire
compact_signature = Secp256k1.ecdsa_signature_parse_der(der_signature)

# Only normalize if the protocol intentionally accepts malleable high-S forms
compact_signature = Secp256k1.ecdsa_signature_normalize(compact_signature)

# Verify
Secp256k1.ecdsa_valid?(compact_signature, msg_hash, pubkey)
#=> true
```

> #### ECDSA and `:crypto` {: .info}
>
> Erlang's `:crypto` module also provides generic ECDSA with digest selection.
> This library uses the libsecp256k1/Bitcoin-oriented contract: sign an already
> prepared 32-byte message hash and verify with secp256k1 public keys. Sign and
> verify use compact 64-byte `r || s` signatures; the signature conversion APIs
> bridge strict DER wire encodings. DER does not include the trailing sighash
> byte used in Bitcoin transactions. Verification rejects high-S. Protocols
> requiring canonical low-S signatures should keep that rejection. Normalize
> only when deliberately accepting malleable, mathematically equivalent forms,
> and use the normalized bytes thereafter.

### Schnorr Signatures (BIP-340)

```elixir
{seckey, pubkey} = Secp256k1.keypair(:xonly)

# Sign (works with 32-byte hash or arbitrary message)
msg_hash = :crypto.hash(:sha256, "Hello Nostr!")
signature = Secp256k1.schnorr_sign(msg_hash, seckey)

# Verify
Secp256k1.schnorr_valid?(signature, msg_hash, pubkey)
#=> true
```

### ECDH Shared Secrets

```elixir
{alice_seckey, _alice_pubkey} = Secp256k1.keypair(:compressed)
{_bob_seckey, bob_pubkey} = Secp256k1.keypair(:compressed)

# Returns libsecp256k1's default hashed ECDH output.
shared_secret = Secp256k1.ecdh(alice_seckey, bob_pubkey)
byte_size(shared_secret)
#=> 32
```

> #### ECDH and `:crypto` {: .info}
>
> `Secp256k1.ecdh/2` wraps the upstream C library behavior. It returns the
> libsecp256k1 default hashed shared secret, currently SHA256 over the
> compressed shared point. For generic raw ECDH, use `:crypto.compute_key/4`.

### MuSig2 Multi-Signatures (BIP-327)

For multi-party signing where multiple parties create a single aggregated signature. See the [MuSig Guide](https://hexdocs.pm/lib_secp256k1/musig.html) for the complete protocol.

> #### Nonces are one-use {: .warning}
>
> MuSig2 secret nonces must never be reused. Call `Secp256k1.MuSig.nonce_gen/5`
> fresh for every signing attempt.

```elixir
# Aggregate public keys from multiple signers
{:ok, agg_pubkey, cache} = Secp256k1.MuSig.pubkey_agg([alice_pubkey, bob_pubkey])

# ... nonce generation, aggregation, signing rounds ...

# Final signature verifies as standard Schnorr
Secp256k1.schnorr_valid?(final_sig, msg_hash, agg_pubkey)
```

## Documentation

- [HexDocs](https://lib-secp256k1.hexdocs.pm/) - API reference
- [Usage Guide](https://lib-secp256k1.hexdocs.pm/usage.html) - detailed examples
- [MuSig Guide](https://lib-secp256k1.hexdocs.pm/musig.html) - multi-signature protocol

## Platform Support

- **Linux** - fully supported, primary development platform
- **macOS** - supported with Xcode Command Line Tools
- **Windows** - not tested, contributions welcome

## License

[WTFPL](LICENSE) - Do What The Fuck You Want To Public License

The underlying secp256k1 C library is MIT licensed. Its `COPYING` file ships inside the vendored tarball, and the Hex package metadata declares both WTFPL and MIT licenses.
