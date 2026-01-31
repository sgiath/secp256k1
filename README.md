# Secp256k1

[![Hex.pm](https://img.shields.io/hexpm/v/lib_secp256k1.svg?style=flat&color=blue)](https://hex.pm/packages/lib_secp256k1)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/lib_secp256k1)
[![License](https://img.shields.io/badge/license-WTFPL-brightgreen)](LICENSE)

Elixir NIF bindings for the [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) cryptographic library. Used extensively in Bitcoin, Ethereum, Nostr, and other blockchain/cryptocurrency applications.

## Features

- **Keypair generation** - secure random secret keys with compressed, uncompressed, or x-only public keys
- **ECDSA signatures** - sign and verify using the traditional Bitcoin signature scheme
- **Schnorr signatures** - BIP-340 compatible, used in Taproot and Nostr
- **MuSig2** - BIP-327 multi-party Schnorr signatures (experimental)
- **ECDH** - Diffie-Hellman shared secret computation

## Installation

### System Dependencies

The library compiles the underlying C library automatically, but requires build tools:

**Linux (Ubuntu/Debian)**

```bash
sudo apt-get install build-essential automake libtool autoconf
```

**macOS**

```bash
brew install make gcc autoconf automake libtool
```

### Elixir Dependency

Add to your `mix.exs`:

```elixir
def deps do
  [
    {:lib_secp256k1, "~> 0.7"}
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
```

### ECDSA Signatures

```elixir
{seckey, pubkey} = Secp256k1.keypair(:compressed)

# Sign a message hash
msg_hash = :crypto.hash(:sha256, "Hello Bitcoin!")
signature = Secp256k1.ecdsa_sign(msg_hash, seckey)

# Verify
Secp256k1.ecdsa_valid?(signature, msg_hash, pubkey)
#=> true
```

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

### MuSig2 Multi-Signatures (BIP-327)

For multi-party signing where multiple parties create a single aggregated signature. See the [MuSig Guide](https://hexdocs.pm/lib_secp256k1/musig.html) for the complete protocol.

```elixir
# Aggregate public keys from multiple signers
{:ok, agg_pubkey, cache} = Secp256k1.MuSig.pubkey_agg([alice_pubkey, bob_pubkey])

# ... nonce generation, aggregation, signing rounds ...

# Final signature verifies as standard Schnorr
Secp256k1.schnorr_valid?(final_sig, msg_hash, agg_pubkey)
```

## Documentation

- [HexDocs](https://hexdocs.pm/lib_secp256k1) - API reference
- [Usage Guide](https://hexdocs.pm/lib_secp256k1/usage.html) - detailed examples
- [MuSig Guide](https://hexdocs.pm/lib_secp256k1/musig.html) - multi-signature protocol

## Platform Support

- **Linux** - fully supported, primary development platform
- **macOS** - supported with Homebrew dependencies
- **Windows** - not tested, contributions welcome

## License

[WTFPL](LICENSE) - Do What The Fuck You Want To Public License

The underlying secp256k1 C library is MIT licensed.
