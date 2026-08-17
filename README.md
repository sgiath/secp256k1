<p align="center">
  <img src="https://raw.githubusercontent.com/sgiath/secp256k1/master/priv/header.svg" alt="secp256k1 - the curve with chord-and-tangent point addition, R = P + Q"/>
</p>

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

## Documentation

- [HexDocs](https://lib-secp256k1.hexdocs.pm/) - API reference
- [Usage Guide](https://lib-secp256k1.hexdocs.pm/usage.html) - detailed examples, also runnable as a [Livebook](docs/usage.livemd)
- [MuSig Guide](https://lib-secp256k1.hexdocs.pm/musig.html) - multi-signature protocol walkthrough, also runnable as a [Livebook](docs/musig.livemd)

From a local checkout, run the guides interactively with
[Livebook](https://livebook.dev):

```bash
livebook server docs
```

## Platform Support

- **Linux** - fully supported, primary development platform
- **macOS** - supported with Xcode Command Line Tools
- **Windows** - not tested, contributions welcome

## License

[WTFPL](LICENSE) - Do What The Fuck You Want To Public License

The underlying secp256k1 C library is MIT licensed. Its `COPYING` file ships inside the vendored tarball, and the Hex package metadata declares both WTFPL and MIT licenses.
