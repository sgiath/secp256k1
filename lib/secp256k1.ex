defmodule Secp256k1 do
  @moduledoc """
  This is unified API for all secp256k1 functions this library provides

  ## Examples

  ### Generate new keypair

      iex> {_seckey, _pubkey} = Secp256k1.keypair(:xonly)

  ### Derive pubkey from your awesome seckey

      iex> seckey = <<0x1111111111111111111111111111111111111111111111111111111111111111::256>>
      iex> pubkey = Secp256k1.pubkey(seckey, :compressed)
      iex> Base.encode16(pubkey, case: :lower)
      "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"

  ### Calculate ECDSA signature

      iex> # your keypair
      iex> {seckey, pubkey} = Secp256k1.keypair(:compressed)
      iex> # prepare your message hash
      iex> msg_hash = :crypto.hash(:sha256, "My awesome message")
      iex> # generate signature
      iex> sig = Secp256k1.ecdsa_sign(msg_hash, seckey)
      iex> # validate your signature
      iex> Secp256k1.ecdsa_valid?(sig, msg_hash, pubkey)
      true

  ### Calculate Schnorr signature

      iex> # your keypair
      iex> {seckey, pubkey} = Secp256k1.keypair(:xonly)
      iex> # prepare your message hash
      iex> msg_hash = :crypto.hash(:sha256, "My awesome message")
      iex> # generate signature
      iex> sig = Secp256k1.schnorr_sign(msg_hash, seckey)
      iex> # validate your signature
      iex> Secp256k1.schnorr_valid?(sig, msg_hash, pubkey)
      true

  """
  @moduledoc authors: ["sgiath <secp256k1@sgiath.dev>"]

  import Secp256k1.Guards

  @typedoc """
  Hash is 32 bytes long binary
  """
  @type hash() :: <<_::256>>

  @typedoc """
  EC secp256k1 seckey is 32 bytes long binary
  """
  @type seckey() :: <<_::256>>

  @typedoc """
  Pubkey can be parsed in compressed (33 bytes), uncompressed (65 bytes) or xonly (32 bytes) format
  """
  @type pubkey_type() :: :compressed | :uncompressed | :xonly

  @typedoc """
  X-only pubkey is binary of 32 byte length
  """
  @type xonly_pubkey() :: <<_::256>>

  @typedoc """
  Compressed pubkey is binary of 33 byte length
  """
  @type compressed_pubkey() :: <<_::264>>

  @typedoc """
  Uncompressed pubkey is binary of 65 byte length
  """
  @type uncompressed_pubkey() :: <<_::520>>

  @typedoc """
  Pubkey is binary of 32, 33 or 65 byte length
  """
  @type pubkey() :: xonly_pubkey() | compressed_pubkey() | uncompressed_pubkey()

  @typedoc """
  Serialized compressed ECDSA signature is 64 bytes long binary
  """
  @type ecdsa_sig() :: <<_::512>>

  @typedoc """
  Schnorr signature is 64 bytes long binary
  """
  @type schnorr_sig() :: <<_::512>>

  @typedoc "ECDH shared secret is 32 bytes long binary"
  @type shared_secret() :: <<_::256>>

  @doc """
  Derive pubkey from provided seckey

  Inputs
    - `seckey` 32 byte long binary
    - `type` one of `:xonly`, `:compressed` or `:uncompressed`

  Output
    - `pubkey` serialization type depends on the type provided
  """
  @spec pubkey(seckey :: seckey(), type :: pubkey_type()) :: pubkey()
  def pubkey(seckey, :xonly) when is_seckey(seckey) do
    Secp256k1.Extrakeys.xonly_pubkey(seckey)
  end

  def pubkey(seckey, :compressed) when is_seckey(seckey) do
    Secp256k1.ECDSA.pubkey(seckey, compress: true)
  end

  def pubkey(seckey, :uncompressed) when is_seckey(seckey) do
    Secp256k1.ECDSA.pubkey(seckey, compress: false)
  end

  @doc """
  Generate new secp256k1 keypair

  Input
    - `type` (see `pubkey/2`)

  Output
    - 2-tuple with seckey on the first place and pubkey on the second place
  """
  @spec keypair(type :: pubkey_type()) :: {seckey(), pubkey()}
  def keypair(type) when type in [:xonly, :compressed, :uncompressed] do
    keypair(:crypto.strong_rand_bytes(32), type)
  end

  @doc """
  Generate new secp256k1 keypair from provided seckey

  For options see `pubkey/2`
  """
  @spec keypair(seckey :: seckey(), type :: pubkey_type()) :: {seckey(), pubkey()}
  def keypair(seckey, type)
      when is_seckey(seckey) and type in [:xonly, :compressed, :uncompressed] do
    {seckey, Secp256k1.pubkey(seckey, type)}
  end

  @doc """
  Create an ECDSA signature

  Inputs
    - `msg_hash` 32 byte long message hash to sign
    - `seckey` 32 byte long binary

  Output
    - `signature` ECDSA signature serialized in compressed format (64 byte binary)
  """
  @spec ecdsa_sign(msg_hash :: hash(), seckey :: seckey()) :: ecdsa_sig()
  defdelegate ecdsa_sign(msg_hash, seckey), to: Secp256k1.ECDSA, as: :sign

  @doc """
  Validate ECDSA signature

  Inputs
    - `signature` 64 byte long binary
    - `msg_hash` 32 byte long message hash that was signed
    - `pubkey` compressed pubkey (33 byte long binary)
  """
  @spec ecdsa_valid?(signature :: ecdsa_sig(), msg_hash :: hash(), pubkey :: compressed_pubkey()) ::
          boolean()
  defdelegate ecdsa_valid?(signature, msg_hash, pubkey), to: Secp256k1.ECDSA, as: :valid?

  @doc """
  Calculate Schnorr signature according to BIP 340

  Inputs
    - `message` can accept arbitrary long binary but only 32 byte long hash is the only option
      strictly according to specification
    - `seckey` 32 byte long binary

  Output
    - `signature` Schnorr signature is 64 byte long binary

  _Note:_ automatic random nonce is added to every run so generated signature is not deterministic
  """
  @spec schnorr_sign(message :: binary(), seckey :: seckey()) :: schnorr_sig()
  defdelegate schnorr_sign(message, seckey), to: Secp256k1.Schnorr, as: :sign

  @doc """
  Validate Schnorr signature

  Inputs
    - `signature` 64 byte long binary
    - `message` arbitrary long binary
    - `pubkey` xonly pubkey (32 byte long binary)
  """
  @spec schnorr_valid?(
          signature :: schnorr_sig(),
          message :: binary(),
          pubkey :: xonly_pubkey()
        ) :: boolean()
  defdelegate schnorr_valid?(signature, message, pubkey), to: Secp256k1.Schnorr, as: :valid?
end
