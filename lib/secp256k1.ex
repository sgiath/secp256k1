defmodule Secp256k1 do
  @moduledoc """
  This is the unified API for the stable secp256k1 functions this library provides.

  Experimental MuSig2 signing uses process-local resources and intentionally remains outside
  this facade. See `Secp256k1.MuSig` for its protocol API.

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

  ### Calculate ECDH shared secret

      iex> {alice_seckey, _alice_pubkey} = Secp256k1.keypair(<<1::256>>, :compressed)
      iex> {_bob_seckey, bob_pubkey} = Secp256k1.keypair(<<2::256>>, :compressed)
      iex> shared_secret = Secp256k1.ecdh(alice_seckey, bob_pubkey)
      iex> byte_size(shared_secret)
      32

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
  Scalar tweak is a 32-byte big-endian integer
  """
  @type tweak() :: <<_::256>>

  @typedoc """
  Parity of a full public key represented in x-only form
  """
  @type pubkey_parity() :: 0 | 1

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

  @typedoc "libsecp256k1 default hashed ECDH shared secret is 32 bytes long binary"
  @type shared_secret() :: <<_::256>>

  @doc """
  Checks whether a 32-byte binary is a valid secp256k1 secret key.

  This validates the scalar value, not only the binary size. A valid secret key is
  greater than zero and smaller than the secp256k1 curve order. Returns `false`
  for wrong-sized binaries and non-binary terms.
  """
  @spec valid_seckey?(term()) :: boolean()
  def valid_seckey?(seckey) when is_seckey(seckey) do
    Secp256k1.Extrakeys.valid_seckey?(seckey)
  end

  def valid_seckey?(_seckey), do: false

  @doc """
  Checks whether a binary encodes a valid secp256k1 public key.

  Accepts x-only (32-byte), compressed (33-byte), and uncompressed (65-byte)
  public-key encodings. Returns `false` for unsupported encodings, wrong-sized
  binaries, and non-binary terms.
  """
  @spec valid_pubkey?(term()) :: boolean()
  def valid_pubkey?(pubkey) when is_pubkey(pubkey) do
    Secp256k1.Extrakeys.valid_pubkey?(pubkey)
  end

  def valid_pubkey?(_pubkey), do: false

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
  Convert a public key to another serialization format.

  Inputs
    - `pubkey` an uncompressed public key when converting to `:compressed`, or a compressed public
      key when converting to `:uncompressed` or `:xonly`
    - `type` the target format, either `:compressed`, `:uncompressed`, or `:xonly`

  Returns the converted public key, or `{:error, reason}` when the correctly sized input does not
  encode a valid secp256k1 public key.
  """
  @spec convert_pubkey(
          pubkey :: compressed_pubkey() | uncompressed_pubkey(),
          type :: :compressed | :uncompressed | :xonly
        ) ::
          compressed_pubkey()
          | uncompressed_pubkey()
          | xonly_pubkey()
          | {:error, binary() | :allocation_failed}
  def convert_pubkey(pubkey, :compressed) when is_uncompressed_pubkey(pubkey) do
    Secp256k1.ECDSA.compress_pubkey(pubkey)
  end

  def convert_pubkey(pubkey, :uncompressed) when is_compressed_pubkey(pubkey) do
    Secp256k1.ECDSA.decompress_pubkey(pubkey)
  end

  def convert_pubkey(pubkey, :xonly) when is_compressed_pubkey(pubkey) do
    Secp256k1.Extrakeys.xonly_pubkey(pubkey)
  end

  @doc """
  Adds a scalar tweak to a secret key for BIP-32-style private derivation.

  Returns an error when the tweak is outside the scalar field or the resulting key
  would be zero.
  """
  @spec ec_seckey_tweak_add(seckey(), tweak()) ::
          seckey() | {:error, binary() | :allocation_failed}
  def ec_seckey_tweak_add(seckey, tweak) when is_seckey(seckey) and is_tweak(tweak) do
    Secp256k1.Extrakeys.ec_seckey_tweak_add(seckey, tweak)
  end

  @doc """
  Adds a scalar multiple of the generator to a compressed or uncompressed public key.

  The output preserves the input serialization format. This is the public-key
  counterpart of `ec_seckey_tweak_add/2` for BIP-32-style public derivation.
  """
  @spec ec_pubkey_tweak_add(compressed_pubkey() | uncompressed_pubkey(), tweak()) ::
          compressed_pubkey()
          | uncompressed_pubkey()
          | {:error, binary() | :allocation_failed}
  def ec_pubkey_tweak_add(pubkey, tweak)
      when (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             is_tweak(tweak) do
    Secp256k1.Extrakeys.ec_pubkey_tweak_add(pubkey, tweak)
  end

  @doc """
  Tweaks a secret key using x-only semantics for signing Taproot outputs.

  The keypair is normalized to an even-Y internal public key before adding the tweak.
  """
  @spec xonly_seckey_tweak_add(seckey(), tweak()) ::
          seckey() | {:error, binary() | :allocation_failed}
  def xonly_seckey_tweak_add(seckey, tweak)
      when is_seckey(seckey) and is_tweak(tweak) do
    Secp256k1.Extrakeys.xonly_seckey_tweak_add(seckey, tweak)
  end

  @doc """
  Adds a scalar tweak to an x-only internal public key.

  Returns the x-only output key and its full-point parity. Keep both values when
  constructing and verifying Taproot commitments.
  """
  @spec xonly_pubkey_tweak_add(xonly_pubkey(), tweak()) ::
          {:ok, xonly_pubkey(), pubkey_parity()}
          | {:error, binary() | :allocation_failed}
  def xonly_pubkey_tweak_add(internal_pubkey, tweak)
      when is_xonly_pubkey(internal_pubkey) and is_tweak(tweak) do
    Secp256k1.Extrakeys.xonly_pubkey_tweak_add(internal_pubkey, tweak)
  end

  @doc """
  Checks an x-only public-key tweak result and parity.

  This verifies the key arithmetic only. The caller remains responsible for deriving
  the tweak according to BIP-341 when using it as a Taproot commitment.
  """
  @spec xonly_pubkey_tweak_add_check(
          xonly_pubkey(),
          pubkey_parity(),
          xonly_pubkey(),
          tweak()
        ) :: boolean()
  def xonly_pubkey_tweak_add_check(tweaked_pubkey, parity, internal_pubkey, tweak)
      when is_xonly_pubkey(tweaked_pubkey) and parity in [0, 1] and
             is_xonly_pubkey(internal_pubkey) and is_tweak(tweak) do
    Secp256k1.Extrakeys.xonly_pubkey_tweak_add_check(
      tweaked_pubkey,
      parity,
      internal_pubkey,
      tweak
    )
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
  Compute libsecp256k1's default hashed ECDH shared secret.

  Inputs
    - `seckey` 32 byte long binary
    - `pubkey` compressed or uncompressed secp256k1 public key

  Output
    - `shared_secret` 32 byte binary

  This wraps libsecp256k1's ECDH module. It returns the upstream library's
  default hashed ECDH output, currently SHA256 over the compressed shared point.
  For generic raw ECDH, use `:crypto.compute_key/4`.
  """
  @spec ecdh(seckey :: seckey(), pubkey :: compressed_pubkey() | uncompressed_pubkey()) ::
          shared_secret()
  def ecdh(seckey, pubkey)
      when is_seckey(seckey) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) do
    Secp256k1.ECDH.ecdh(seckey, pubkey)
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
  def ecdsa_sign(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    Secp256k1.ECDSA.sign(msg_hash, seckey)
  end

  @doc """
  Validate ECDSA signature

  Inputs
    - `signature` 64 byte long binary
    - `msg_hash` 32 byte long message hash that was signed
    - `pubkey` compressed (33-byte) or uncompressed (65-byte) public key
  """
  @spec ecdsa_valid?(
          signature :: ecdsa_sig(),
          msg_hash :: hash(),
          pubkey :: compressed_pubkey() | uncompressed_pubkey()
        ) :: boolean()
  def ecdsa_valid?(signature, msg_hash, pubkey)
      when is_ecdsa_sig(signature) and is_hash(msg_hash) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) do
    Secp256k1.ECDSA.valid?(signature, msg_hash, pubkey)
  end

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
  def schnorr_sign(message, seckey) when is_binary(message) and is_seckey(seckey) do
    Secp256k1.Schnorr.sign(message, seckey)
  end

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
  def schnorr_valid?(signature, message, pubkey)
      when is_schnorr_sig(signature) and is_binary(message) and is_xonly_pubkey(pubkey) do
    Secp256k1.Schnorr.valid?(signature, message, pubkey)
  end
end
