defmodule Secp256k1 do
  @moduledoc """
  This is the unified API for the stable secp256k1 functions this library provides.

  Experimental MuSig2 signing uses NIF resources and intentionally remains outside this facade.
  See `Secp256k1.MuSig` for its protocol API.

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

  ## Error contract

  All modules in this library share one error contract:

    * **Wrong shape** - an argument with the wrong type or binary size fails the Elixir guards
      and raises `FunctionClauseError`. The key predicates `valid_seckey?/1` and
      `valid_pubkey?/1` (and their `Secp256k1.Extrakeys` counterparts) return `false`
      instead. The MuSig aggregation functions `Secp256k1.MuSig.pubkey_agg/1`,
      `Secp256k1.MuSig.nonce_agg/1`, and `Secp256k1.MuSig.partial_sig_agg/2` guard only the
      outer list: a list element of the wrong type or size raises `ArgumentError`.
    * **Invalid secrets, signatures, and MuSig values** - a correctly sized secret key that is
      not a valid scalar (zero or not below the curve order) raises `ArgumentError`. So do
      malformed DER in the accepted 8-72 byte range, compact ECDSA signatures that cannot be
      parsed by `ecdsa_signature_serialize_der/1` or `ecdsa_signature_normalize/1`, MuSig
      resources that are stale, of the wrong kind, or created by another NIF library, and MuSig
      public keys, public nonces, aggregate nonces, or partial signatures that cannot be parsed. A
      `Secp256k1.MuSig.nonce_gen/2` secret key that does not derive the given public key also
      raises `ArgumentError`.
    * **Malformed public keys** - a correctly sized public key that does not encode a curve
      point returns `{:error, reason}` from `ecdh/2`, `convert_pubkey/2`,
      `ec_pubkey_tweak_add/2`, and `xonly_pubkey_tweak_add/2` (and their feature-module
      counterparts).
    * **Predicates** - `ecdsa_valid?/3`, `schnorr_valid?/3`, `xonly_pubkey_tweak_add_check/4`,
      `valid_seckey?/1`, and `valid_pubkey?/1` return `false` for correctly sized but invalid
      signatures, keys, or tweaks. `Secp256k1.MuSig.partial_sig_verify/5` is a MuSig
      exception: it returns `false` for a partial signature that does not verify or a key
      aggregation cache other than the session's, but raises `ArgumentError` for unparsable
      arguments, as listed above.
    * **Operation failures** - a cryptographic operation that rejects valid-looking input (for
      example a tweak at or above the curve order, a tweak producing an invalid key, a used
      MuSig secret nonce, or a `Secp256k1.MuSig.partial_sign/4` call whose secret key, key
      aggregation cache, or session does not match the secret nonce or the session) returns
      `{:error, reason}` with a binary `reason` describing the failure. A native allocation
      failure returns `{:error, :allocation_failed}`.
    * **libsecp256k1 callbacks** - libsecp256k1 reports API misuse through its
      illegal-argument callback and internal consistency failures through its error callback.
      This library never prints either message during a function call. A call that triggers
      the illegal-argument callback discards its result and raises `ArgumentError`; a call
      that triggers the internal-error callback discards its result and returns
      `{:error, "libsecp256k1 internal error"}`. libsecp256k1 v0.7.1 invokes the
      internal-error callback only from code paths these bindings do not use, so predicate
      specs remain `boolean()`. The one exception is libsecp256k1's self-test, which runs
      once when the NIF loads, before these callbacks are installed: on a miscompiled
      library it fails, and libsecp256k1's default error callback prints a message and
      aborts the VM.

  **Exceptions can contain secrets.** A `FunctionClauseError` report lists the call's
  arguments, and stacktraces of `ArgumentError` and other exceptions raised from a NIF include
  them too. For functions that take secret keys, auxiliary randomness, tweaks derived from
  secrets, or other secret-bearing values, those arguments are the secrets. Do not log full
  exception reports or stacktraces from such calls; redact the arguments before logging. This
  affects only reporting: the exception classes above are as documented.

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
  Compressed (33 bytes) or uncompressed (65 bytes) full public key, as opposed to an x-only key
  """
  @type full_pubkey() :: compressed_pubkey() | uncompressed_pubkey()

  @typedoc """
  Compact ECDSA signature (`r || s`) is 64 bytes long binary
  """
  @type ecdsa_sig() :: <<_::512>>

  @typedoc """
  Standard-sized strict DER-encoded ECDSA signature (8-72 bytes), excluding any
  Bitcoin transaction sighash byte
  """
  @type ecdsa_der_sig() :: binary()

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
  defdelegate valid_seckey?(seckey), to: Secp256k1.Extrakeys

  @doc """
  Checks whether a binary encodes a valid secp256k1 public key.

  Accepts x-only (32-byte), compressed (33-byte), and uncompressed (65-byte)
  public-key encodings. Returns `false` for unsupported encodings, wrong-sized
  binaries, and non-binary terms.
  """
  @spec valid_pubkey?(term()) :: boolean()
  defdelegate valid_pubkey?(pubkey), to: Secp256k1.Extrakeys

  @doc """
  Derive pubkey from provided seckey

  Inputs
    - `seckey` 32 byte long binary
    - `type` one of `:xonly`, `:compressed` or `:uncompressed`

  Output
    - `pubkey` serialization type depends on the type provided

  A correctly sized `seckey` that is not a valid secret scalar raises `ArgumentError`. A native
  derivation or allocation failure returns `{:error, reason}`.
  """
  @spec pubkey(seckey :: seckey(), type :: pubkey_type()) ::
          pubkey() | {:error, binary() | :allocation_failed}
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
  @spec convert_pubkey(pubkey :: uncompressed_pubkey(), type :: :compressed) ::
          compressed_pubkey() | {:error, binary() | :allocation_failed}
  @spec convert_pubkey(pubkey :: compressed_pubkey(), type :: :uncompressed) ::
          uncompressed_pubkey() | {:error, binary() | :allocation_failed}
  @spec convert_pubkey(pubkey :: compressed_pubkey(), type :: :xonly) ::
          xonly_pubkey() | {:error, binary() | :allocation_failed}
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
  defdelegate ec_seckey_tweak_add(seckey, tweak), to: Secp256k1.Extrakeys

  @doc """
  Adds a scalar multiple of the generator to a compressed or uncompressed public key.

  The output preserves the input serialization format. This is the public-key
  counterpart of `ec_seckey_tweak_add/2` for BIP-32-style public derivation.
  """
  @spec ec_pubkey_tweak_add(full_pubkey(), tweak()) ::
          compressed_pubkey()
          | uncompressed_pubkey()
          | {:error, binary() | :allocation_failed}
  defdelegate ec_pubkey_tweak_add(pubkey, tweak), to: Secp256k1.Extrakeys

  @doc """
  Tweaks a secret key using x-only semantics for signing Taproot outputs.

  The keypair is normalized to an even-Y internal public key before adding the tweak.
  """
  @spec xonly_seckey_tweak_add(seckey(), tweak()) ::
          seckey() | {:error, binary() | :allocation_failed}
  defdelegate xonly_seckey_tweak_add(seckey, tweak), to: Secp256k1.Extrakeys

  @doc """
  Adds a scalar tweak to an x-only internal public key.

  Returns the x-only output key and its full-point parity. Keep both values when
  constructing and verifying Taproot commitments.
  """
  @spec xonly_pubkey_tweak_add(xonly_pubkey(), tweak()) ::
          {:ok, xonly_pubkey(), pubkey_parity()}
          | {:error, binary() | :allocation_failed}
  defdelegate xonly_pubkey_tweak_add(internal_pubkey, tweak), to: Secp256k1.Extrakeys

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
  defdelegate xonly_pubkey_tweak_add_check(tweaked_pubkey, parity, internal_pubkey, tweak),
    to: Secp256k1.Extrakeys

  @doc """
  Generate new secp256k1 keypair

  Input
    - `type` (see `pubkey/2`)

  Output
    - 2-tuple with seckey on the first place and pubkey on the second place, or
      `{:error, reason}` when public-key derivation fails (see `pubkey/2`)
  """
  @spec keypair(type :: pubkey_type()) ::
          {seckey(), pubkey()} | {:error, binary() | :allocation_failed}
  def keypair(type) when type in [:xonly, :compressed, :uncompressed] do
    keypair(:crypto.strong_rand_bytes(32), type)
  end

  @doc """
  Generate new secp256k1 keypair from provided seckey

  For options and errors see `pubkey/2`. Returns `{:error, reason}` instead of a keypair when
  public-key derivation fails.
  """
  @spec keypair(seckey :: seckey(), type :: pubkey_type()) ::
          {seckey(), pubkey()} | {:error, binary() | :allocation_failed}
  def keypair(seckey, type)
      when is_seckey(seckey) and type in [:xonly, :compressed, :uncompressed] do
    case pubkey(seckey, type) do
      {:error, _reason} = error -> error
      pubkey -> {seckey, pubkey}
    end
  end

  @doc """
  Compute libsecp256k1's default hashed ECDH shared secret.

  Inputs
    - `seckey` 32 byte long binary
    - `pubkey` compressed or uncompressed secp256k1 public key

  Output
    - `shared_secret` 32 byte binary, or `{:error, reason}` when `pubkey` does not encode a
      valid secp256k1 public key

  This wraps libsecp256k1's ECDH module. It returns the upstream library's
  default hashed ECDH output, currently SHA256 over the compressed shared point.
  For generic raw ECDH, use `:crypto.compute_key/4`.
  """
  @spec ecdh(seckey :: seckey(), pubkey :: full_pubkey()) ::
          shared_secret() | {:error, binary() | :allocation_failed}
  defdelegate ecdh(seckey, pubkey), to: Secp256k1.ECDH

  @doc """
  Create an ECDSA signature

  Inputs
    - `msg_hash` 32 byte long message hash to sign
    - `seckey` 32 byte long binary

  Output
    - `signature` ECDSA signature serialized in compact `r || s` format (64 byte binary)
  """
  @spec ecdsa_sign(msg_hash :: hash(), seckey :: seckey()) ::
          ecdsa_sig() | {:error, binary() | :allocation_failed}
  defdelegate ecdsa_sign(msg_hash, seckey), to: Secp256k1.ECDSA, as: :sign

  @doc """
  Serializes a compact 64-byte ECDSA signature as strict DER.

  The result does not include a Bitcoin transaction sighash byte.
  """
  @spec ecdsa_signature_serialize_der(ecdsa_sig()) ::
          ecdsa_der_sig() | {:error, binary() | :allocation_failed}
  defdelegate ecdsa_signature_serialize_der(signature), to: Secp256k1.ECDSA, as: :serialize_der

  @doc """
  Parses an 8-72-byte strict DER ECDSA signature into compact 64-byte `r || s` form.

  Remove any trailing Bitcoin transaction sighash byte before parsing. Wrong-sized
  input raises `FunctionClauseError`; malformed DER in the accepted size range
  raises `ArgumentError`.
  """
  @spec ecdsa_signature_parse_der(ecdsa_der_sig()) ::
          ecdsa_sig() | {:error, binary() | :allocation_failed}
  defdelegate ecdsa_signature_parse_der(signature), to: Secp256k1.ECDSA, as: :parse_der

  @doc """
  Converts a compact ECDSA signature to the low-S form required by libsecp256k1 verification.

  Already-normalized signatures are returned unchanged. Normalization accepts a
  malleable alternate encoding; use it only when the protocol deliberately accepts
  mathematical equivalence, and use the normalized bytes thereafter. Protocols
  requiring canonical low-S signatures should reject high-S instead.
  """
  @spec ecdsa_signature_normalize(ecdsa_sig()) ::
          ecdsa_sig() | {:error, binary() | :allocation_failed}
  defdelegate ecdsa_signature_normalize(signature), to: Secp256k1.ECDSA, as: :normalize

  @doc """
  Validate ECDSA signature.

  High-S signatures return `false`. Normalize only if the surrounding protocol
  deliberately accepts malleable signature encodings.

  Inputs
    - `signature` 64 byte long binary
    - `msg_hash` 32 byte long message hash that was signed
    - `pubkey` compressed (33-byte) or uncompressed (65-byte) public key
  """
  @spec ecdsa_valid?(signature :: ecdsa_sig(), msg_hash :: hash(), pubkey :: full_pubkey()) ::
          boolean()
  defdelegate ecdsa_valid?(signature, msg_hash, pubkey), to: Secp256k1.ECDSA, as: :valid?

  @doc """
  Calculate Schnorr signature according to BIP 340

  Inputs
    - `message` binary of any length. BIP-340 signs arbitrary-length messages; sign exactly the
      bytes your protocol specifies. Bitcoin Taproot and Nostr, for example, sign a 32-byte
      hash. Messages larger than 65_536 bytes are signed on a dirty CPU scheduler.
    - `seckey` 32 byte long binary

  Output
    - `signature` Schnorr signature is 64 byte long binary, or `{:error, reason}` when signing
      fails

  _Note:_ automatic random nonce is added to every run so generated signature is not deterministic
  """
  @spec schnorr_sign(message :: binary(), seckey :: seckey()) ::
          schnorr_sig() | {:error, binary() | :allocation_failed}
  defdelegate schnorr_sign(message, seckey), to: Secp256k1.Schnorr, as: :sign

  @doc """
  Validate Schnorr signature

  Inputs
    - `signature` 64 byte long binary
    - `message` the exact signed binary, of any length. Messages larger than 65_536 bytes are
      verified on a dirty CPU scheduler.
    - `pubkey` xonly pubkey (32 byte long binary)
  """
  @spec schnorr_valid?(
          signature :: schnorr_sig(),
          message :: binary(),
          pubkey :: xonly_pubkey()
        ) :: boolean()
  defdelegate schnorr_valid?(signature, message, pubkey), to: Secp256k1.Schnorr, as: :valid?
end
