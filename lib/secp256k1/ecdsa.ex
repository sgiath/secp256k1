defmodule Secp256k1.ECDSA do
  @moduledoc """
  Module implementing ECDSA pubkey derivation and signatures
  """

  import Secp256k1.Guards

  @doc """
  Derive pubkey from seckey

  ## Options
    - :compress (default true) - whether to format pubkey in compressed or uncompressed format

  ## Examples

      iex> {seckey, _} = Secp256k1.keypair(:compressed)
      iex> pubkey = Secp256k1.ECDSA.pubkey(seckey)
      iex> byte_size(pubkey)
      33

  """
  @spec pubkey(seckey :: Secp256k1.seckey(), opts :: Keyword.t()) ::
          Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
  def pubkey(seckey, opts \\ []) when is_seckey(seckey) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @doc """
  Derive compressed pubkey from seckey
  """
  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.compressed_pubkey()
  def compressed_pubkey(seckey) when is_seckey(seckey),
    do: Secp256k1.NIF.ecdsa_compressed_pubkey(seckey)

  @doc """
  Derive uncompressed pubkey from seckey
  """
  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.uncompressed_pubkey()
  def uncompressed_pubkey(seckey) when is_seckey(seckey),
    do: Secp256k1.NIF.ecdsa_uncompressed_pubkey(seckey)

  @doc """
  Convert uncompressed pubkey to compressed one
  """
  @spec compress_pubkey(pubkey :: Secp256k1.uncompressed_pubkey()) ::
          Secp256k1.compressed_pubkey()
  def compress_pubkey(pubkey) when is_uncompressed_pubkey(pubkey),
    do: Secp256k1.NIF.ecdsa_compress_pubkey(pubkey)

  @doc """
  Convert compressed pubkey to uncompressed one
  """
  @spec decompress_pubkey(pubkey :: Secp256k1.compressed_pubkey()) ::
          Secp256k1.uncompressed_pubkey()
  def decompress_pubkey(pubkey) when is_compressed_pubkey(pubkey),
    do: Secp256k1.NIF.ecdsa_decompress_pubkey(pubkey)

  @doc """
  Generate an ECDSA signature of a message hash with random RFC 6979 additional data.

  ## Examples

      iex> {seckey, _} = Secp256k1.keypair(:compressed)
      iex> msg_hash = :crypto.hash(:sha256, "hello")
      iex> signature = Secp256k1.ECDSA.sign(msg_hash, seckey)
      iex> byte_size(signature)
      64

  """
  @spec sign(msg_hash :: Secp256k1.hash(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.ecdsa_sig()
  def sign(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    sign(msg_hash, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate an ECDSA signature with explicit RFC 6979 additional data.

  > #### Deterministic signing is for tests only {: .warning}
  >
  > Pass `nil` only in tests that require reproducible signatures, such as
  > interoperability and test-vector checks. Use `sign/2` for normal signing.

  A 32-byte value is passed as libsecp256k1 `ndata` to derive a synthetic nonce.
  """
  @spec sign(
          msg_hash :: Secp256k1.hash(),
          seckey :: Secp256k1.seckey(),
          nonce_data :: nil | <<_::256>>
        ) :: Secp256k1.ecdsa_sig()
  def sign(msg_hash, seckey, nonce_data)
      when is_hash(msg_hash) and is_seckey(seckey) and
             (is_nil(nonce_data) or is_bin_size(nonce_data, 32)) do
    Secp256k1.NIF.ecdsa_sign(msg_hash, seckey, nonce_data)
  end

  @doc """
  Serializes a compact 64-byte ECDSA signature as strict DER.

  The returned binary contains only the DER signature. Bitcoin transaction
  sighash bytes are not part of this encoding and must be handled separately.
  """
  @spec serialize_der(signature :: Secp256k1.ecdsa_sig()) ::
          Secp256k1.ecdsa_der_sig() | {:error, binary() | :allocation_failed}
  def serialize_der(signature) when is_ecdsa_sig(signature),
    do: Secp256k1.NIF.ecdsa_serialize_der(signature)

  @doc """
  Parses a standard-sized strict DER ECDSA signature into compact 64-byte `r || s` form.

  Accepts DER signatures from 8 through 72 bytes. Wrong-sized input raises
  `FunctionClauseError`; malformed DER within that range raises `ArgumentError`.
  As in upstream libsecp256k1, syntactically valid DER containing out-of-range
  values parses to a compact signature that cannot verify. A trailing Bitcoin
  transaction sighash byte must be removed before calling this function.
  """
  @spec parse_der(signature :: Secp256k1.ecdsa_der_sig()) ::
          Secp256k1.ecdsa_sig() | {:error, binary() | :allocation_failed}
  def parse_der(signature)
      when is_binary(signature) and byte_size(signature) >= 8 and byte_size(signature) <= 72 do
    Secp256k1.NIF.ecdsa_parse_der(signature)
  end

  @doc """
  Converts a compact ECDSA signature to its low-S form.

  This operation is idempotent. libsecp256k1 verification rejects high-S
  signatures. Normalize only when the protocol deliberately accepts the
  mathematically equivalent high-S form: doing so accepts a malleable signature,
  and all subsequent identity or hashing operations must use the normalized bytes.
  Protocols requiring canonical low-S signatures should reject instead.
  """
  @spec normalize(signature :: Secp256k1.ecdsa_sig()) ::
          Secp256k1.ecdsa_sig() | {:error, binary() | :allocation_failed}
  def normalize(signature) when is_ecdsa_sig(signature),
    do: Secp256k1.NIF.ecdsa_normalize(signature)

  @doc """
  Check if ECDSA signature is valid.

  High-S signatures return `false`. Call `normalize/1` first only when the
  surrounding protocol deliberately accepts malleable signature encodings.

  ## Examples

      iex> {seckey, pubkey} = Secp256k1.keypair(:compressed)
      iex> msg_hash = :crypto.hash(:sha256, "hello")
      iex> signature = Secp256k1.ECDSA.sign(msg_hash, seckey)
      iex> Secp256k1.ECDSA.valid?(signature, msg_hash, pubkey)
      true

  """
  @spec valid?(
          signature :: Secp256k1.ecdsa_sig(),
          msg_hash :: Secp256k1.hash(),
          pubkey :: Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
        ) :: boolean()
  def valid?(signature, msg_hash, pubkey)
      when is_ecdsa_sig(signature) and is_hash(msg_hash) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) do
    Secp256k1.NIF.ecdsa_valid?(signature, msg_hash, pubkey)
  end
end
