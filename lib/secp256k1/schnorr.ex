defmodule Secp256k1.Schnorr do
  @moduledoc """
  Module implementing Schnorr signatures as defined in BIP340

  BIP340 signs and verifies messages of any length. Sign exactly the bytes your protocol
  specifies: Bitcoin Taproot and Nostr, for example, sign a 32-byte hash.

  Messages larger than 65_536 bytes are signed and verified on dirty CPU schedulers so that
  hashing them does not block a normal BEAM scheduler. Smaller messages run on the calling
  normal scheduler.
  """

  import Secp256k1.Guards

  @dirty_message_threshold 65_536

  @doc """
  Generate Schnorr signature of message (32-byte hash or arbitrary-length message)

  ## Examples

  ### Sign a 32-byte hash

      iex> {seckey, _} = Secp256k1.keypair(:xonly)
      iex> msg_hash = :crypto.hash(:sha256, "hello")
      iex> signature = Secp256k1.Schnorr.sign(msg_hash, seckey)
      iex> byte_size(signature)
      64

  ### Sign an arbitrary message

      iex> {seckey, _} = Secp256k1.keypair(:xonly)
      iex> message = "This is a long message that is not 32 bytes"
      iex> signature = Secp256k1.Schnorr.sign(message, seckey)
      iex> byte_size(signature)
      64

  """
  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def sign(message, seckey) when is_hash(message) and is_seckey(seckey),
    do: sign32(message, seckey)

  def sign(message, seckey) when is_binary(message) and is_seckey(seckey),
    do: sign_custom(message, seckey)

  @doc """
  Generate Schnorr signature of a hash (AUX is randomly generated)
  """
  @spec sign32(msg_hash :: Secp256k1.hash(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def sign32(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    sign32(msg_hash, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate Schnorr signature of a hash and specify AUX - NOT RECOMMENDED
  """
  @spec sign32(
          msg_hash :: Secp256k1.hash(),
          seckey :: Secp256k1.seckey(),
          aux :: <<_::256>>
        ) :: Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def sign32(msg_hash, seckey, aux)
      when is_hash(msg_hash) and is_seckey(seckey) and is_bin_size(aux, 32) do
    Secp256k1.NIF.schnorr_sign32(msg_hash, seckey, aux)
  end

  @doc """
  Generate Schnorr signature of arbitrary message (AUX is randomly generated)
  """
  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def sign_custom(message, seckey) when is_binary(message) and is_seckey(seckey) do
    sign_custom(message, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate Schnorr signature of a arbitrary message and specify AUX - NOT RECOMMENDED
  """
  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey(), aux :: <<_::256>>) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def sign_custom(message, seckey, aux)
      when is_binary(message) and is_seckey(seckey) and is_bin_size(aux, 32) do
    if byte_size(message) > @dirty_message_threshold do
      Secp256k1.NIF.schnorr_sign_custom_dirty(message, seckey, aux)
    else
      Secp256k1.NIF.schnorr_sign_custom(message, seckey, aux)
    end
  end

  @doc """
  Validate Schnorr signature of a message of any length

  ## Examples

      iex> {seckey, pubkey} = Secp256k1.keypair(:xonly)
      iex> msg_hash = :crypto.hash(:sha256, "hello")
      iex> signature = Secp256k1.Schnorr.sign(msg_hash, seckey)
      iex> Secp256k1.Schnorr.valid?(signature, msg_hash, pubkey)
      true

  """
  @spec valid?(
          signature :: Secp256k1.schnorr_sig(),
          message :: binary(),
          pubkey :: Secp256k1.xonly_pubkey()
        ) :: boolean()
  def valid?(signature, message, pubkey)
      when is_schnorr_sig(signature) and is_binary(message) and is_xonly_pubkey(pubkey) do
    if byte_size(message) > @dirty_message_threshold do
      Secp256k1.NIF.schnorr_valid_dirty?(signature, message, pubkey)
    else
      Secp256k1.NIF.schnorr_valid?(signature, message, pubkey)
    end
  end
end
