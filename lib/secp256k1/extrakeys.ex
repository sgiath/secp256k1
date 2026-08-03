defmodule Secp256k1.Extrakeys do
  @moduledoc """
  Module implementing extrakeys functions of secp256k1
  """

  import Secp256k1.Guards

  @doc """
  Derive xonly pubkey from seckey

  ## Examples

      iex> {seckey, _} = Secp256k1.keypair(:compressed)
      iex> xonly = Secp256k1.Extrakeys.xonly_pubkey(seckey)
      iex> byte_size(xonly)
      32

  """
  @spec xonly_pubkey(Secp256k1.seckey()) :: Secp256k1.xonly_pubkey()
  def xonly_pubkey(seckey) when is_seckey(seckey), do: xonly_pubkey_nif(seckey)

  @doc """
  Adds a scalar tweak to a secret key.

  This is the private-key counterpart of `ec_pubkey_tweak_add/2`. The tweak must be a
  32-byte scalar less than the secp256k1 curve order; zero is allowed. Returns an error
  when the tweak is invalid or the resulting secret key would be zero.
  """
  @spec ec_seckey_tweak_add(Secp256k1.seckey(), Secp256k1.tweak()) ::
          Secp256k1.seckey() | {:error, binary() | :allocation_failed}
  def ec_seckey_tweak_add(seckey, tweak) when is_seckey(seckey) and is_tweak(tweak),
    do: ec_seckey_tweak_add_nif(seckey, tweak)

  @doc """
  Adds a scalar multiple of the generator to a full public key.

  Compressed input produces compressed output and uncompressed input produces
  uncompressed output. Returns an error for an invalid key or tweak, or when the
  resulting point would be at infinity.
  """
  @spec ec_pubkey_tweak_add(
          Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey(),
          Secp256k1.tweak()
        ) ::
          Secp256k1.compressed_pubkey()
          | Secp256k1.uncompressed_pubkey()
          | {:error, binary() | :allocation_failed}
  def ec_pubkey_tweak_add(pubkey, tweak)
      when (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             is_tweak(tweak),
      do: ec_pubkey_tweak_add_nif(pubkey, tweak)

  @doc """
  Tweaks a secret key using x-only public-key semantics.

  Before adding the tweak, this normalizes the keypair so its public key has even Y.
  Use this result to sign for the output returned by `xonly_pubkey_tweak_add/2`.
  """
  @spec xonly_seckey_tweak_add(Secp256k1.seckey(), Secp256k1.tweak()) ::
          Secp256k1.seckey() | {:error, binary() | :allocation_failed}
  def xonly_seckey_tweak_add(seckey, tweak)
      when is_seckey(seckey) and is_tweak(tweak),
      do: xonly_seckey_tweak_add_nif(seckey, tweak)

  @doc """
  Adds a scalar tweak to an x-only public key.

  Returns the tweaked x-only public key together with the parity of the full output
  point. The parity is required to verify the tweak with
  `xonly_pubkey_tweak_add_check/4`.
  """
  @spec xonly_pubkey_tweak_add(Secp256k1.xonly_pubkey(), Secp256k1.tweak()) ::
          {:ok, Secp256k1.xonly_pubkey(), Secp256k1.pubkey_parity()}
          | {:error, binary() | :allocation_failed}
  def xonly_pubkey_tweak_add(internal_pubkey, tweak)
      when is_xonly_pubkey(internal_pubkey) and is_tweak(tweak),
      do: xonly_pubkey_tweak_add_nif(internal_pubkey, tweak)

  @doc """
  Checks an x-only public-key tweak result, including its parity.

  This verifies the key-tweak arithmetic. It does not verify that the tweak was built
  as a BIP-341 Taproot commitment.
  """
  @spec xonly_pubkey_tweak_add_check(
          Secp256k1.xonly_pubkey(),
          Secp256k1.pubkey_parity(),
          Secp256k1.xonly_pubkey(),
          Secp256k1.tweak()
        ) :: boolean()
  def xonly_pubkey_tweak_add_check(tweaked_pubkey, parity, internal_pubkey, tweak)
      when is_xonly_pubkey(tweaked_pubkey) and parity in [0, 1] and
             is_xonly_pubkey(internal_pubkey) and is_tweak(tweak),
      do: xonly_pubkey_tweak_add_check_nif(tweaked_pubkey, parity, internal_pubkey, tweak)

  @doc false
  def xonly_pubkey_nif(_seckey), do: :erlang.nif_error({:error, :not_loaded})

  @doc false
  def ec_seckey_tweak_add_nif(_seckey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  @doc false
  def ec_pubkey_tweak_add_nif(_pubkey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  @doc false
  def xonly_seckey_tweak_add_nif(_seckey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  @doc false
  def xonly_pubkey_tweak_add_nif(_pubkey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  @doc false
  def xonly_pubkey_tweak_add_check_nif(_tweaked_pubkey, _parity, _internal_pubkey, _tweak),
    do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/extrakeys")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
