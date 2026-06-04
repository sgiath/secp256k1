defmodule Secp256k1.MuSig do
  @moduledoc """
  Module implementing MuSig2 multi-signatures as defined in BIP327.
  EXPERIMENTAL: This module uses experimental features of libsecp256k1.

  Key aggregation caches, signing sessions, and secret nonces are process-local
  NIF resources. They are not binaries and cannot be serialized or sent to
  another BEAM instance. Public nonces, aggregate nonces, partial signatures,
  and final signatures are serialized binaries.

  ## Example

      # 1. Key Aggregation
      {alice_sec, alice_pub} = Secp256k1.keypair(:compressed)
      {bob_sec, bob_pub} = Secp256k1.keypair(:compressed)

      {:ok, agg_pubkey, cache} = Secp256k1.MuSig.pubkey_agg([alice_pub, bob_pub])

      # 2. Nonce Generation
      msg_hash = :crypto.hash(:sha256, "Joint Account")
      {:ok, alice_secnonce, alice_pubnonce} = Secp256k1.MuSig.nonce_gen(alice_sec, alice_pub, msg_hash, cache, nil)
      {:ok, bob_secnonce, bob_pubnonce} = Secp256k1.MuSig.nonce_gen(bob_sec, bob_pub, msg_hash, cache, nil)

      # 3. Nonce Aggregation
      aggnonce = Secp256k1.MuSig.nonce_agg([alice_pubnonce, bob_pubnonce])

      # 4. Session Setup
      session = Secp256k1.MuSig.nonce_process(aggnonce, msg_hash, cache)

      # 5. Partial Signing
      alice_sig = Secp256k1.MuSig.partial_sign(alice_secnonce, alice_sec, cache, session)
      bob_sig = Secp256k1.MuSig.partial_sign(bob_secnonce, bob_sec, cache, session)

      # 6. Signature Aggregation
      final_sig = Secp256k1.MuSig.partial_sig_agg(session, [alice_sig, bob_sig])

      # 7. Verification
      Secp256k1.Schnorr.valid?(final_sig, msg_hash, agg_pubkey)
      # => true
  """

  @opaque keyagg_cache :: reference()
  @opaque session :: reference()
  @opaque secnonce :: reference()
  # 66 bytes
  @type pubnonce :: <<_::528>>
  # 66 bytes
  @type aggnonce :: <<_::528>>
  # 32 bytes
  @type partial_sig :: <<_::256>>

  @doc """
  Aggregates public keys.

  Returns the aggregated x-only public key and a process-local key aggregation
  cache resource.
  """
  @spec pubkey_agg([Secp256k1.pubkey()]) ::
          {:ok, Secp256k1.xonly_pubkey(), keyagg_cache()} | {:error, term()}
  def pubkey_agg(pubkeys) when is_list(pubkeys), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Gets the full public key from the key aggregation cache.
  """
  @spec pubkey_get(keyagg_cache()) :: Secp256k1.pubkey() | {:error, term()}
  def pubkey_get(_cache), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Applies a plain EC tweak to the aggregated public key.

  Returns the new cache and the tweaked public key.
  """
  @spec pubkey_ec_tweak_add(keyagg_cache(), <<_::256>>) ::
          {:ok, keyagg_cache(), Secp256k1.pubkey()} | {:error, term()}
  def pubkey_ec_tweak_add(_cache, _tweak),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Applies an x-only tweak to the aggregated public key.

  Returns the new cache and the tweaked public key.
  """
  @spec pubkey_xonly_tweak_add(keyagg_cache(), <<_::256>>) ::
          {:ok, keyagg_cache(), Secp256k1.pubkey()} | {:error, term()}
  def pubkey_xonly_tweak_add(_cache, _tweak),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Generates a nonce for the signing session.

  Arguments:
  - `seckey`: (Optional) The secret key of the signer.
  - `pubkey`: The public key of the signer.
  - `msg`: (Optional) The message to be signed (32-byte hash).
  - `cache`: (Optional) The key aggregation cache resource.
  - `extra`: (Optional) Extra input for nonce derivation (32 bytes).

  Returns a secret nonce resource and a serialized public nonce.
  """
  @spec nonce_gen(
          Secp256k1.seckey() | nil,
          Secp256k1.pubkey(),
          binary() | nil,
          keyagg_cache() | nil,
          binary() | nil
        ) :: {:ok, secnonce(), pubnonce()} | {:error, term()}
  def nonce_gen(_seckey, _pubkey, _msg, _cache, _extra),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Aggregates public nonces from all signers.
  """
  @spec nonce_agg([pubnonce()]) :: aggnonce() | {:error, term()}
  def nonce_agg(pubnonces) when is_list(pubnonces), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Processes the aggregate nonce and creates a signing session.
  """
  @spec nonce_process(aggnonce(), binary(), keyagg_cache()) :: session() | {:error, term()}
  def nonce_process(_aggnonce, _msg, _cache),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Creates a partial signature.

  This function consumes the secret nonce.
  """
  @spec partial_sign(secnonce(), Secp256k1.seckey(), keyagg_cache(), session()) ::
          partial_sig() | {:error, term()}
  def partial_sign(_secnonce, _seckey, _cache, _session),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Verifies a partial signature.
  """
  @spec partial_sig_verify(
          partial_sig(),
          pubnonce(),
          Secp256k1.pubkey(),
          keyagg_cache(),
          session()
        ) :: boolean()
  def partial_sig_verify(_partial_sig, _pubnonce, _pubkey, _cache, _session),
    do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Aggregates partial signatures into the final Schnorr signature.
  """
  @spec partial_sig_agg(session(), [partial_sig()]) :: Secp256k1.schnorr_sig() | {:error, term()}
  def partial_sig_agg(_session, _partial_sigs), do: :erlang.nif_error({:error, :not_loaded})

  # Internal NIF loading

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/musig")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
