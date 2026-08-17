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

  import Secp256k1.Guards

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
  def pubkey_agg(pubkeys) when is_list(pubkeys) and pubkeys != [],
    do: Secp256k1.NIF.musig_pubkey_agg(pubkeys)

  @doc """
  Gets the full public key from the key aggregation cache.
  """
  @spec pubkey_get(keyagg_cache()) :: Secp256k1.pubkey() | {:error, term()}
  def pubkey_get(cache) when is_reference(cache), do: Secp256k1.NIF.musig_pubkey_get(cache)

  @doc """
  Applies a plain EC tweak to the aggregated public key.

  Returns the new cache and the tweaked public key.
  """
  @spec pubkey_ec_tweak_add(keyagg_cache(), <<_::256>>) ::
          {:ok, keyagg_cache(), Secp256k1.pubkey()} | {:error, term()}
  def pubkey_ec_tweak_add(cache, tweak) when is_reference(cache) and is_bin_size(tweak, 32),
    do: Secp256k1.NIF.musig_pubkey_ec_tweak_add(cache, tweak)

  @doc """
  Applies an x-only tweak to the aggregated public key.

  Returns the new cache and the tweaked public key.
  """
  @spec pubkey_xonly_tweak_add(keyagg_cache(), <<_::256>>) ::
          {:ok, keyagg_cache(), Secp256k1.pubkey()} | {:error, term()}
  def pubkey_xonly_tweak_add(cache, tweak) when is_reference(cache) and is_bin_size(tweak, 32),
    do: Secp256k1.NIF.musig_pubkey_xonly_tweak_add(cache, tweak)

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
          Secp256k1.hash() | nil,
          keyagg_cache() | nil,
          binary() | nil
        ) :: {:ok, secnonce(), pubnonce()} | {:error, term()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def nonce_gen(seckey, pubkey, msg, cache, extra)
      when (is_nil(seckey) or is_seckey(seckey)) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             (is_nil(msg) or is_hash(msg)) and (is_nil(cache) or is_reference(cache)) and
             (is_nil(extra) or is_bin_size(extra, 32)),
      do: Secp256k1.NIF.musig_nonce_gen(seckey, pubkey, msg, cache, extra)

  @doc """
  Aggregates public nonces from all signers.
  """
  @spec nonce_agg([pubnonce()]) :: aggnonce() | {:error, term()}
  def nonce_agg(pubnonces) when is_list(pubnonces) and pubnonces != [],
    do: Secp256k1.NIF.musig_nonce_agg(pubnonces)

  @doc """
  Processes the aggregate nonce and creates a signing session.
  """
  @spec nonce_process(aggnonce(), binary(), keyagg_cache()) :: session() | {:error, term()}
  def nonce_process(aggnonce, msg, cache)
      when is_bin_size(aggnonce, 66) and is_hash(msg) and is_reference(cache),
      do: Secp256k1.NIF.musig_nonce_process(aggnonce, msg, cache)

  @doc """
  Creates a partial signature.

  This function consumes the secret nonce.
  """
  @spec partial_sign(secnonce(), Secp256k1.seckey(), keyagg_cache(), session()) ::
          partial_sig() | {:error, term()}
  def partial_sign(secnonce, seckey, cache, session)
      when is_reference(secnonce) and is_seckey(seckey) and is_reference(cache) and
             is_reference(session),
      do: Secp256k1.NIF.musig_partial_sign(secnonce, seckey, cache, session)

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
  def partial_sig_verify(psig, pubnonce, pubkey, cache, session)
      when is_bin_size(psig, 32) and is_bin_size(pubnonce, 66) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             is_reference(cache) and is_reference(session),
      do: Secp256k1.NIF.musig_partial_sig_verify(psig, pubnonce, pubkey, cache, session)

  @doc """
  Aggregates partial signatures into the final Schnorr signature.
  """
  @spec partial_sig_agg(session(), [partial_sig()]) :: Secp256k1.schnorr_sig() | {:error, term()}
  def partial_sig_agg(session, partial_sigs)
      when is_reference(session) and is_list(partial_sigs) and partial_sigs != [],
      do: Secp256k1.NIF.musig_partial_sig_agg(session, partial_sigs)
end
