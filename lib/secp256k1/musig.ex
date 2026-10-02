defmodule Secp256k1.MuSig do
  @moduledoc """
  Module implementing MuSig2 multi-signatures as defined in BIP327.
  EXPERIMENTAL: This module uses experimental features of libsecp256k1.

  ## Signing transcript

  Every signer runs the same steps over the same public data. The values below form one
  signing transcript; mixing values from different transcripts makes signing or verification
  fail.

    1. `pubkey_agg/1` - every signer passes the same list of individual full public keys
       (33-byte compressed or 65-byte uncompressed) **in the same order**. The order changes
       the aggregate key; this function does not sort. Agree on an order out of band, for
       example BIP327 `KeySort`, which sorts 33-byte compressed keys lexicographically
       (`Enum.sort/1`). Apply any `pubkey_ec_tweak_add/2` or `pubkey_xonly_tweak_add/2`
       tweaks identically, in the same order, and use the returned cache from then on.
    2. `nonce_gen/5` - each signer generates a fresh nonce pair for its own key. `pubkey` must
       be that signer's individual public key from the aggregated list, and the secret key
       later passed to `partial_sign/4` must derive it. Pass the secret key here when
       available; a secret key that does not derive `pubkey` raises `ArgumentError`. Signers
       then exchange the serialized public nonces.
    3. `nonce_agg/1` - aggregate all signers' public nonces into one aggregate nonce.
    4. `nonce_process/3` - each signer creates a session from the aggregate nonce, the 32-byte
       message, and the key aggregation cache from step 1.
    5. `partial_sign/4` - each signer signs with its own secret nonce, its own secret key, the
       cache, and the session. Signers then exchange partial signatures.
    6. `partial_sig_verify/5` - verify each received partial signature against the signer's
       public nonce from step 2, the signer's individual public key from step 1, the cache,
       and the session. Identifies a misbehaving signer before aggregation.
    7. `partial_sig_agg/2` - aggregate the partial signatures with the session into a BIP340
       Schnorr signature that verifies against the aggregate x-only public key with
       `Secp256k1.Schnorr.valid?/3`.

  ## Resources

  Key aggregation caches, signing sessions, and secret nonces are NIF resources, not binaries.
  Each is a reference to native memory owned by the current BEAM node:

    * Any process on the same node can use the reference, for example after it is sent in a
      message or stored in ETS.
    * Sending or sharing a secret nonce reference does not copy the nonce. All copies of the
      reference point to the same nonce, and `partial_sign/4` enforces one use across all
      processes.
    * Resources cannot be persisted or used on another node. `:erlang.term_to_binary/1`
      encodes only a handle to the live object, never the nonce, cache, or session state.
      Decoding it on another node, in another VM, or after the object was garbage collected
      produces a stale reference that raises `ArgumentError`.

  Public nonces, aggregate nonces, partial signatures, and final signatures are serialized
  binaries that can be stored and transmitted.

  ## Example

      # 1. Key aggregation: every signer uses the same ordered list
      {alice_sec, alice_pub} = Secp256k1.keypair(:compressed)
      {bob_sec, bob_pub} = Secp256k1.keypair(:compressed)
      pubkeys = Enum.sort([alice_pub, bob_pub])

      {:ok, agg_pubkey, cache} = Secp256k1.MuSig.pubkey_agg(pubkeys)

      # 2. Nonce generation: each signer uses its own key pair
      msg_hash = :crypto.hash(:sha256, "Joint Account")
      {:ok, alice_secnonce, alice_pubnonce} = Secp256k1.MuSig.nonce_gen(alice_sec, alice_pub, msg_hash, cache, nil)
      {:ok, bob_secnonce, bob_pubnonce} = Secp256k1.MuSig.nonce_gen(bob_sec, bob_pub, msg_hash, cache, nil)

      # 3. Nonce aggregation
      aggnonce = Secp256k1.MuSig.nonce_agg([alice_pubnonce, bob_pubnonce])

      # 4. Session setup
      session = Secp256k1.MuSig.nonce_process(aggnonce, msg_hash, cache)

      # 5. Partial signing
      alice_sig = Secp256k1.MuSig.partial_sign(alice_secnonce, alice_sec, cache, session)
      bob_sig = Secp256k1.MuSig.partial_sign(bob_secnonce, bob_sec, cache, session)

      # 6. Partial signature verification
      true = Secp256k1.MuSig.partial_sig_verify(alice_sig, alice_pubnonce, alice_pub, cache, session)
      true = Secp256k1.MuSig.partial_sig_verify(bob_sig, bob_pubnonce, bob_pub, cache, session)

      # 7. Signature aggregation and verification
      final_sig = Secp256k1.MuSig.partial_sig_agg(session, [alice_sig, bob_sig])
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
  Aggregates individual full public keys.

  All signers must pass the same keys in the same order. X-only or unparsable public keys
  raise `ArgumentError`.

  Returns the aggregated x-only public key and a key aggregation cache resource.
  """
  @spec pubkey_agg([Secp256k1.full_pubkey()]) ::
          {:ok, Secp256k1.xonly_pubkey(), keyagg_cache()}
          | {:error, binary() | :allocation_failed}
  def pubkey_agg(pubkeys) when is_list(pubkeys) and pubkeys != [],
    do: Secp256k1.NIF.musig_pubkey_agg(pubkeys)

  @doc """
  Gets the full aggregate public key from the key aggregation cache, in compressed form.
  """
  @spec pubkey_get(keyagg_cache()) ::
          Secp256k1.compressed_pubkey() | {:error, binary() | :allocation_failed}
  def pubkey_get(cache) when is_reference(cache), do: Secp256k1.NIF.musig_pubkey_get(cache)

  @doc """
  Applies a plain EC tweak to the aggregated public key.

  Returns a new cache and the tweaked full public key in compressed form. The input cache is
  not modified. Use the returned cache for the rest of the signing transcript.
  """
  @spec pubkey_ec_tweak_add(keyagg_cache(), Secp256k1.tweak()) ::
          {:ok, keyagg_cache(), Secp256k1.compressed_pubkey()}
          | {:error, binary() | :allocation_failed}
  def pubkey_ec_tweak_add(cache, tweak) when is_reference(cache) and is_tweak(tweak),
    do: Secp256k1.NIF.musig_pubkey_ec_tweak_add(cache, tweak)

  @doc """
  Applies an x-only tweak to the aggregated public key.

  Returns a new cache and the tweaked full public key in compressed form. The input cache is
  not modified. Use the returned cache for the rest of the signing transcript.
  """
  @spec pubkey_xonly_tweak_add(keyagg_cache(), Secp256k1.tweak()) ::
          {:ok, keyagg_cache(), Secp256k1.compressed_pubkey()}
          | {:error, binary() | :allocation_failed}
  def pubkey_xonly_tweak_add(cache, tweak) when is_reference(cache) and is_tweak(tweak),
    do: Secp256k1.NIF.musig_pubkey_xonly_tweak_add(cache, tweak)

  @doc """
  Generates a fresh nonce pair for one signer.

  Arguments:
  - `seckey`: (Optional) The signer's secret key. When given, it must be a valid secret scalar
    that derives `pubkey`; otherwise this raises `ArgumentError`. Passing it strengthens nonce
    derivation against bad randomness.
  - `pubkey`: The signer's individual full public key, as passed to `pubkey_agg/1`. The
    secret key later passed to `partial_sign/4` must derive it. Unparsable keys raise
    `ArgumentError`.
  - `msg`: (Optional) The 32-byte message that will be signed, if already known.
  - `cache`: (Optional) The key aggregation cache of this signing transcript.
  - `extra`: (Optional) 32 bytes of extra input for nonce derivation.

  Returns a secret nonce resource bound to `pubkey` and a serialized public nonce. Call this for
  every signing attempt; never reuse a secret nonce.
  """
  @spec nonce_gen(
          Secp256k1.seckey() | nil,
          Secp256k1.full_pubkey(),
          Secp256k1.hash() | nil,
          keyagg_cache() | nil,
          <<_::256>> | nil
        ) :: {:ok, secnonce(), pubnonce()} | {:error, binary() | :allocation_failed}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def nonce_gen(seckey, pubkey, msg, cache, extra)
      when (is_nil(seckey) or is_seckey(seckey)) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             (is_nil(msg) or is_hash(msg)) and (is_nil(cache) or is_reference(cache)) and
             (is_nil(extra) or is_bin_size(extra, 32)),
      do: Secp256k1.NIF.musig_nonce_gen(seckey, pubkey, msg, cache, extra)

  @doc """
  Aggregates the public nonces of all signers.

  Unparsable public nonces raise `ArgumentError`.
  """
  @spec nonce_agg([pubnonce()]) :: aggnonce() | {:error, binary() | :allocation_failed}
  def nonce_agg(pubnonces) when is_list(pubnonces) and pubnonces != [],
    do: Secp256k1.NIF.musig_nonce_agg(pubnonces)

  @doc """
  Processes the aggregate nonce and creates a signing session for a 32-byte message.

  `cache` must be the key aggregation cache of this signing transcript, including all tweaks.
  An unparsable aggregate nonce raises `ArgumentError`.
  """
  @spec nonce_process(aggnonce(), Secp256k1.hash(), keyagg_cache()) ::
          session() | {:error, binary() | :allocation_failed}
  def nonce_process(aggnonce, msg, cache)
      when is_bin_size(aggnonce, 66) and is_hash(msg) and is_reference(cache),
      do: Secp256k1.NIF.musig_nonce_process(aggnonce, msg, cache)

  @doc """
  Creates a partial signature.

  `secnonce` must come from this signer's `nonce_gen/5` call, `seckey` must derive the public
  key passed to that call, and `cache` and `session` must belong to the same signing
  transcript.

  Calls that raise `ArgumentError` (an invalid secret scalar, or resources of the wrong kind)
  do not consume the nonce. Any other call consumes it, from whichever process makes it: the
  nonce is marked used and erased even when signing fails. A secret key whose public key
  differs from the one bound to the nonce returns
  `{:error, "secret key does not match secnonce public key"}`, and every later call with the
  same nonce returns `{:error, "nonce already used"}`.
  """
  @spec partial_sign(secnonce(), Secp256k1.seckey(), keyagg_cache(), session()) ::
          partial_sig() | {:error, binary() | :allocation_failed}
  def partial_sign(secnonce, seckey, cache, session)
      when is_reference(secnonce) and is_seckey(seckey) and is_reference(cache) and
             is_reference(session),
      do: Secp256k1.NIF.musig_partial_sign(secnonce, seckey, cache, session)

  @doc """
  Verifies one signer's partial signature.

  Arguments:
  - `psig`: The partial signature received from the signer.
  - `pubnonce`: The public nonce the same signer contributed to `nonce_agg/1`.
  - `pubkey`: The same signer's individual full public key, as passed to `pubkey_agg/1` and
    `nonce_gen/5`.
  - `cache`: The key aggregation cache of this signing transcript.
  - `session`: The session returned by `nonce_process/3` for this signing transcript.

  Returns `false` when the partial signature does not verify. Unparsable partial signatures,
  public nonces, or public keys raise `ArgumentError`.
  """
  @spec partial_sig_verify(
          partial_sig(),
          pubnonce(),
          Secp256k1.full_pubkey(),
          keyagg_cache(),
          session()
        ) :: boolean()
  def partial_sig_verify(psig, pubnonce, pubkey, cache, session)
      when is_bin_size(psig, 32) and is_bin_size(pubnonce, 66) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) and
             is_reference(cache) and is_reference(session),
      do: Secp256k1.NIF.musig_partial_sig_verify(psig, pubnonce, pubkey, cache, session)

  @doc """
  Aggregates partial signatures into the final BIP340 Schnorr signature.

  Unparsable partial signatures raise `ArgumentError`. Aggregation does not verify partial
  signatures; use `partial_sig_verify/5` first.
  """
  @spec partial_sig_agg(session(), [partial_sig()]) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def partial_sig_agg(session, partial_sigs)
      when is_reference(session) and is_list(partial_sigs) and partial_sigs != [],
      do: Secp256k1.NIF.musig_partial_sig_agg(session, partial_sigs)
end
