defmodule Secp256k1.MuSig do
  @moduledoc """
  Module implementing MuSig2 multi-signatures as defined in BIP327.
  EXPERIMENTAL: This module uses experimental features of libsecp256k1.

  ## Signing transcript

  Every signer runs the same steps over the same public data. The values below form one
  signing transcript. The resources remember part of the transcript, so some mixes are
  rejected (see "Transcript checks" below); keeping the rest consistent is the caller's
  responsibility.

    1. `pubkey_agg/1` - every signer passes the same list of individual full public keys
       (33-byte compressed or 65-byte uncompressed) **in the same order**. The order changes
       the aggregate key; this function does not sort. Agree on an order out of band, for
       example BIP327 `KeySort`, which sorts 33-byte compressed keys lexicographically
       (`Enum.sort/1`). Apply any `pubkey_ec_tweak_add/2` or `pubkey_xonly_tweak_add/2`
       tweaks identically, in the same order, and use the returned cache from then on.
    2. `nonce_gen/2` - each signer generates a fresh nonce pair for its own key. `pubkey` must
       be that signer's individual public key from the aggregated list, and the secret key
       later passed to `partial_sign/4` must derive it. Pass the secret key here when
       available; a secret key that does not derive `pubkey` raises `ArgumentError`. Pass the
       message and the cache (after all tweaks) too when they are already known, so
       `partial_sign/4` can check them. Signers then exchange the serialized public nonces.
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

  ## Transcript checks

  A session remembers the key aggregation cache and the message given to `nonce_process/3`.
  A secret nonce remembers the public key given to `nonce_gen/2` and, when they were given,
  the message and the cache. Caches are compared by value: a cache recomputed from the same
  keys and tweaks matches.

    * `partial_sign/4` returns an error and consumes the secret nonce when the cache is not
      the session's (`{:error, "keyagg cache does not match session"}`), when the secret
      nonce was generated for another cache
      (`{:error, "secnonce was generated for a different keyagg cache"}`) or another message
      (`{:error, "secnonce was generated for a different message"}`), or when the secret key
      does not derive the secret nonce's public key
      (`{:error, "secret key does not match secnonce public key"}`).
    * `partial_sig_verify/5` returns `false` when the cache is not the session's.

  Other transcript values are not cross-checked. The caller must still ensure that:

    * the signer's public key is in the list passed to `pubkey_agg/1`;
    * the aggregate nonce passed to `nonce_process/3` includes the signer's public nonce;
    * the partial signatures passed to `partial_sig_agg/2` were made for that session (verify
      each one with `partial_sig_verify/5` first);
    * the message and cache match the transcript when `nonce_gen/2` did not receive them.
      Pass both to `nonce_gen/2` whenever they are known.

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
    * Hot code upgrades that change the library version are not supported while MuSig
      resources are live. Resources created by a different version are not taken over by the
      new native code; using them raises `ArgumentError`.

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
      {:ok, alice_secnonce, alice_pubnonce} =
        Secp256k1.MuSig.nonce_gen(alice_pub, seckey: alice_sec, msg: msg_hash, cache: cache)

      {:ok, bob_secnonce, bob_pubnonce} =
        Secp256k1.MuSig.nonce_gen(bob_pub, seckey: bob_sec, msg: msg_hash, cache: cache)

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

  @typedoc """
  Key aggregation cache resource returned by `pubkey_agg/1` and the tweak functions.

  Node-local and immutable: tweaking returns a new cache. Cannot be serialized.
  """
  @opaque keyagg_cache :: reference()

  @typedoc """
  Signing session resource returned by `nonce_process/3`.

  Node-local; derived from the aggregate nonce and remembers the message and key aggregation
  cache it was processed from. Cannot be serialized.
  """
  @opaque session :: reference()

  @typedoc """
  One-use secret nonce resource returned by `nonce_gen/2`.

  Node-local and shared by reference: `partial_sign/4` consumes it for every holder. Never
  persist, send to another node, or reuse it.
  """
  @opaque secnonce :: reference()

  @typedoc "Serialized 66-byte public nonce from `nonce_gen/2`; safe to transmit."
  @type pubnonce :: <<_::528>>

  @typedoc "Serialized 66-byte aggregate nonce from `nonce_agg/1`; safe to transmit."
  @type aggnonce :: <<_::528>>

  @typedoc "Serialized 32-byte partial signature from `partial_sign/4`; safe to transmit."
  @type partial_sig :: <<_::256>>

  @typedoc """
  Option for `nonce_gen/2`. Every option is optional; `nil` is the same as leaving it out.
  """
  @type nonce_gen_opt ::
          {:seckey, Secp256k1.seckey() | nil}
          | {:msg, Secp256k1.hash() | nil}
          | {:cache, keyagg_cache() | nil}
          | {:extra, <<_::256>> | nil}

  @doc """
  Aggregates individual full public keys.

  All signers must pass the same keys in the same order. The guard checks only that the list
  is non-empty: elements that are not binaries, x-only keys, and unparsable public keys raise
  `ArgumentError`.

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

  Returns the tweaked full public key in compressed form and a new cache. The input cache is
  not modified. Use the returned cache for the rest of the signing transcript.
  """
  @spec pubkey_ec_tweak_add(keyagg_cache(), Secp256k1.tweak()) ::
          {:ok, Secp256k1.compressed_pubkey(), keyagg_cache()}
          | {:error, binary() | :allocation_failed}
  def pubkey_ec_tweak_add(cache, tweak) when is_reference(cache) and is_tweak(tweak),
    do: Secp256k1.NIF.musig_pubkey_ec_tweak_add(cache, tweak)

  @doc """
  Applies an x-only tweak to the aggregated public key.

  Returns the tweaked full public key in compressed form and a new cache. The input cache is
  not modified. Use the returned cache for the rest of the signing transcript.
  """
  @spec pubkey_xonly_tweak_add(keyagg_cache(), Secp256k1.tweak()) ::
          {:ok, Secp256k1.compressed_pubkey(), keyagg_cache()}
          | {:error, binary() | :allocation_failed}
  def pubkey_xonly_tweak_add(cache, tweak) when is_reference(cache) and is_tweak(tweak),
    do: Secp256k1.NIF.musig_pubkey_xonly_tweak_add(cache, tweak)

  @doc """
  Generates a fresh nonce pair for one signer.

  `pubkey` is the signer's individual full public key, as passed to `pubkey_agg/1`. The
  secret key later passed to `partial_sign/4` must derive it. Unparsable keys raise
  `ArgumentError`.

  ## Options

    * `:seckey` - the signer's secret key. When given, it must be a valid secret scalar that
      derives `pubkey`; otherwise this raises `ArgumentError`. Passing it strengthens nonce
      derivation against bad randomness.
    * `:msg` - the 32-byte message that will be signed, if already known.
    * `:cache` - the key aggregation cache of this signing transcript, after all tweaks.
    * `:extra` - 32 bytes of extra input for nonce derivation.

  `opts` is a keyword list. Every option defaults to `nil`, meaning not given. An unknown
  option raises `ArgumentError`; `opts` that is not a list, or an option value of the wrong
  type or size, raises `FunctionClauseError`.

  Returns a secret nonce resource and a serialized public nonce. The secret nonce is bound to
  `pubkey` and, when given, to `:msg` and `:cache`: `partial_sign/4` rejects a session for
  another message or another cache. Without them, that value is not checked, so pass `:msg`
  and `:cache` whenever they are known. Call this for every signing attempt; never reuse a
  secret nonce.

  Returns `{:error, "RNG failed"}` when the operating system's random number generator
  fails; no nonce is created.

  ## Examples

      {:ok, secnonce, pubnonce} =
        Secp256k1.MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg_hash, cache: cache)
  """
  @spec nonce_gen(Secp256k1.full_pubkey(), [nonce_gen_opt()]) ::
          {:ok, secnonce(), pubnonce()} | {:error, binary() | :allocation_failed}
  def nonce_gen(pubkey, opts \\ []) when is_full_pubkey(pubkey) and is_list(opts) do
    # Keyword.validate!/2 would put the whole option list, secret key included, into the
    # exception message; report only the offending keys.
    case Keyword.validate(opts, seckey: nil, msg: nil, cache: nil, extra: nil) do
      {:ok, opts} ->
        nonce_gen_nif(opts[:seckey], pubkey, opts[:msg], opts[:cache], opts[:extra])

      {:error, keys} ->
        raise ArgumentError,
              "invalid nonce_gen/2 options #{inspect(keys)}; " <>
                "allowed keys are :seckey, :msg, :cache, and :extra"
    end
  end

  defp nonce_gen_nif(seckey, pubkey, msg, cache, extra)
       when (is_nil(seckey) or is_seckey(seckey)) and (is_nil(msg) or is_hash(msg)) and
              (is_nil(cache) or is_reference(cache)) and
              (is_nil(extra) or is_musig_nonce_extra(extra)),
       do: Secp256k1.NIF.musig_nonce_gen(seckey, pubkey, msg, cache, extra)

  @doc """
  Aggregates the public nonces of all signers.

  The guard checks only that the list is non-empty: elements that are not 66-byte binaries,
  and unparsable public nonces, raise `ArgumentError`.
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
      when is_musig_aggnonce(aggnonce) and is_hash(msg) and is_reference(cache),
      do: Secp256k1.NIF.musig_nonce_process(aggnonce, msg, cache)

  @doc """
  Creates a partial signature.

  `secnonce` must come from this signer's `nonce_gen/2` call, `seckey` must derive the public
  key passed to that call, and `cache` and `session` must belong to the same signing
  transcript. See "Transcript checks" in the module documentation for what is checked.

  An invalid secret scalar or a resource of the wrong kind raises `ArgumentError` without
  consuming the nonce. Any call that returns consumes it, from whichever process makes it:
  the nonce is marked used and erased even when signing fails. These errors are returned:

    * `{:error, "keyagg cache does not match session"}` - `cache` differs from the cache
      given to `nonce_process/3`.
    * `{:error, "secnonce was generated for a different keyagg cache"}` - `nonce_gen/2`
      received a different cache.
    * `{:error, "secnonce was generated for a different message"}` - `nonce_gen/2` received
      a message other than the session's.
    * `{:error, "secret key does not match secnonce public key"}` - `seckey` does not derive
      the public key given to `nonce_gen/2`.
    * `{:error, :allocation_failed}` - the partial signature was computed but its binary
      could not be allocated. The nonce is consumed and the partial signature is lost: start
      a new signing attempt with fresh nonces.
    * `{:error, "nonce already used"}` - every call after the nonce was consumed.
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
    `nonce_gen/2`.
  - `cache`: The key aggregation cache of this signing transcript.
  - `session`: The session returned by `nonce_process/3` for this signing transcript.

  Returns `false` when the partial signature does not verify, or when `cache` differs from
  the cache given to `nonce_process/3` for `session`. Unparsable partial signatures, public
  nonces, or public keys raise `ArgumentError`.
  """
  @spec partial_sig_verify(
          partial_sig(),
          pubnonce(),
          Secp256k1.full_pubkey(),
          keyagg_cache(),
          session()
        ) :: boolean()
  def partial_sig_verify(psig, pubnonce, pubkey, cache, session)
      when is_musig_partial_sig(psig) and is_musig_pubnonce(pubnonce) and is_reference(cache) and
             is_reference(session) and is_full_pubkey(pubkey),
      do: Secp256k1.NIF.musig_partial_sig_verify(psig, pubnonce, pubkey, cache, session)

  @doc """
  Aggregates partial signatures into the final BIP340 Schnorr signature.

  The guard checks only that the list is non-empty: elements that are not 32-byte binaries,
  and unparsable partial signatures, raise `ArgumentError`. Aggregation does not verify
  partial signatures or check that they belong to `session`; use `partial_sig_verify/5`
  first.
  """
  @spec partial_sig_agg(session(), [partial_sig()]) ::
          Secp256k1.schnorr_sig() | {:error, binary() | :allocation_failed}
  def partial_sig_agg(session, partial_sigs)
      when is_reference(session) and is_list(partial_sigs) and partial_sigs != [],
      do: Secp256k1.NIF.musig_partial_sig_agg(session, partial_sigs)
end
