defmodule Secp256k1.MuSigTest do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr
  alias Secp256k1Test.MuSigSubprocess

  test "3-of-3 signing flow" do
    msg = :crypto.strong_rand_bytes(32)

    # 1. Generate keys
    signers =
      for _ <- 1..3 do
        {seckey, pubkey} = Secp256k1.keypair(:compressed)
        %{seckey: seckey, pubkey: pubkey}
      end

    pubkeys = Enum.map(signers, & &1.pubkey)

    # 2. Aggregate public keys
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    assert byte_size(agg_xonly_pubkey) == 32
    assert is_reference(cache)

    # 3. Generate nonces
    # We need to keep the secnonce resource alive
    signers =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} =
          MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, cache, nil)

        assert byte_size(pubnonce) == 66

        Map.merge(signer, %{secnonce: secnonce, pubnonce: pubnonce})
      end)

    pubnonces = Enum.map(signers, & &1.pubnonce)

    # 4. Aggregate nonces
    aggnonce = MuSig.nonce_agg(pubnonces)
    assert byte_size(aggnonce) == 66

    # 5. Process nonces (create session)
    session = MuSig.nonce_process(aggnonce, msg, cache)
    assert is_reference(session)

    # 6. Partial signing
    signers =
      Enum.map(signers, fn signer ->
        partial_sig =
          MuSig.partial_sign(signer.secnonce, signer.seckey, cache, session)

        assert byte_size(partial_sig) == 32

        Map.put(signer, :partial_sig, partial_sig)
      end)

    # 7. Verify partial signatures
    for signer <- signers do
      assert MuSig.partial_sig_verify(
               signer.partial_sig,
               signer.pubnonce,
               signer.pubkey,
               cache,
               session
             )
    end

    # 8. Aggregate signatures
    partial_sigs = Enum.map(signers, & &1.partial_sig)
    final_sig = MuSig.partial_sig_agg(session, partial_sigs)
    assert byte_size(final_sig) == 64

    # 9. Verify final signature
    assert Schnorr.valid?(final_sig, msg, agg_xonly_pubkey)
  end

  test "EC tweak of the cache matches tweaking the aggregate public key" do
    signers = signers(2)
    pubkeys = Enum.map(signers, & &1.pubkey)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)

    agg_pubkey = MuSig.pubkey_get(cache)
    tweak = :crypto.hash(:sha256, "ec tweak")

    assert {:ok, tweaked_pubkey, tweaked_cache} = MuSig.pubkey_ec_tweak_add(cache, tweak)
    assert tweaked_pubkey == Secp256k1.ec_pubkey_tweak_add(agg_pubkey, tweak)
    assert MuSig.pubkey_get(tweaked_cache) == tweaked_pubkey
    assert MuSig.pubkey_get(cache) == agg_pubkey
  end

  test "x-only tweak of the cache matches x-only tweaking of the aggregate key" do
    signers = signers(2)
    pubkeys = Enum.map(signers, & &1.pubkey)
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    agg_pubkey = MuSig.pubkey_get(cache)
    tweak = :crypto.hash(:sha256, "x-only tweak")

    {:ok, expected_xonly_pubkey, parity} =
      Secp256k1.xonly_pubkey_tweak_add(agg_xonly_pubkey, tweak)

    assert {:ok, tweaked_pubkey, tweaked_cache} = MuSig.pubkey_xonly_tweak_add(cache, tweak)
    assert tweaked_pubkey == <<2 + parity, expected_xonly_pubkey::binary>>
    assert MuSig.pubkey_get(tweaked_cache) == tweaked_pubkey
    assert MuSig.pubkey_get(cache) == agg_pubkey
  end

  test "signing with a tweaked cache produces a signature for the tweaked key" do
    signers = signers(2)
    msg = :crypto.strong_rand_bytes(32)
    pubkeys = Enum.map(signers, & &1.pubkey)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    {:ok, _pubkey, cache} = MuSig.pubkey_ec_tweak_add(cache, :crypto.hash(:sha256, "ec tweak"))

    {:ok, <<_prefix, tweaked_xonly_pubkey::binary>>, cache} =
      MuSig.pubkey_xonly_tweak_add(cache, :crypto.hash(:sha256, "x-only tweak"))

    signature = sign_with(signers, msg, cache)

    assert Schnorr.valid?(signature, msg, tweaked_xonly_pubkey)
  end

  test "nonce_gen rejects a secret key that does not derive the signer public key" do
    [signer, other] = signers(2)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([signer.pubkey, other.pubkey])
    msg = :crypto.strong_rand_bytes(32)

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(other.seckey, signer.pubkey, msg, cache, nil)
    end
  end

  test "nonce_gen rejects right-sized invalid secret-key scalars" do
    {_seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)
    curve_order = d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

    for seckey <- [<<0::256>>, curve_order] do
      assert_raise ArgumentError, fn -> MuSig.nonce_gen(seckey, pubkey, msg, cache, nil) end
    end
  end

  test "partial_sign with a mismatched secret key consumes the nonce" do
    [signer, other] = signers(2)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([signer.pubkey, other.pubkey])
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, cache, nil)
    {:ok, _, other_pubnonce} = MuSig.nonce_gen(other.seckey, other.pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce, other_pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)

    assert {:error, "secret key does not match secnonce public key"} =
             MuSig.partial_sign(secnonce, other.seckey, cache, session)

    assert {:error, "nonce already used"} =
             MuSig.partial_sign(secnonce, signer.seckey, cache, session)
  end

  test "partial_sign with a cache other than the session's consumes the nonce" do
    signer = single_signer()
    msg = :crypto.strong_rand_bytes(32)
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, nil, nil)
    session = session_for([pubnonce], msg, signer.cache)

    assert {:error, "keyagg cache does not match session"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.other_cache, session)

    assert {:error, "nonce already used"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.cache, session)
  end

  test "partial_sign rejects a session for a message other than the secnonce's" do
    signer = single_signer()
    nonce_msg = :crypto.strong_rand_bytes(32)
    session_msg = :crypto.hash(:sha256, nonce_msg)

    {:ok, secnonce, pubnonce} =
      MuSig.nonce_gen(signer.seckey, signer.pubkey, nonce_msg, signer.cache, nil)

    session = session_for([pubnonce], session_msg, signer.cache)

    assert {:error, "secnonce was generated for a different message"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.cache, session)

    assert {:error, "nonce already used"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.cache, session)
  end

  test "partial_sign rejects a cache other than the secnonce's" do
    signer = single_signer()
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} =
      MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, signer.cache, nil)

    session = session_for([pubnonce], msg, signer.other_cache)

    assert {:error, "secnonce was generated for a different keyagg cache"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.other_cache, session)

    assert {:error, "nonce already used"} =
             MuSig.partial_sign(secnonce, signer.seckey, signer.other_cache, session)
  end

  test "an independently recomputed equal cache matches the transcript" do
    signers = signers(2)
    pubkeys = Enum.map(signers, & &1.pubkey)
    msg = :crypto.strong_rand_bytes(32)
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    {:ok, ^agg_xonly_pubkey, recomputed_cache} = MuSig.pubkey_agg(pubkeys)

    nonces =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} = MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, cache, nil)
        {secnonce, pubnonce}
      end)

    session =
      nonces
      |> Enum.map(fn {_secnonce, pubnonce} -> pubnonce end)
      |> session_for(msg, recomputed_cache)

    partial_sigs =
      Enum.zip_with(signers, nonces, fn signer, {secnonce, pubnonce} ->
        partial_sig = MuSig.partial_sign(secnonce, signer.seckey, cache, session)

        assert MuSig.partial_sig_verify(
                 partial_sig,
                 pubnonce,
                 signer.pubkey,
                 recomputed_cache,
                 session
               )

        partial_sig
      end)

    signature = MuSig.partial_sig_agg(session, partial_sigs)
    assert Schnorr.valid?(signature, msg, agg_xonly_pubkey)
  end

  test "partial_sign raises for wrong-kind resources without consuming the nonce" do
    signer = single_signer()
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} =
      MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, signer.cache, nil)

    session = session_for([pubnonce], msg, signer.cache)
    %{seckey: seckey, cache: cache} = signer

    swapped_args = [
      [session, seckey, cache, session],
      [cache, seckey, cache, session],
      [secnonce, seckey, session, session],
      [secnonce, seckey, secnonce, session],
      [secnonce, seckey, cache, cache],
      [secnonce, seckey, cache, secnonce]
    ]

    for args <- swapped_args do
      assert_raise ArgumentError, fn -> apply(MuSig, :partial_sign, args) end
    end

    partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)
    assert MuSig.partial_sig_verify(partial_sig, pubnonce, signer.pubkey, cache, session)
  end

  test "partial_sign raises for invalid secret-key scalars without consuming the nonce" do
    signer = single_signer()
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} =
      MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, signer.cache, nil)

    session = session_for([pubnonce], msg, signer.cache)
    curve_order = d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

    for seckey <- [<<0::256>>, curve_order] do
      assert_raise ArgumentError, fn ->
        MuSig.partial_sign(secnonce, seckey, signer.cache, session)
      end
    end

    partial_sig = MuSig.partial_sign(secnonce, signer.seckey, signer.cache, session)
    assert MuSig.partial_sig_verify(partial_sig, pubnonce, signer.pubkey, signer.cache, session)
  end

  test "nonce_gen optional inputs each produce a verifying signature" do
    signers = signers(2)
    msg = :crypto.strong_rand_bytes(32)
    pubkeys = Enum.map(signers, & &1.pubkey)
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    extra = :crypto.strong_rand_bytes(32)

    variants = [
      without_seckey: &MuSig.nonce_gen(nil, &1.pubkey, msg, cache, nil),
      without_msg: &MuSig.nonce_gen(&1.seckey, &1.pubkey, nil, cache, nil),
      without_cache: &MuSig.nonce_gen(&1.seckey, &1.pubkey, msg, nil, nil),
      with_extra: &MuSig.nonce_gen(&1.seckey, &1.pubkey, msg, cache, extra)
    ]

    for {variant, nonce_gen} <- variants do
      signature = sign_with(signers, msg, cache, nonce_gen)
      assert Schnorr.valid?(signature, msg, agg_xonly_pubkey), "#{variant}"
    end
  end

  test "partial_sig_verify returns false for a mismatched signature, signer, session, or cache" do
    [alice, bob] = signers(2)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([alice.pubkey, bob.pubkey])
    {:ok, _pubkey, other_cache} = MuSig.pubkey_ec_tweak_add(cache, :crypto.hash(:sha256, "tweak"))
    msg = :crypto.strong_rand_bytes(32)

    {:ok, alice_secnonce, alice_nonce} =
      MuSig.nonce_gen(alice.seckey, alice.pubkey, msg, cache, nil)

    {:ok, bob_secnonce, bob_nonce} = MuSig.nonce_gen(bob.seckey, bob.pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([alice_nonce, bob_nonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)
    other_msg_session = MuSig.nonce_process(aggnonce, :crypto.hash(:sha256, msg), cache)
    alice_sig = MuSig.partial_sign(alice_secnonce, alice.seckey, cache, session)
    bob_sig = MuSig.partial_sign(bob_secnonce, bob.seckey, cache, session)
    verify = &MuSig.partial_sig_verify(&1, &2, &3, cache, &4)

    assert verify.(alice_sig, alice_nonce, alice.pubkey, session)
    assert verify.(bob_sig, alice_nonce, alice.pubkey, session) == false
    assert verify.(alice_sig, alice_nonce, bob.pubkey, session) == false
    assert verify.(alice_sig, bob_nonce, alice.pubkey, session) == false
    assert verify.(alice_sig, alice_nonce, alice.pubkey, other_msg_session) == false

    assert MuSig.partial_sig_verify(alice_sig, alice_nonce, alice.pubkey, other_cache, session) ==
             false
  end

  test "nonce reuse protection" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)

    sig = MuSig.partial_sign(secnonce, seckey, cache, session)
    assert MuSig.partial_sig_verify(sig, pubnonce, pubkey, cache, session)

    # Second sign with same nonce resource should fail
    assert {:error, "nonce already used"} = MuSig.partial_sign(secnonce, seckey, cache, session)
  end

  test "nonce reuse protection is concurrency-safe" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)

    parent = self()

    tasks =
      for _ <- 1..32 do
        Task.async(fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> MuSig.partial_sign(secnonce, seckey, cache, session)
          after
            5_000 -> exit(:barrier_timeout)
          end
        end)
      end

    for _ <- tasks do
      assert_receive {:ready, _pid}, 5_000
    end

    Enum.each(tasks, fn task -> send(task.pid, :go) end)

    results = Task.await_many(tasks, 5_000)
    successful_signatures = Enum.filter(results, &(is_binary(&1) and byte_size(&1) == 32))
    nonce_reuse_errors = Enum.filter(results, &match?({:error, "nonce already used"}, &1))

    assert [signature] = successful_signatures
    assert MuSig.partial_sig_verify(signature, pubnonce, pubkey, cache, session)
    assert length(nonce_reuse_errors) == 31
    refute {:error, "secp256k1_musig_partial_sign failed"} in results
  end

  test "serialized MuSig inputs reject overlong binaries" do
    state = signing_state()

    assert_raise ArgumentError, fn ->
      MuSig.nonce_agg([state.pubnonce <> <<0>>])
    end

    assert_raise FunctionClauseError, fn ->
      MuSig.nonce_process(state.aggnonce <> <<0>>, state.msg, state.cache)
    end

    assert_raise FunctionClauseError, fn ->
      MuSig.partial_sig_verify(
        state.partial_sig <> <<0>>,
        state.pubnonce,
        state.pubkey,
        state.cache,
        state.session
      )
    end

    assert_raise FunctionClauseError, fn ->
      MuSig.partial_sig_verify(
        state.partial_sig,
        state.pubnonce <> <<0>>,
        state.pubkey,
        state.cache,
        state.session
      )
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_agg(state.session, [state.partial_sig <> <<0>>])
    end
  end

  test "serialized MuSig inputs reject short binaries" do
    state = signing_state()
    short_pubnonce = binary_part(state.pubnonce, 0, 65)
    short_aggnonce = binary_part(state.aggnonce, 0, 65)
    short_partial_sig = binary_part(state.partial_sig, 0, 31)

    assert_raise ArgumentError, fn ->
      MuSig.nonce_agg([short_pubnonce])
    end

    assert_raise FunctionClauseError, fn ->
      MuSig.nonce_process(short_aggnonce, state.msg, state.cache)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_agg(state.session, [short_partial_sig])
    end
  end

  test "opaque MuSig state rejects forged binaries" do
    state = signing_state()
    tweak = <<1::256>>

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :pubkey_get, [<<0::197*8>>])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :pubkey_ec_tweak_add, [<<0::197*8>>, tweak])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :pubkey_xonly_tweak_add, [<<0::197*8>>, tweak])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :nonce_process, [state.aggnonce, state.msg, <<0::197*8>>])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :partial_sig_verify, [
        state.partial_sig,
        state.pubnonce,
        state.pubkey,
        <<0::197*8>>,
        state.session
      ])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :partial_sig_verify, [
        state.partial_sig,
        state.pubnonce,
        state.pubkey,
        state.cache,
        <<0::133*8>>
      ])
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :partial_sig_agg, [<<0::133*8>>, [state.partial_sig]])
    end
  end

  test "nonce_gen requires a signer public key" do
    msg = :crypto.strong_rand_bytes(32)
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :nonce_gen, [seckey, nil, msg, cache, nil])
    end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(seckey, <<0::33*8>>, msg, cache, nil)
    end
  end

  @tag :expensive
  test "formerly aborting malformed cache probes only raise in child BEAM" do
    assert_subprocess_argument_error("Secp256k1.NIF.musig_pubkey_get(<<0::197*8>>)")

    assert_subprocess_argument_error("""
    alias Secp256k1.MuSig
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = <<1::256>>
    {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    Secp256k1.NIF.musig_nonce_process(aggnonce, msg, <<0::197*8>>)
    """)

    assert_subprocess_argument_error("""
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = Secp256k1.MuSig.pubkey_agg([pubkey])
    Secp256k1.NIF.musig_nonce_gen(seckey, nil, <<1::256>>, cache, nil)
    """)
  end

  @tag :expensive
  test "formerly aborting malformed session probe only raises in child BEAM" do
    assert_subprocess_argument_error("""
    alias Secp256k1.MuSig
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = <<1::256>>
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)
    partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)
    Secp256k1.NIF.musig_partial_sig_agg(<<0::133*8>>, [partial_sig])
    """)
  end

  defp signers(count) do
    for _ <- 1..count do
      {seckey, pubkey} = Secp256k1.keypair(:compressed)
      %{seckey: seckey, pubkey: pubkey}
    end
  end

  defp sign_with(signers, msg, cache) do
    sign_with(signers, msg, cache, &MuSig.nonce_gen(&1.seckey, &1.pubkey, msg, cache, nil))
  end

  defp sign_with(signers, msg, cache, nonce_gen) do
    nonces =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} = nonce_gen.(signer)
        {secnonce, pubnonce}
      end)

    session =
      nonces
      |> Enum.map(fn {_secnonce, pubnonce} -> pubnonce end)
      |> session_for(msg, cache)

    partial_sigs =
      Enum.zip_with(signers, nonces, fn signer, {secnonce, pubnonce} ->
        partial_sig = MuSig.partial_sign(secnonce, signer.seckey, cache, session)
        assert MuSig.partial_sig_verify(partial_sig, pubnonce, signer.pubkey, cache, session)
        partial_sig
      end)

    MuSig.partial_sig_agg(session, partial_sigs)
  end

  # One signer whose key is the whole key set. `other_cache` is a tweaked cache for the same key:
  # a valid cache whose bytes differ from `cache`.
  defp single_signer do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    {:ok, _pubkey, other_cache} = MuSig.pubkey_ec_tweak_add(cache, :crypto.hash(:sha256, "tweak"))
    %{seckey: seckey, pubkey: pubkey, cache: cache, other_cache: other_cache}
  end

  defp session_for(pubnonces, msg, cache) do
    pubnonces
    |> MuSig.nonce_agg()
    |> MuSig.nonce_process(msg, cache)
  end

  defp signing_state do
    msg = :crypto.strong_rand_bytes(32)
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _, cache} = MuSig.pubkey_agg([pubkey])
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)
    partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)

    %{
      msg: msg,
      pubkey: pubkey,
      cache: cache,
      pubnonce: pubnonce,
      aggnonce: aggnonce,
      session: session,
      partial_sig: partial_sig
    }
  end

  defp assert_subprocess_argument_error(expression) do
    {output, status} = MuSigSubprocess.run(expression)

    assert status == 0, output
    assert output =~ "MUSIG_SUBPROCESS_ARGUMENT_ERROR"
  end
end
