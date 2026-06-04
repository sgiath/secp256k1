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

  test "cache resource supports public key lookup and functional tweaks" do
    {_seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])

    assert is_reference(cache)
    assert byte_size(MuSig.pubkey_get(cache)) == 33

    tweak = :crypto.strong_rand_bytes(32)
    {:ok, ec_tweaked_cache, ec_tweaked_pubkey} = MuSig.pubkey_ec_tweak_add(cache, tweak)
    assert is_reference(ec_tweaked_cache)
    assert byte_size(ec_tweaked_pubkey) == 33
    assert is_reference(cache)

    {:ok, xonly_tweaked_cache, xonly_tweaked_pubkey} = MuSig.pubkey_xonly_tweak_add(cache, tweak)
    assert is_reference(xonly_tweaked_cache)
    assert byte_size(xonly_tweaked_pubkey) == 33
  end

  test "nonce reuse protection" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)

    # First sign should succeed
    _sig = MuSig.partial_sign(secnonce, seckey, cache, session)

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

    assert length(successful_signatures) == 1
    assert length(nonce_reuse_errors) == 31
    refute {:error, "secp256k1_musig_partial_sign failed"} in results
  end

  test "serialized MuSig inputs reject overlong binaries" do
    state = signing_state()

    assert_raise ArgumentError, fn ->
      MuSig.nonce_agg([state.pubnonce <> <<0>>])
    end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_process(state.aggnonce <> <<0>>, state.msg, state.cache)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_verify(
        state.partial_sig <> <<0>>,
        state.pubnonce,
        state.pubkey,
        state.cache,
        state.session
      )
    end

    assert_raise ArgumentError, fn ->
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

    assert_raise ArgumentError, fn ->
      MuSig.nonce_process(short_aggnonce, state.msg, state.cache)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_agg(state.session, [short_partial_sig])
    end
  end

  test "opaque MuSig state rejects forged binaries" do
    state = signing_state()
    tweak = <<1::256>>

    assert_raise ArgumentError, fn ->
      MuSig.pubkey_get(<<0::197*8>>)
    end

    assert_raise ArgumentError, fn ->
      MuSig.pubkey_ec_tweak_add(<<0::197*8>>, tweak)
    end

    assert_raise ArgumentError, fn ->
      MuSig.pubkey_xonly_tweak_add(<<0::197*8>>, tweak)
    end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_process(state.aggnonce, state.msg, <<0::197*8>>)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_verify(
        state.partial_sig,
        state.pubnonce,
        state.pubkey,
        <<0::197*8>>,
        state.session
      )
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_verify(
        state.partial_sig,
        state.pubnonce,
        state.pubkey,
        state.cache,
        <<0::133*8>>
      )
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_agg(<<0::133*8>>, [state.partial_sig])
    end
  end

  test "nonce_gen requires a signer public key" do
    msg = :crypto.strong_rand_bytes(32)
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(seckey, nil, msg, cache, nil)
    end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(seckey, <<0::33*8>>, msg, cache, nil)
    end
  end

  test "formerly aborting malformed cache probes only raise in child BEAM" do
    assert_subprocess_argument_error("""
    alias Secp256k1.MuSig
    MuSig.pubkey_get(<<0::197*8>>)
    """)

    assert_subprocess_argument_error("""
    alias Secp256k1.MuSig
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = <<1::256>>
    {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    MuSig.nonce_process(aggnonce, msg, <<0::197*8>>)
    """)

    assert_subprocess_argument_error("""
    alias Secp256k1.MuSig
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = <<1::256>>
    MuSig.nonce_gen(seckey, nil, msg, cache, nil)
    """)
  end

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
    MuSig.partial_sig_agg(<<0::133*8>>, [partial_sig])
    """)
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
