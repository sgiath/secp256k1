defmodule Secp256k1.MuSigSubprocessTest do
  use Secp256k1Test.Case, async: true

  import Secp256k1Test.MuSigFlow

  alias Secp256k1.MuSig
  alias Secp256k1Test.MuSigSubprocess

  @tag :expensive
  test "formerly aborting malformed cache probes only raise in child BEAM" do
    assert_subprocess_argument_error("", "Secp256k1.NIF.musig_pubkey_get(<<0::197*8>>)")

    assert_subprocess_argument_error(
      """
      alias Secp256k1.MuSig
      {seckey, pubkey} = Secp256k1.keypair(:compressed)
      {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
      msg = <<1::256>>
      {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
      aggnonce = MuSig.nonce_agg([pubnonce])
      """,
      "Secp256k1.NIF.musig_nonce_process(aggnonce, msg, <<0::197*8>>)"
    )

    assert_subprocess_argument_error(
      """
      {seckey, pubkey} = Secp256k1.keypair(:compressed)
      {:ok, _agg_xonly_pubkey, cache} = Secp256k1.MuSig.pubkey_agg([pubkey])
      """,
      "Secp256k1.NIF.musig_nonce_gen(seckey, nil, <<1::256>>, cache, nil)"
    )
  end

  @tag :expensive
  test "formerly aborting malformed session probe only raises in child BEAM" do
    assert_subprocess_argument_error(
      """
      alias Secp256k1.MuSig
      {seckey, pubkey} = Secp256k1.keypair(:compressed)
      {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
      msg = <<1::256>>
      {:ok, secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
      aggnonce = MuSig.nonce_agg([pubnonce])
      session = MuSig.nonce_process(aggnonce, msg, cache)
      partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)
      """,
      "Secp256k1.NIF.musig_partial_sig_agg(<<0::133*8>>, [partial_sig])"
    )
  end

  @tag :expensive
  test "genuine MuSig resources raise in a BEAM that does not hold them" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
    session = session_for([pubnonce], msg, cache)
    terms = Enum.map([cache, secnonce, session], &serialize/1)
    [cache_term, secnonce_term, session_term] = terms

    # In this VM the serialized handles decode to the live resources they were taken from. The
    # originals must stay referenced until decoded: if a GC frees one first, its handle is stale.
    [decoded_cache, decoded_secnonce, decoded_session] = Enum.map(terms, &deserialize/1)
    assert [decoded_cache, decoded_secnonce, decoded_session] == [cache, secnonce, session]
    assert MuSig.pubkey_get(decoded_cache) == MuSig.pubkey_get(cache)

    partial_sig = MuSig.partial_sign(decoded_secnonce, seckey, cache, decoded_session)

    assert MuSig.partial_sig_verify(partial_sig, pubnonce, pubkey, cache, session) == true

    # A child BEAM decodes the same handles, but their resources do not exist there. Each probe
    # passes the stale handle alongside otherwise valid arguments.
    child_signer = """
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = <<1::256>>
    {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
    session = MuSig.nonce_process(MuSig.nonce_agg([pubnonce]), msg, cache)
    """

    assert_stale_resource_argument_error(cache_term, "", "MuSig.pubkey_get(stale)")

    assert_stale_resource_argument_error(
      secnonce_term,
      child_signer,
      "MuSig.partial_sign(stale, seckey, cache, session)"
    )

    assert_stale_resource_argument_error(
      session_term,
      "",
      ~s|MuSig.partial_sig_agg(stale, [Base.decode16!("#{Base.encode16(partial_sig)}")])|
    )
  end

  # Runs `setup`, then `probe`, in a child BEAM. The probe marker before the `ArgumentError`
  # marker proves the exception comes from the probed call, not from the setup.
  defp assert_subprocess_argument_error(setup, probe) do
    {output, status} = MuSigSubprocess.run(setup, probe)

    assert status == 0, output
    assert output =~ "MUSIG_SUBPROCESS_PROBE\nMUSIG_SUBPROCESS_ARGUMENT_ERROR", output
  end

  defp serialize(term) do
    term
    |> :erlang.term_to_binary()
    |> Base.encode64()
  end

  defp deserialize(serialized) do
    serialized
    |> Base.decode64!()
    |> :erlang.binary_to_term()
  end

  # Decodes `serialized` as `stale` before any child resource exists, runs `setup`, then
  # `probe`.
  defp assert_stale_resource_argument_error(serialized, setup, probe) do
    assert_subprocess_argument_error(
      """
      alias Secp256k1.MuSig
      stale = "#{serialized}" |> Base.decode64!() |> :erlang.binary_to_term()
      true = is_reference(stale)
      #{setup}
      """,
      probe
    )
  end
end
