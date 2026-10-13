defmodule Secp256k1.MuSigSubprocessTest do
  use Secp256k1Test.Case, async: true

  import Secp256k1Test.MuSigFlow

  alias Secp256k1.MuSig
  alias Secp256k1Test.MuSigSubprocess

  @tag :expensive
  test "formerly aborting malformed cache probes only raise in child BEAM" do
    assert_subprocess_argument_errors([
      {"", "Secp256k1.NIF.musig_pubkey_get(<<0::197*8>>)"},
      {"""
       alias Secp256k1.MuSig
       {seckey, pubkey} = Secp256k1.keypair(:compressed)
       {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
       msg = <<1::256>>
       {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
       aggnonce = MuSig.nonce_agg([pubnonce])
       """, "Secp256k1.NIF.musig_nonce_process(aggnonce, msg, <<0::197*8>>)"},
      {"", "Secp256k1.NIF.musig_nonce_gen(seckey, nil, <<1::256>>, cache, nil)"}
    ])
  end

  @tag :expensive
  test "formerly aborting malformed session probe only raises in child BEAM" do
    assert_subprocess_argument_errors([
      {"""
       alias Secp256k1.MuSig
       {seckey, pubkey} = Secp256k1.keypair(:compressed)
       {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
       msg = <<1::256>>
       {:ok, secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
       aggnonce = MuSig.nonce_agg([pubnonce])
       session = MuSig.nonce_process(aggnonce, msg, cache)
       partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)
       """, "Secp256k1.NIF.musig_partial_sig_agg(<<0::133*8>>, [partial_sig])"}
    ])
  end

  @tag :expensive
  test "genuine MuSig resources raise in a BEAM that does not hold them" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
    session = session_for([pubnonce], msg, cache)
    terms = Enum.map([cache, secnonce, session], &serialize/1)

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

    # Each handle is decoded before any child resource exists, so it cannot name one.
    assert_subprocess_argument_errors([
      {"""
       alias Secp256k1.MuSig
       [stale_cache, stale_secnonce, stale_session] =
         Enum.map(#{inspect(terms)}, &(&1 |> Base.decode64!() |> :erlang.binary_to_term()))

       true = Enum.all?([stale_cache, stale_secnonce, stale_session], &is_reference/1)
       """, "MuSig.pubkey_get(stale_cache)"},
      {child_signer, "MuSig.partial_sign(stale_secnonce, seckey, cache, session)"},
      {"",
       ~s|MuSig.partial_sig_agg(stale_session, [Base.decode16!("#{Base.encode16(partial_sig)}")])|}
    ])
  end

  # Runs `steps` in one child BEAM. Each probe's marker directly before its own `ArgumentError`
  # marker proves the exception comes from that probed call, not from a setup or another probe.
  defp assert_subprocess_argument_errors(steps) do
    {output, status} = MuSigSubprocess.run(steps)

    assert status == 0, output

    for n <- 1..length(steps) do
      assert output =~ "MUSIG_SUBPROCESS_PROBE:#{n}\nMUSIG_SUBPROCESS_ARGUMENT_ERROR:#{n}:",
             output
    end
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
end
