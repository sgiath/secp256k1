defmodule Secp256k1Test.NifBehavior do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.{ECDH, ECDSA, Extrakeys, MuSig, Schnorr}

  test "MuSig resource APIs reject forged references" do
    state = signing_state()
    forged_resource = make_ref()

    assert_raise ArgumentError, fn -> MuSig.pubkey_get(forged_resource) end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_process(state.aggnonce, state.message, forged_resource)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sign(forged_resource, state.seckey, state.cache, state.session)
    end
  end

  test "MuSig rejects right-sized invalid serialized content" do
    state = signing_state()

    assert_raise ArgumentError, fn ->
      MuSig.nonce_process(<<4, 0::520>>, state.message, state.cache)
    end

    assert_raise ArgumentError, fn ->
      MuSig.partial_sig_agg(state.session, [:binary.copy(<<255>>, 32)])
    end
  end

  test "feature NIF operations succeed concurrently across 50 iterations" do
    seckey = d("0000000000000000000000000000000000000000000000000000000000000001")
    peer_seckey = d("0000000000000000000000000000000000000000000000000000000000000002")
    compressed_pubkey = ECDSA.pubkey(seckey)
    peer_pubkey = ECDSA.pubkey(peer_seckey)
    xonly_pubkey = Extrakeys.xonly_pubkey(seckey)

    feature_operations = [
      ecdsa: fn message ->
        message
        |> ECDSA.sign(seckey)
        |> ECDSA.valid?(message, compressed_pubkey)
      end,
      schnorr: fn message ->
        message
        |> Schnorr.sign(seckey)
        |> Schnorr.valid?(message, xonly_pubkey)
      end,
      ecdh: fn _message ->
        ECDH.ecdh(seckey, peer_pubkey) == ECDH.ecdh(peer_seckey, compressed_pubkey)
      end,
      extrakeys: fn _message ->
        Extrakeys.xonly_pubkey(seckey) == xonly_pubkey
      end
    ]

    results =
      for iteration <- 1..50, {feature, operation} <- feature_operations do
        {iteration, feature, operation}
      end
      |> Task.async_stream(
        fn {iteration, feature, operation} ->
          message = :crypto.hash(:sha256, Integer.to_string(iteration))
          {feature, operation.(message)}
        end,
        max_concurrency: 32,
        timeout: :infinity
      )
      |> Enum.to_list()

    expected_results =
      for _iteration <- 1..50, {feature, _operation} <- feature_operations do
        {:ok, {feature, true}}
      end

    assert results == expected_results
  end

  defp signing_state do
    message = :crypto.hash(:sha256, "NIF behavior characterization")
    seckey = d("0000000000000000000000000000000000000000000000000000000000000001")
    pubkey = ECDSA.pubkey(seckey)
    {:ok, _aggregate_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    {:ok, _secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, message, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, message, cache)

    %{
      aggnonce: aggnonce,
      cache: cache,
      message: message,
      seckey: seckey,
      session: session
    }
  end
end
