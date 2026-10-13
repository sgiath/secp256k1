defmodule Secp256k1Test.Concurrency do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDH
  alias Secp256k1.ECDSA
  alias Secp256k1.Extrakeys
  alias Secp256k1.Schnorr

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

    for_result =
      for iteration <- 1..50, {feature, operation} <- feature_operations do
        {iteration, feature, operation}
      end

    results =
      for_result
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
end
