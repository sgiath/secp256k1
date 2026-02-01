defmodule Secp256k1Test.MuSigVectors do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1Test.Vectors

  @musig Vectors.load_musig2()
  @key_agg @musig["key_agg"]
  @nonce_agg @musig["nonce_agg"]

  test "MuSig2 key aggregation valid cases" do
    pubkeys = @key_agg["pubkeys"]

    for case_data <- @key_agg["valid"] do
      keys = Enum.map(case_data["key_indices"], &hex_to_bin(Enum.at(pubkeys, &1)))
      expected = hex_to_bin(case_data["expected"])

      assert {:ok, agg_xonly, _cache} = MuSig.pubkey_agg(keys)
      assert agg_xonly == expected
    end
  end

  test "MuSig2 key aggregation invalid pubkey cases" do
    pubkeys = @key_agg["pubkeys"]

    for case_data <- @key_agg["invalid"], case_data["error"] == "MUSIG_PUBKEY" do
      keys = Enum.map(case_data["key_indices"], &hex_to_bin(Enum.at(pubkeys, &1)))

      assert_raise ArgumentError, fn ->
        MuSig.pubkey_agg(keys)
      end
    end
  end

  test "MuSig2 nonce aggregation valid cases" do
    pubnonces = @nonce_agg["pubnonces"]

    for case_data <- @nonce_agg["valid"] do
      nonces = Enum.map(case_data["pnonce_indices"], &hex_to_bin(Enum.at(pubnonces, &1)))
      expected = hex_to_bin(case_data["expected"])

      aggnonce = MuSig.nonce_agg(nonces)

      assert byte_size(aggnonce) == 132
      assert binary_part(aggnonce, 0, 66) == expected
    end
  end

  test "MuSig2 nonce aggregation invalid cases" do
    pubnonces = @nonce_agg["pubnonces"]

    for case_data <- @nonce_agg["invalid"] do
      nonces = Enum.map(case_data["pnonce_indices"], &hex_to_bin(Enum.at(pubnonces, &1)))

      assert_raise ArgumentError, fn ->
        MuSig.nonce_agg(nonces)
      end
    end
  end

  defp hex_to_bin(hex) when is_binary(hex) do
    Base.decode16!(hex, case: :mixed)
  end
end
