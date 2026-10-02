defmodule Secp256k1Test.MuSigVectors do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1Test.Vectors

  @musig Vectors.load_musig2()
  @key_agg @musig["key_agg"]
  @nonce_agg @musig["nonce_agg"]

  test "MuSig2 key aggregation valid cases" do
    pubkeys = @key_agg["pubkeys"]

    for case_data <- @key_agg["valid"] do
      keys = Enum.map(case_data["key_indices"], &d(Enum.at(pubkeys, &1)))
      expected = d(case_data["expected"])

      assert {:ok, agg_xonly, _cache} = MuSig.pubkey_agg(keys)
      assert agg_xonly == expected
    end
  end

  test "MuSig2 key aggregation invalid pubkey cases" do
    pubkeys = @key_agg["pubkeys"]

    for case_data <- @key_agg["invalid"], case_data["error"] == "MUSIG_PUBKEY" do
      keys = Enum.map(case_data["key_indices"], &d(Enum.at(pubkeys, &1)))

      assert_raise ArgumentError, fn ->
        MuSig.pubkey_agg(keys)
      end
    end
  end

  test "MuSig2 key aggregation invalid tweak cases" do
    pubkeys = @key_agg["pubkeys"]
    tweaks = @key_agg["tweaks"]

    for case_data <- @key_agg["invalid"], case_data["error"] == "MUSIG_TWEAK" do
      keys = Enum.map(case_data["key_indices"], &d(Enum.at(pubkeys, &1)))
      tweak_count = case_data["tweak_indices_len"]

      steps =
        case_data["tweak_indices"]
        |> Enum.take(tweak_count)
        |> Enum.zip(Enum.take(case_data["is_xonly"], tweak_count))

      assert {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(keys)

      result =
        Enum.reduce_while(steps, {:ok, cache}, fn {tweak_index, is_xonly}, {:ok, cache} ->
          case apply_tweak(cache, d(Enum.at(tweaks, tweak_index)), is_xonly == 1) do
            {:ok, tweaked_cache, _pubkey} -> {:cont, {:ok, tweaked_cache}}
            error -> {:halt, error}
          end
        end)

      assert {:error, reason} = result
      assert is_binary(reason)
    end
  end

  test "MuSig2 nonce aggregation valid cases" do
    pubnonces = @nonce_agg["pubnonces"]

    for case_data <- @nonce_agg["valid"] do
      nonces = Enum.map(case_data["pnonce_indices"], &d(Enum.at(pubnonces, &1)))
      expected = d(case_data["expected"])

      aggnonce = MuSig.nonce_agg(nonces)

      assert aggnonce == expected
    end
  end

  test "MuSig2 nonce aggregation invalid cases" do
    pubnonces = @nonce_agg["pubnonces"]

    for case_data <- @nonce_agg["invalid"] do
      nonces = Enum.map(case_data["pnonce_indices"], &d(Enum.at(pubnonces, &1)))

      assert_raise ArgumentError, fn ->
        MuSig.nonce_agg(nonces)
      end
    end
  end

  defp apply_tweak(cache, tweak, true), do: MuSig.pubkey_xonly_tweak_add(cache, tweak)
  defp apply_tweak(cache, tweak, false), do: MuSig.pubkey_ec_tweak_add(cache, tweak)
end
