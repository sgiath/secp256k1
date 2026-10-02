defmodule Secp256k1Test.MuSigVectors do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr
  alias Secp256k1Test.Vectors

  @curve_order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @musig Vectors.load_musig2()
  @key_agg @musig["key_agg"]
  @nonce_agg @musig["nonce_agg"]

  @sign_verify Vectors.load_bip327_sign_verify()
  @tweak Vectors.load_bip327_tweak()
  @sig_agg Vectors.load_bip327_sig_agg()

  # Fixture filters. Skipped cases are not reachable through the public API:
  # - Messages that are not 32 bytes (BIP-327 "Empty message" and "38-byte message"): the
  #   API signs and verifies `Secp256k1.hash()` messages only.
  # - Sign errors that need an injected secret nonce ("signer's pubkey is not in the list of
  #   pubkeys", which BIP-327 marks optional and libsecp256k1 does not check, and "Secnonce is
  #   invalid"): `MuSig.nonce_gen/5` is the only way to obtain a secnonce.
  @sign_verify_valid @sign_verify.valid
                     |> Enum.with_index()
                     |> Enum.filter(fn {vector, _index} -> byte_size(vector.msg) == 32 end)
  @sign_error_reachable @sign_verify.sign_error
                        |> Enum.with_index()
                        |> Enum.filter(fn {vector, _index} ->
                          vector.error["contrib"] in ["pubkey", "aggnonce"]
                        end)

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
        |> Enum.map(fn {tweak_index, is_xonly} ->
          {d(Enum.at(tweaks, tweak_index)), is_xonly == 1}
        end)

      assert {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(keys)
      assert {:error, reason} = apply_tweaks(cache, steps)
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

  for {vector, index} <- @sign_verify_valid do
    comment = vector.comment || "partial signature verifies"

    test "BIP-327 sign/verify valid ##{index}: #{comment}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, [])

      assert MuSig.nonce_agg(vector.pubnonces) == vector.aggnonce

      session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

      assert verify(vector.psig, vector, cache, session)
    end
  end

  for {vector, index} <- @sign_error_reachable do
    test "BIP-327 sign error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      case vector.error["contrib"] do
        "pubkey" ->
          assert_raise ArgumentError, fn -> MuSig.pubkey_agg(vector.pubkeys) end

        "aggnonce" ->
          cache = keyagg_cache(vector.pubkeys, [])

          assert_raise ArgumentError, fn ->
            MuSig.nonce_process(vector.aggnonce, vector.msg, cache)
          end
      end
    end
  end

  for {vector, index} <- Enum.with_index(@sign_verify.verify_fail) do
    test "BIP-327 verify fail ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, [])
      aggnonce = MuSig.nonce_agg(vector.pubnonces)
      session = MuSig.nonce_process(aggnonce, vector.msg, cache)

      if :binary.decode_unsigned(vector.psig) >= @curve_order do
        # libsecp256k1 rejects an out-of-range partial signature at parse time (its own
        # vector harness expects `secp256k1_musig_partial_sig_parse` to fail). The public API
        # raises for unparsable partial signatures instead of returning `false`.
        assert_raise ArgumentError, fn -> verify(vector.psig, vector, cache, session) end
      else
        assert verify(vector.psig, vector, cache, session) == false
      end
    end
  end

  for {vector, index} <- Enum.with_index(@sign_verify.verify_error) do
    test "BIP-327 verify error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      # The invalid contribution is rejected where the verifier first parses it while
      # rebuilding the transcript.
      case vector.error["contrib"] do
        "pubnonce" -> assert_raise ArgumentError, fn -> MuSig.nonce_agg(vector.pubnonces) end
        "pubkey" -> assert_raise ArgumentError, fn -> MuSig.pubkey_agg(vector.pubkeys) end
      end

      # `partial_sig_verify/5` rejects the same contribution when it is passed directly,
      # here against the well-formed transcript of the first valid case.
      {baseline, _index} = hd(@sign_verify_valid)
      cache = keyagg_cache(baseline.pubkeys, [])
      session = MuSig.nonce_process(baseline.aggnonce, baseline.msg, cache)

      assert_raise ArgumentError, fn -> verify(vector.psig, vector, cache, session) end
    end
  end

  for {vector, index} <- Enum.with_index(@tweak.valid) do
    test "BIP-327 tweak valid ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, vector.tweaks)

      assert MuSig.nonce_agg(vector.pubnonces) == vector.aggnonce

      session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

      assert verify(vector.psig, vector, cache, session)
    end
  end

  for {vector, index} <- Enum.with_index(@tweak.error) do
    test "BIP-327 tweak error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      assert {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(vector.pubkeys)
      assert {:error, reason} = apply_tweaks(cache, vector.tweaks)
      assert is_binary(reason)
    end
  end

  for {vector, index} <- Enum.with_index(@sig_agg.valid) do
    test "BIP-327 signature aggregation valid ##{index}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, vector.tweaks)

      assert MuSig.nonce_agg(vector.pubnonces) == vector.aggnonce

      session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

      assert MuSig.partial_sig_agg(session, vector.psigs) == vector.expected

      <<_parity, agg_xonly::binary-size(32)>> = MuSig.pubkey_get(cache)
      assert Schnorr.valid?(vector.expected, vector.msg, agg_xonly)
    end
  end

  for {vector, index} <- Enum.with_index(@sig_agg.error) do
    test "BIP-327 signature aggregation error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, vector.tweaks)
      session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

      assert_raise ArgumentError, fn -> MuSig.partial_sig_agg(session, vector.psigs) end
    end
  end

  defp keyagg_cache(pubkeys, tweaks) do
    {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(pubkeys)
    {:ok, tweaked_cache} = apply_tweaks(cache, tweaks)
    tweaked_cache
  end

  defp apply_tweaks(cache, tweaks) do
    Enum.reduce_while(tweaks, {:ok, cache}, fn {tweak, is_xonly}, {:ok, cache} ->
      case apply_tweak(cache, tweak, is_xonly) do
        {:ok, _tweaked_pubkey, tweaked_cache} -> {:cont, {:ok, tweaked_cache}}
        error -> {:halt, error}
      end
    end)
  end

  defp apply_tweak(cache, tweak, true), do: MuSig.pubkey_xonly_tweak_add(cache, tweak)
  defp apply_tweak(cache, tweak, false), do: MuSig.pubkey_ec_tweak_add(cache, tweak)

  defp verify(psig, vector, cache, session) do
    MuSig.partial_sig_verify(
      psig,
      Enum.at(vector.pubnonces, vector.signer_index),
      Enum.at(vector.pubkeys, vector.signer_index),
      cache,
      session
    )
  end
end
