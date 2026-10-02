defmodule Secp256k1Test.MuSigVectors do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr
  alias Secp256k1Test.Vectors

  @curve_order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @musig Vectors.load_musig2()
  @sign_verify Vectors.load_bip327_sign_verify()
  @tweak Vectors.load_bip327_tweak()
  @sig_agg Vectors.load_bip327_sig_agg()

  @cases %{
    key_agg_valid: @musig.key_agg_valid,
    key_agg_invalid: @musig.key_agg_invalid,
    nonce_agg_valid: @musig.nonce_agg_valid,
    nonce_agg_invalid: @musig.nonce_agg_invalid,
    sign_verify_valid: @sign_verify.valid,
    sign_error: @sign_verify.sign_error,
    verify_fail: @sign_verify.verify_fail,
    verify_error: @sign_verify.verify_error,
    tweak_valid: @tweak.valid,
    tweak_error: @tweak.error,
    sig_agg_valid: @sig_agg.valid,
    sig_agg_error: @sig_agg.error
  }

  # Case counts of the bundled fixtures, so a truncated fixture fails instead of running fewer
  # cases.
  @case_counts %{
    key_agg_valid: 4,
    key_agg_invalid: 5,
    nonce_agg_valid: 2,
    nonce_agg_invalid: 3,
    sign_verify_valid: 6,
    sign_error: 6,
    verify_fail: 3,
    verify_error: 2,
    tweak_valid: 5,
    tweak_error: 1,
    sig_agg_valid: 4,
    sig_agg_error: 1
  }

  # `{category, index, comment}` of every case not exercised, as listed in
  # `test/vectors/README.md` ("Coverage"). They are not reachable through the public API:
  # - Messages that are not 32 bytes: the API signs and verifies `Secp256k1.hash()` messages
  #   only.
  # - Sign errors that need an injected secret nonce (the signer's pubkey missing from the key
  #   list, which BIP-327 marks optional and libsecp256k1 does not check, and an invalid
  #   secnonce): `MuSig.nonce_gen/2` is the only way to obtain a secnonce.
  @excluded [
    {:sign_verify_valid, 4, "Empty message"},
    {:sign_verify_valid, 5, "38-byte message"},
    {:sign_error, 0,
     "The signers pubkey is not in the list of pubkeys. This test case is optional: it can be " <>
       "skipped by implementations that do not check that the signer's pubkey is included in " <>
       "the list of pubkeys."},
    {:sign_error, 5, "Secnonce is invalid which may indicate nonce reuse"}
  ]

  @sign_verify_valid for {vector, index} <- Enum.with_index(@sign_verify.valid),
                         {:sign_verify_valid, index, vector.comment} not in @excluded,
                         do: {vector, index}

  @sign_error_reachable for {vector, index} <- Enum.with_index(@sign_verify.sign_error),
                            {:sign_error, index, vector.comment} not in @excluded,
                            do: {vector, index}

  test "fixtures contain every expected case" do
    counts = Map.new(@cases, fn {category, vectors} -> {category, length(vectors)} end)

    assert counts == @case_counts
  end

  test "every excluded case names an existing fixture case" do
    for {category, index, comment} <- @excluded do
      assert %{comment: ^comment} = Enum.fetch!(@cases[category], index)
    end
  end

  test "MuSig2 key aggregation valid cases" do
    for vector <- @musig.key_agg_valid do
      assert {:ok, agg_xonly, _cache} = MuSig.pubkey_agg(vector.pubkeys)
      assert agg_xonly == vector.expected
    end
  end

  test "MuSig2 key aggregation invalid cases" do
    for vector <- @musig.key_agg_invalid do
      case vector.error do
        "MUSIG_PUBKEY" ->
          assert_raise ArgumentError, fn -> MuSig.pubkey_agg(vector.pubkeys) end

        "MUSIG_TWEAK" ->
          assert {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(vector.pubkeys)
          assert {:error, reason} = apply_tweaks(cache, vector.tweaks)
          assert is_binary(reason)

        error ->
          flunk("unknown key aggregation error category: #{inspect(error)}")
      end
    end
  end

  test "MuSig2 nonce aggregation valid cases" do
    for vector <- @musig.nonce_agg_valid do
      assert MuSig.nonce_agg(vector.pubnonces) == vector.expected
    end
  end

  test "MuSig2 nonce aggregation invalid cases" do
    for vector <- @musig.nonce_agg_invalid do
      assert_raise ArgumentError, fn -> MuSig.nonce_agg(vector.pubnonces) end
    end
  end

  for {vector, index} <- @sign_verify_valid do
    comment = vector.comment || "partial signature verifies"

    test "BIP-327 sign/verify valid ##{index}: #{comment}" do
      vector = unquote(Macro.escape(vector))
      cache = keyagg_cache(vector.pubkeys, [])

      assert MuSig.nonce_agg(vector.pubnonces) == vector.aggnonce

      session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

      assert verify(vector.psig, vector, cache, session) == true
    end
  end

  for {vector, index} <- @sign_error_reachable do
    test "BIP-327 sign error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      case vector.error do
        %{"type" => "invalid_contribution", "contrib" => "pubkey"} ->
          assert_raise ArgumentError, fn -> MuSig.pubkey_agg(vector.pubkeys) end

        %{"type" => "invalid_contribution", "contrib" => "aggnonce"} ->
          cache = keyagg_cache(vector.pubkeys, [])

          assert_raise ArgumentError, fn ->
            MuSig.nonce_process(vector.aggnonce, vector.msg, cache)
          end

        error ->
          flunk("unknown sign error category: #{inspect(error)}")
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
      case vector.error do
        %{"type" => "invalid_contribution", "contrib" => "pubnonce"} ->
          assert_raise ArgumentError, fn -> MuSig.nonce_agg(vector.pubnonces) end

        %{"type" => "invalid_contribution", "contrib" => "pubkey"} ->
          assert_raise ArgumentError, fn -> MuSig.pubkey_agg(vector.pubkeys) end

        error ->
          flunk("unknown verify error category: #{inspect(error)}")
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

      assert verify(vector.psig, vector, cache, session) == true
    end
  end

  for {vector, index} <- Enum.with_index(@tweak.error) do
    test "BIP-327 tweak error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      case vector.error do
        %{"type" => "value"} ->
          assert {:ok, _agg_xonly, cache} = MuSig.pubkey_agg(vector.pubkeys)
          assert {:error, reason} = apply_tweaks(cache, vector.tweaks)
          assert is_binary(reason)

        error ->
          flunk("unknown tweak error category: #{inspect(error)}")
      end
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
      assert Schnorr.valid?(vector.expected, vector.msg, agg_xonly) == true
    end
  end

  for {vector, index} <- Enum.with_index(@sig_agg.error) do
    test "BIP-327 signature aggregation error ##{index}: #{vector.comment}" do
      vector = unquote(Macro.escape(vector))

      case vector.error do
        %{"type" => "invalid_contribution", "contrib" => "psig"} ->
          cache = keyagg_cache(vector.pubkeys, vector.tweaks)
          session = MuSig.nonce_process(vector.aggnonce, vector.msg, cache)

          assert_raise ArgumentError, fn -> MuSig.partial_sig_agg(session, vector.psigs) end

        error ->
          flunk("unknown signature aggregation error category: #{inspect(error)}")
      end
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
