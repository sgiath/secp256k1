defmodule Secp256k1Test.Vectors do
  @moduledoc false

  @vectors_dir Path.expand("../vectors", __DIR__)
  def load_bip340 do
    @vectors_dir
    |> Path.join("bip340.csv")
    |> File.read!()
    |> String.split(~r/\r?\n/, trim: true)
    |> Enum.drop(1)
    |> Enum.map(&parse_bip340_line/1)
  end

  # Returns the parsed cases with the fixture's declared `numberOfTests`.
  def load_wycheproof_ecdsa do
    vectors = load_json("wycheproof_ecdsa.json")
    groups = Map.fetch!(vectors, "testGroups")

    %{
      number_of_tests: Map.fetch!(vectors, "numberOfTests"),
      tests: Enum.flat_map(groups, &parse_wycheproof_group/1)
    }
  end

  # `musig2.json` mirrors the libsecp256k1 C structs; only the first `*_len` entries of an
  # index array are meaningful (see `vectors/README.md`).
  def load_musig2 do
    %{"key_agg" => key_agg, "nonce_agg" => nonce_agg} = load_json("musig2.json")
    pubkeys = decode_hex_list(key_agg["pubkeys"])
    tweaks = decode_hex_list(key_agg["tweaks"])
    pubnonces = decode_hex_list(nonce_agg["pubnonces"])

    key_agg_pubkeys = fn test_case ->
      pick(pubkeys, take_len!(test_case["key_indices"], test_case["key_indices_len"]))
    end

    %{
      key_agg_valid:
        Enum.map(key_agg["valid"], fn test_case ->
          %{pubkeys: key_agg_pubkeys.(test_case), expected: decode_hex(test_case["expected"])}
        end),
      key_agg_invalid:
        Enum.map(key_agg["invalid"], fn test_case ->
          count = test_case["tweak_indices_len"]

          %{
            pubkeys: key_agg_pubkeys.(test_case),
            tweaks:
              tweak_steps(
                tweaks,
                take_len!(test_case["tweak_indices"], count),
                Enum.map(take_len!(test_case["is_xonly"], count), &(&1 == 1))
              ),
            error: test_case["error"]
          }
        end),
      nonce_agg_valid:
        Enum.map(nonce_agg["valid"], fn test_case ->
          %{
            pubnonces: pick(pubnonces, test_case["pnonce_indices"]),
            expected: decode_hex(test_case["expected"])
          }
        end),
      nonce_agg_invalid:
        Enum.map(nonce_agg["invalid"], fn test_case ->
          %{pubnonces: pick(pubnonces, test_case["pnonce_indices"])}
        end)
    }
  end

  def load_bip327_sign_verify do
    vectors = load_json("bip327_sign_verify.json")
    pubkeys = decode_hex_list(vectors["pubkeys"])
    pubnonces = decode_hex_list(vectors["pnonces"])
    aggnonces = decode_hex_list(vectors["aggnonces"])
    msgs = decode_hex_list(vectors["msgs"])

    transcript = fn test_case ->
      %{
        pubkeys: pick(pubkeys, test_case["key_indices"]),
        pubnonces: pick(pubnonces, test_case["nonce_indices"] || []),
        aggnonce:
          test_case["aggnonce_index"] && Enum.fetch!(aggnonces, test_case["aggnonce_index"]),
        msg: Enum.fetch!(msgs, test_case["msg_index"]),
        signer_index: test_case["signer_index"],
        psig: test_case["sig"] && decode_hex(test_case["sig"]),
        error: test_case["error"],
        comment: test_case["comment"]
      }
    end

    %{
      valid:
        Enum.map(vectors["valid_test_cases"], fn test_case ->
          %{transcript.(test_case) | psig: decode_hex(test_case["expected"])}
        end),
      sign_error: Enum.map(vectors["sign_error_test_cases"], transcript),
      verify_fail: Enum.map(vectors["verify_fail_test_cases"], transcript),
      verify_error: Enum.map(vectors["verify_error_test_cases"], transcript)
    }
  end

  def load_bip327_tweak do
    vectors = load_json("bip327_tweak.json")
    pubkeys = decode_hex_list(vectors["pubkeys"])
    pubnonces = decode_hex_list(vectors["pnonces"])
    tweaks = decode_hex_list(vectors["tweaks"])

    transcript = fn test_case ->
      %{
        pubkeys: pick(pubkeys, test_case["key_indices"]),
        pubnonces: pick(pubnonces, test_case["nonce_indices"]),
        aggnonce: decode_hex(vectors["aggnonce"]),
        msg: decode_hex(vectors["msg"]),
        tweaks: tweak_steps(tweaks, test_case["tweak_indices"], test_case["is_xonly"]),
        signer_index: test_case["signer_index"],
        psig: test_case["expected"] && decode_hex(test_case["expected"]),
        error: test_case["error"],
        comment: test_case["comment"]
      }
    end

    %{
      valid: Enum.map(vectors["valid_test_cases"], transcript),
      error: Enum.map(vectors["error_test_cases"], transcript)
    }
  end

  def load_bip327_sig_agg do
    vectors = load_json("bip327_sig_agg.json")
    pubkeys = decode_hex_list(vectors["pubkeys"])
    pubnonces = decode_hex_list(vectors["pnonces"])
    tweaks = decode_hex_list(vectors["tweaks"])
    psigs = decode_hex_list(vectors["psigs"])

    transcript = fn test_case ->
      %{
        pubkeys: pick(pubkeys, test_case["key_indices"]),
        pubnonces: pick(pubnonces, test_case["nonce_indices"]),
        aggnonce: decode_hex(test_case["aggnonce"]),
        msg: decode_hex(vectors["msg"]),
        tweaks: tweak_steps(tweaks, test_case["tweak_indices"], test_case["is_xonly"]),
        psigs: pick(psigs, test_case["psig_indices"]),
        expected: test_case["expected"] && decode_hex(test_case["expected"]),
        error: test_case["error"],
        comment: test_case["comment"]
      }
    end

    %{
      valid: Enum.map(vectors["valid_test_cases"], transcript),
      error: Enum.map(vectors["error_test_cases"], transcript)
    }
  end

  defp load_json(file) do
    @vectors_dir
    |> Path.join(file)
    |> File.read!()
    |> Jason.decode!()
  end

  # Each step is `{tweak, is_xonly}`, applied in order to the aggregate key.
  defp tweak_steps(tweaks, tweak_indices, is_xonly)
       when length(tweak_indices) == length(is_xonly) do
    tweaks
    |> pick(tweak_indices)
    |> Enum.zip(is_xonly)
  end

  defp tweak_steps(_tweaks, tweak_indices, is_xonly) do
    raise ArgumentError,
          "tweak vector has #{length(tweak_indices)} tweak indices " <>
            "but #{length(is_xonly)} is_xonly flags"
  end

  defp take_len!(values, len) when length(values) >= len, do: Enum.take(values, len)

  defp take_len!(values, len) do
    raise ArgumentError, "vector declares #{len} entries but has #{length(values)}"
  end

  defp pick(values, indices), do: Enum.map(indices, &Enum.fetch!(values, &1))

  defp decode_hex_list(values), do: Enum.map(values, &decode_hex/1)

  defp decode_hex(value), do: Base.decode16!(value, case: :mixed)

  defp parse_bip340_line(line) do
    [index, secret_key, public_key, aux_rand, message, signature, result, comment] =
      String.split(line, ",", parts: 8)

    idx = String.to_integer(index)
    trimmed_comment = String.trim(comment || "")

    %{
      index: idx,
      secret_key: decode_hex_optional(secret_key),
      public_key: decode_hex_optional(public_key),
      aux_rand: decode_hex_optional(aux_rand),
      message: decode_hex_message(message),
      signature: decode_hex_optional(signature),
      verification_result: String.upcase(result) == "TRUE",
      comment: if(trimmed_comment == "", do: "vector #{idx}", else: trimmed_comment)
    }
  end

  defp parse_wycheproof_group(group) do
    pubkey =
      group
      |> Map.fetch!("publicKey")
      |> Map.fetch!("uncompressed")
      |> decode_hex()

    group
    |> Map.fetch!("tests")
    |> Enum.map(fn test ->
      %{
        tc_id: test["tcId"],
        comment: test["comment"],
        msg: decode_hex(test["msg"]),
        sig: decode_hex(test["sig"]),
        result: test["result"],
        pubkey: pubkey,
        flags: test["flags"] || []
      }
    end)
  end

  defp decode_hex_optional(nil), do: nil
  defp decode_hex_optional(""), do: nil
  defp decode_hex_optional(value), do: Base.decode16!(value, case: :mixed)

  defp decode_hex_message(""), do: <<>>
  defp decode_hex_message(value), do: decode_hex_optional(value)
end
