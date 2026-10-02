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

  def load_wycheproof_ecdsa do
    @vectors_dir
    |> Path.join("wycheproof_ecdsa.json")
    |> File.read!()
    |> Jason.decode!()
    |> Map.fetch!("testGroups")
    |> Enum.flat_map(&parse_wycheproof_group/1)
  end

  def load_musig2, do: load_json("musig2.json")

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
        aggnonce: test_case["aggnonce_index"] && Enum.at(aggnonces, test_case["aggnonce_index"]),
        msg: Enum.at(msgs, test_case["msg_index"]),
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
        tweaks: tweak_steps(tweaks, test_case),
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
        tweaks: tweak_steps(tweaks, test_case),
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
  defp tweak_steps(tweaks, test_case) do
    tweaks
    |> pick(test_case["tweak_indices"])
    |> Enum.zip(test_case["is_xonly"])
  end

  defp pick(values, indices), do: Enum.map(indices, &Enum.at(values, &1))

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
      |> decode_hex_optional()

    group
    |> Map.fetch!("tests")
    |> Enum.map(fn test ->
      %{
        tc_id: test["tcId"],
        comment: test["comment"],
        msg: decode_hex_optional(test["msg"]) || <<>>,
        sig: decode_hex_optional(test["sig"]),
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
