defmodule Secp256k1Test.Vectors do
  @moduledoc false

  @vectors_dir Path.expand("../vectors", __DIR__)
  @wycheproof_skip_flags MapSet.new([
                           "BerEncodedSignature",
                           "InvalidEncoding",
                           "InvalidTypesInSignature"
                         ])

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
    |> JSON.decode!()
    |> Map.fetch!("testGroups")
    |> Enum.flat_map(&parse_wycheproof_group/1)
  end

  def load_musig2 do
    @vectors_dir
    |> Path.join("musig2.json")
    |> File.read!()
    |> JSON.decode!()
  end

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
    |> Enum.reject(&skip_wycheproof_test?/1)
    |> Enum.map(fn test ->
      %{
        tc_id: test["tcId"],
        comment: test["comment"],
        msg: decode_hex_optional(test["msg"]) || <<>>,
        sig: test["sig"],
        result: test["result"],
        pubkey: pubkey,
        flags: test["flags"] || []
      }
    end)
  end

  defp skip_wycheproof_test?(test) do
    flags = test["flags"] || []
    Enum.any?(flags, &MapSet.member?(@wycheproof_skip_flags, &1))
  end

  defp decode_hex_optional(nil), do: nil
  defp decode_hex_optional(""), do: nil
  defp decode_hex_optional(value), do: Base.decode16!(value, case: :mixed)

  defp decode_hex_message(""), do: <<>>
  defp decode_hex_message(value), do: decode_hex_optional(value)
end
