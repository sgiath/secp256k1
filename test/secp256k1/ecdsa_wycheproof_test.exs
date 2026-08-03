defmodule Secp256k1Test.ECDSAWycheproof do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDSA
  alias Secp256k1Test.DER
  alias Secp256k1Test.Vectors

  @skip_flags ["BerEncodedSignature", "InvalidEncoding", "InvalidTypesInSignature"]

  setup_all do
    {:ok, tests: Vectors.load_wycheproof_ecdsa()}
  end

  test "Wycheproof filtering excludes DER-encoding flags", %{tests: tests} do
    assert Enum.all?(tests, fn test ->
             Enum.all?(test.flags, &(&1 not in @skip_flags))
           end)
  end

  test "Wycheproof ECDSA vectors", %{tests: tests} do
    failures = Enum.flat_map(tests, &vector_failures/1)

    assert failures == [], Enum.join(failures, "\n")
  end

  defp vector_failures(test_case) do
    expected = test_case.result == "valid"
    actual = verify(test_case)

    valid_result? =
      if expected, do: actual == true, else: actual in [false, :invalid, :invalid_der]

    if valid_result? do
      []
    else
      comment = test_case.comment || "tc #{test_case.tc_id}"

      [
        "Wycheproof ECDSA ##{test_case.tc_id} (#{comment}): expected #{test_case.result}, got #{inspect(actual)}"
      ]
    end
  end

  defp verify(test_case) do
    pubkey = ECDSA.compress_pubkey(test_case.pubkey)
    msg_hash = :crypto.hash(:sha256, test_case.msg)

    try do
      signature = DER.to_compact(test_case.sig)

      try do
        case ECDSA.valid?(signature, msg_hash, pubkey) do
          true -> true
          false -> false
          {:error, _} -> :invalid
        end
      rescue
        ArgumentError -> :invalid
      end
    rescue
      ArgumentError -> :invalid_der
    end
  end
end
