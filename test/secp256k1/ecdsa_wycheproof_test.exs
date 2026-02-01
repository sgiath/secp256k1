defmodule Secp256k1Test.ECDSAWycheproof do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDSA
  alias Secp256k1Test.DER
  alias Secp256k1Test.Vectors

  @tests Vectors.load_wycheproof_ecdsa()
  @skip_flags ["BerEncodedSignature", "InvalidEncoding", "InvalidTypesInSignature"]

  test "Wycheproof filtering excludes DER-encoding flags" do
    assert Enum.all?(@tests, fn test ->
             Enum.all?(test.flags, &(&1 not in @skip_flags))
           end)
  end

  for test_case <- @tests do
    tc_id = test_case.tc_id
    comment = test_case.comment || "tc #{tc_id}"

    test "Wycheproof ECDSA ##{tc_id}: #{comment}" do
      expected = unquote(test_case.result) == "valid"
      pubkey = ECDSA.compress_pubkey(unquote(test_case.pubkey))
      msg = unquote(test_case.msg)
      msg_hash = :crypto.hash(:sha256, msg)

      actual =
        try do
          signature = DER.to_compact(unquote(test_case.sig))

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

      if expected do
        assert actual == true
      else
        assert actual in [false, :invalid, :invalid_der]
      end
    end
  end
end
