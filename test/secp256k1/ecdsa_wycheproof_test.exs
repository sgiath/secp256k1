defmodule Secp256k1Test.ECDSAWycheproof do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDSA
  alias Secp256k1Test.Vectors

  # Pinned independently of the fixture so a fixture that shrinks together with its own
  # `numberOfTests` still fails.
  @expected_tests 463

  setup_all do
    {:ok, vectors: Vectors.load_wycheproof_ecdsa()}
  end

  test "loads every declared Wycheproof case", %{vectors: vectors} do
    tc_ids = Enum.map(vectors.tests, & &1.tc_id)

    assert vectors.number_of_tests == @expected_tests
    assert length(vectors.tests) == @expected_tests
    assert tc_ids == Enum.to_list(1..@expected_tests)
  end

  test "Wycheproof ECDSA vectors", %{vectors: vectors} do
    failures = Enum.flat_map(vectors.tests, &vector_failures/1)

    assert failures == [], Enum.join(failures, "\n")
  end

  # A valid vector must parse and verify. An invalid vector is rejected either by DER parsing
  # or by `valid?/3` returning `false`; once the DER parses, `valid?/3` must return a boolean.
  defp vector_failures(test_case) do
    actual = outcome(test_case)

    accepted =
      case test_case.result do
        "valid" -> [true]
        "invalid" -> [false, :der_rejected]
        _unknown -> []
      end

    if actual in accepted do
      []
    else
      comment = test_case.comment || "tc #{test_case.tc_id}"

      [
        "Wycheproof ECDSA ##{test_case.tc_id} (#{comment}): " <>
          "expected #{test_case.result}, got #{inspect(actual)}"
      ]
    end
  end

  defp outcome(test_case) do
    case parse_der(test_case.sig) do
      {:ok, signature} -> verify(signature, test_case)
      :rejected -> :der_rejected
    end
  end

  # Malformed DER in the accepted 8-72 byte range raises `ArgumentError`; any other length
  # fails the guard.
  defp parse_der(der) when byte_size(der) in 8..72 do
    {:ok, ECDSA.parse_der(der)}
  rescue
    ArgumentError -> :rejected
  end

  defp parse_der(der) do
    {:ok, ECDSA.parse_der(der)}
  rescue
    FunctionClauseError -> :rejected
  end

  # Exceptions are reported as failures, not accepted as rejections.
  defp verify(signature, test_case) do
    pubkey = ECDSA.compress_pubkey(test_case.pubkey)
    msg_hash = :crypto.hash(:sha256, test_case.msg)

    ECDSA.valid?(signature, msg_hash, pubkey)
  rescue
    exception -> {:raised, exception}
  end
end
