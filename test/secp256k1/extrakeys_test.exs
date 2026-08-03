defmodule Secp256k1Test.Extrakeys do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.Extrakeys

  doctest Secp256k1.Extrakeys

  setup_all do
    {:ok,
     %{
       seckey: d("1111111111111111111111111111111111111111111111111111111111111111"),
       pubkey: d("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
     }}
  end

  test "successful", %{seckey: s, pubkey: p} do
    assert Extrakeys.xonly_pubkey(s) == p
  end

  test "rejects invalid-sized secret keys" do
    assert_raise FunctionClauseError, fn -> Extrakeys.xonly_pubkey(<<1>>) end
  end
end
