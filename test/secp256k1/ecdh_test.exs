defmodule Secp256k1Test.ECDH do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDH

  doctest Secp256k1.ECDH

  setup_all do
    {:ok,
     %{
       alice_seckey: d("0000000000000000000000000000000000000000000000000000000000000001"),
       bob_seckey: d("0000000000000000000000000000000000000000000000000000000000000002"),
       alice_pubkey_compressed:
         d("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
       alice_pubkey_uncompressed:
         d(
           "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
         ),
       bob_pubkey_compressed:
         d("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
       bob_pubkey_uncompressed:
         d(
           "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
         ),
       libsecp_shared_secret:
         d("b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7"),
       raw_shared_secret: d("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
     }}
  end

  test "computes the same shared secret from both participant directions", %{
    alice_seckey: alice_seckey,
    bob_seckey: bob_seckey,
    alice_pubkey_compressed: alice_pubkey,
    bob_pubkey_compressed: bob_pubkey,
    libsecp_shared_secret: expected
  } do
    assert ECDH.ecdh(alice_seckey, bob_pubkey) == expected
    assert ECDH.ecdh(bob_seckey, alice_pubkey) == expected
  end

  test "accepts compressed and uncompressed public keys", %{
    alice_seckey: alice_seckey,
    bob_pubkey_compressed: bob_pubkey_compressed,
    bob_pubkey_uncompressed: bob_pubkey_uncompressed,
    libsecp_shared_secret: expected
  } do
    assert byte_size(ECDH.ecdh(alice_seckey, bob_pubkey_compressed)) == 32
    assert ECDH.ecdh(alice_seckey, bob_pubkey_compressed) == expected
    assert ECDH.ecdh(alice_seckey, bob_pubkey_uncompressed) == expected
  end

  test "public delegate uses the ECDH module", %{
    alice_seckey: alice_seckey,
    bob_pubkey_compressed: bob_pubkey,
    libsecp_shared_secret: expected
  } do
    assert Secp256k1.ecdh(alice_seckey, bob_pubkey) == ECDH.ecdh(alice_seckey, bob_pubkey)
    assert Secp256k1.ecdh(alice_seckey, bob_pubkey) == expected
  end

  test "returns libsecp256k1 default hashed output, not raw crypto ECDH", %{
    alice_seckey: alice_seckey,
    bob_pubkey_compressed: bob_pubkey_compressed,
    bob_pubkey_uncompressed: bob_pubkey_uncompressed,
    libsecp_shared_secret: expected,
    raw_shared_secret: raw_expected
  } do
    raw_shared_secret =
      :crypto.compute_key(:ecdh, bob_pubkey_uncompressed, alice_seckey, :secp256k1)

    assert raw_shared_secret == raw_expected
    assert raw_shared_secret != expected
    assert :crypto.hash(:sha256, bob_pubkey_compressed) == expected
    assert ECDH.ecdh(alice_seckey, bob_pubkey_compressed) == expected
  end

  test "rejects invalid secret keys", %{bob_pubkey_compressed: bob_pubkey} do
    assert_raise FunctionClauseError, fn ->
      ECDH.ecdh(<<1>>, bob_pubkey)
    end

    assert_raise ArgumentError, fn ->
      ECDH.ecdh(<<0::256>>, bob_pubkey)
    end
  end

  test "rejects invalid public keys", %{alice_seckey: alice_seckey} do
    assert_raise FunctionClauseError, fn ->
      ECDH.ecdh(alice_seckey, <<1::256>>)
    end

    assert ECDH.ecdh(alice_seckey, :binary.copy(<<0>>, 33)) ==
             {:error, "secp256k1_ec_pubkey_parse failed"}
  end
end
