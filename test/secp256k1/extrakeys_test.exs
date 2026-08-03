defmodule Secp256k1Test.Extrakeys do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.Extrakeys

  doctest Secp256k1.Extrakeys

  @generator_x d("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  @generator_compressed d("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  @negated_generator_compressed d(
                                  "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                )
  @point_two_x d("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
  @point_two_compressed d("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
  @curve_order d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

  # BIP-341 wallet-test-vectors.json: scriptPubKey[1], keyPathSpending[0].inputSpending[1]
  # https://github.com/bitcoin/bips/blob/e35a46ecf3031c21dc7f7fdb694986789a3a8144/bip-0341/wallet-test-vectors.json
  @bip341_internal_seckey d("1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f")
  @bip341_internal_pubkey d("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27")
  @bip341_tweak d("cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001")
  @bip341_output_pubkey d("147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3")
  @bip341_output_seckey d("ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080")

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

  test "converts a compressed public key to x-only form" do
    assert Extrakeys.xonly_pubkey(@generator_compressed) == @generator_x
    assert Extrakeys.xonly_pubkey(@negated_generator_compressed) == @generator_x
  end

  test "rejects malformed compressed public keys" do
    assert {:error, _reason} = Extrakeys.xonly_pubkey(<<0::264>>)
  end

  test "adds a scalar tweak to secret and public keys" do
    seckey = <<1::256>>
    tweak = <<1::256>>
    assert Extrakeys.ec_seckey_tweak_add(seckey, tweak) == <<2::256>>
    assert Extrakeys.ec_pubkey_tweak_add(@generator_compressed, tweak) == @point_two_compressed
  end

  test "preserves uncompressed public-key serialization when adding a tweak" do
    seckey = <<1::256>>
    pubkey = Secp256k1.pubkey(seckey, :uncompressed)

    assert Extrakeys.ec_pubkey_tweak_add(pubkey, <<1::256>>) ==
             Secp256k1.pubkey(<<2::256>>, :uncompressed)
  end

  test "rejects scalar tweaks that produce invalid plain keys" do
    cancelling_tweak = d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")

    assert {:error, _reason} = Extrakeys.ec_seckey_tweak_add(<<1::256>>, cancelling_tweak)

    assert {:error, _reason} =
             Extrakeys.ec_pubkey_tweak_add(@generator_compressed, cancelling_tweak)
  end

  test "rejects the curve order instead of reducing it modulo the order" do
    assert {:error, _reason} = Extrakeys.ec_seckey_tweak_add(<<1::256>>, @curve_order)
    assert {:error, _reason} = Extrakeys.ec_pubkey_tweak_add(@generator_compressed, @curve_order)
    assert {:error, _reason} = Extrakeys.xonly_seckey_tweak_add(<<1::256>>, @curve_order)
    assert {:error, _reason} = Extrakeys.xonly_pubkey_tweak_add(@generator_x, @curve_order)
  end

  test "accepts the zero tweak as the identity" do
    zero = <<0::256>>

    assert Extrakeys.ec_seckey_tweak_add(<<1::256>>, zero) == <<1::256>>
    assert Extrakeys.ec_pubkey_tweak_add(@generator_compressed, zero) == @generator_compressed
    assert Extrakeys.xonly_seckey_tweak_add(<<1::256>>, zero) == <<1::256>>
    assert {:ok, @generator_x, 0} = Extrakeys.xonly_pubkey_tweak_add(@generator_x, zero)
    assert Extrakeys.xonly_pubkey_tweak_add_check(@generator_x, 0, @generator_x, zero)
  end

  test "adds and checks x-only public-key tweaks with output parity" do
    assert {:ok, @point_two_x, 0} =
             Extrakeys.xonly_pubkey_tweak_add(@generator_x, <<1::256>>)

    assert Extrakeys.xonly_pubkey_tweak_add_check(
             @point_two_x,
             0,
             @generator_x,
             <<1::256>>
           )

    refute Extrakeys.xonly_pubkey_tweak_add_check(
             @point_two_x,
             1,
             @generator_x,
             <<1::256>>
           )
  end

  test "tweaks x-only secret keys for signing" do
    assert Extrakeys.xonly_seckey_tweak_add(<<1::256>>, <<1::256>>) == <<2::256>>

    tweaked_seckey = Extrakeys.xonly_seckey_tweak_add(<<6::256>>, <<1::256>>)
    internal_pubkey = Extrakeys.xonly_pubkey(<<6::256>>)
    {:ok, tweaked_pubkey, _parity} = Extrakeys.xonly_pubkey_tweak_add(internal_pubkey, <<1::256>>)

    assert Extrakeys.xonly_pubkey(tweaked_seckey) == tweaked_pubkey
  end

  test "matches the published BIP-341 odd-parity key-tweak vector" do
    assert Extrakeys.xonly_pubkey(@bip341_internal_seckey) == @bip341_internal_pubkey

    assert {:ok, @bip341_output_pubkey, 1} =
             Extrakeys.xonly_pubkey_tweak_add(@bip341_internal_pubkey, @bip341_tweak)

    assert Extrakeys.xonly_pubkey_tweak_add_check(
             @bip341_output_pubkey,
             1,
             @bip341_internal_pubkey,
             @bip341_tweak
           )

    assert Extrakeys.xonly_seckey_tweak_add(@bip341_internal_seckey, @bip341_tweak) ==
             @bip341_output_seckey

    assert Extrakeys.xonly_pubkey(@bip341_output_seckey) == @bip341_output_pubkey
  end

  test "rejects invalid tweak input sizes at the Elixir boundary" do
    assert_raise FunctionClauseError, fn -> Extrakeys.ec_seckey_tweak_add(<<1::256>>, <<1>>) end

    assert_raise FunctionClauseError, fn ->
      Extrakeys.xonly_pubkey_tweak_add(@generator_x, <<1>>)
    end
  end
end
