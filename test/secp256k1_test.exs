defmodule Secp256k1Test do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDH
  alias Secp256k1.ECDSA
  alias Secp256k1.Extrakeys
  alias Secp256k1.Schnorr

  doctest Secp256k1

  @curve_order d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

  setup_all do
    {:ok,
     %{
       seckey: d("eea73e861ec4ebda129c8fac849d28a244d43e0e51092736a704732c5377e9d2"),
       pubkey: d("8ab190faee92eda6b14a402e28229762015d8ce464b4c9e9593e466cecbef015"),
       message: d("1bb96f5c4738df288c57eed39c16b87fc5e3d863c689cca7f6d0f3cb92e04ec4"),
       signature:
         d(
           "ab344b9d1956bb4a17ac73f16b099faad1484271e41821a636af2260d39d94850dc0823dec7ec5acfbf6323feb43482632feb87b5f8ee7aa2b982f0d775f8098"
         )
     }}
  end

  test "keypair/1 generates a valid secret key and its derived public key" do
    for {type, pubkey_size} <- [compressed: 33, uncompressed: 65, xonly: 32] do
      {seckey, pubkey} = Secp256k1.keypair(type)

      assert Secp256k1.valid_seckey?(seckey)
      assert byte_size(pubkey) == pubkey_size
      assert pubkey == Secp256k1.pubkey(seckey, type)
    end
  end

  test "keypair/2 derives the public key of the given secret key", %{seckey: s, pubkey: p} do
    assert Secp256k1.keypair(s, :xonly) == {s, p}
  end

  test "pubkey", %{seckey: s, pubkey: p} do
    # compressed
    pubkey = Secp256k1.pubkey(s, :compressed)
    assert byte_size(pubkey) == 33

    # uncompressed
    pubkey = Secp256k1.pubkey(s, :uncompressed)
    assert byte_size(pubkey) == 65

    # x-only
    pubkey = Secp256k1.pubkey(s, :xonly)
    assert pubkey == p
  end

  test "convert_pubkey/2 converts a received compressed public key to x-only", %{
    seckey: seckey,
    pubkey: xonly_pubkey
  } do
    compressed_pubkey = Secp256k1.pubkey(seckey, :compressed)

    assert Secp256k1.convert_pubkey(compressed_pubkey, :xonly) == xonly_pubkey
  end

  test "convert_pubkey/2 returns an error for a malformed compressed public key" do
    assert {:error, _reason} = Secp256k1.convert_pubkey(<<0::264>>, :xonly)
  end

  test "convert_pubkey/2 converts between compressed and uncompressed formats", %{seckey: seckey} do
    compressed_pubkey = Secp256k1.pubkey(seckey, :compressed)
    uncompressed_pubkey = Secp256k1.pubkey(seckey, :uncompressed)

    assert Secp256k1.convert_pubkey(uncompressed_pubkey, :compressed) == compressed_pubkey
    assert Secp256k1.convert_pubkey(compressed_pubkey, :uncompressed) == uncompressed_pubkey
  end

  test "convert_pubkey/2 returns an error for a malformed public key" do
    assert {:error, _reason} = Secp256k1.convert_pubkey(<<0::520>>, :compressed)
  end

  test "convert_pubkey/2 rejects encodings it cannot convert" do
    assert_raise FunctionClauseError, fn -> Secp256k1.convert_pubkey(<<1>>, :xonly) end

    assert_raise FunctionClauseError, fn ->
      apply(Secp256k1, :convert_pubkey, [<<0::520>>, :xonly])
    end
  end

  # Delegates have no logic of their own: each must return what its feature function returns.
  test "delegates return their feature functions' results" do
    # The public key of 6 has odd Y, so the plain and x-only tweaks give different results.
    seckey = <<6::256>>
    tweak = <<1::256>>
    msg_hash = :crypto.hash(:sha256, "facade delegates")
    compressed = Secp256k1.pubkey(seckey, :compressed)
    xonly = Secp256k1.pubkey(seckey, :xonly)
    {:ok, tweaked_xonly, parity} = Extrakeys.xonly_pubkey_tweak_add(xonly, tweak)
    <<r::binary-size(32), s::256>> = ecdsa_sig = ECDSA.sign(msg_hash, seckey, nil)
    high_s_sig = <<r::binary, :binary.decode_unsigned(@curve_order) - s::256>>
    schnorr_sig = Schnorr.sign32(msg_hash, seckey, <<0::256>>)

    delegates = [
      {:valid_seckey?, Extrakeys, :valid_seckey?, [seckey]},
      {:valid_pubkey?, Extrakeys, :valid_pubkey?, [xonly]},
      {:ec_seckey_tweak_add, Extrakeys, :ec_seckey_tweak_add, [seckey, tweak]},
      {:ec_pubkey_tweak_add, Extrakeys, :ec_pubkey_tweak_add, [compressed, tweak]},
      {:xonly_seckey_tweak_add, Extrakeys, :xonly_seckey_tweak_add, [seckey, tweak]},
      {:xonly_pubkey_tweak_add, Extrakeys, :xonly_pubkey_tweak_add, [xonly, tweak]},
      {:xonly_pubkey_tweak_add_check, Extrakeys, :xonly_pubkey_tweak_add_check,
       [tweaked_xonly, parity, xonly, tweak]},
      {:ecdh, ECDH, :ecdh, [seckey, Secp256k1.pubkey(<<2::256>>, :compressed)]},
      {:ecdsa_signature_serialize_der, ECDSA, :serialize_der, [ecdsa_sig]},
      {:ecdsa_signature_parse_der, ECDSA, :parse_der, [ECDSA.serialize_der(ecdsa_sig)]},
      {:ecdsa_signature_normalize, ECDSA, :normalize, [high_s_sig]},
      {:ecdsa_valid?, ECDSA, :valid?, [ecdsa_sig, msg_hash, compressed]},
      {:schnorr_valid?, Schnorr, :valid?, [schnorr_sig, msg_hash, xonly]}
    ]

    for {delegate, module, function, args} <- delegates do
      assert apply(Secp256k1, delegate, args) == apply(module, function, args), "#{delegate}"
    end

    # The randomized signers cannot be compared by value; their signatures must verify.
    ecdsa_signature = Secp256k1.ecdsa_sign(msg_hash, seckey)
    assert ECDSA.valid?(ecdsa_signature, msg_hash, compressed)
    schnorr_signature = Secp256k1.schnorr_sign(msg_hash, seckey)
    assert Schnorr.valid?(schnorr_signature, msg_hash, xonly)
  end
end
