defmodule Secp256k1Test.ECDSA do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDSA

  doctest Secp256k1.ECDSA

  @curve_order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @compact_signature d(
                       "5dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"
                     )
  @der_signature d(
                   "304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"
                 )

  setup_all do
    {:ok,
     %{
       seckey: d("1111111111111111111111111111111111111111111111111111111111111111"),
       pubkey_compressed: d("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
       pubkey_uncompressed:
         d(
           "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
         )
     }}
  end

  test "successful", %{seckey: seckey, pubkey_compressed: pc, pubkey_uncompressed: pu} do
    assert ECDSA.pubkey(seckey) == pc
    assert ECDSA.pubkey(seckey, compress: true) == pc
    assert ECDSA.pubkey(seckey, compress: false) == pu

    assert ECDSA.compressed_pubkey(seckey) == pc
    assert ECDSA.uncompressed_pubkey(seckey) == pu

    assert ECDSA.compress_pubkey(pu) == pc
    assert ECDSA.decompress_pubkey(pc) == pu
  end

  test "public-key functions reject invalid-sized binary arguments" do
    assert_raise FunctionClauseError, fn -> ECDSA.compressed_pubkey(<<1>>) end
    assert_raise FunctionClauseError, fn -> ECDSA.uncompressed_pubkey(<<1>>) end
    assert_raise FunctionClauseError, fn -> ECDSA.compress_pubkey(<<1>>) end
    assert_raise FunctionClauseError, fn -> ECDSA.decompress_pubkey(<<1>>) end
  end

  test "sign/3 with nil uses deterministic RFC 6979" do
    seckey = d("0000000000000000000000000000000000000000000000000000000000000001")
    msg_hash = d("0000000000000000000000000000000000000000000000000000000000000002")

    expected_signature =
      d(
        "56166f3a4b7d34af3bcc6c8a92a8f3c40309db9f22d7c83f8c5b87b374fd8047348ebb966e4e4c5ab15c43277b857c2844e45958f79b1e511163ca560b2ab246"
      )

    assert ECDSA.sign(msg_hash, seckey, nil) == expected_signature
  end

  test "sign/3 accepts 32-byte nonce data" do
    seckey = d("0000000000000000000000000000000000000000000000000000000000000001")
    msg_hash = d("0000000000000000000000000000000000000000000000000000000000000002")
    nonce_data = d("0000000000000000000000000000000000000000000000000000000000000003")

    expected_signature =
      d(
        "07c27f689e6c426d08caada20c3f896d754c1ac8208a90600cb6a3fc37ba6b4c39b4343acb2c54c14917f43e6af781445819bdb0af55536dc026a24c0ead5617"
      )

    assert ECDSA.sign(msg_hash, seckey, nonce_data) == expected_signature
  end

  test "sign/3 rejects invalid-sized binary arguments", %{seckey: seckey} do
    msg_hash = :crypto.hash(:sha256, "hello")

    assert_raise FunctionClauseError, fn -> ECDSA.sign(<<1>>, seckey, nil) end
    assert_raise FunctionClauseError, fn -> ECDSA.sign(msg_hash, <<1>>, nil) end
    assert_raise FunctionClauseError, fn -> ECDSA.sign(msg_hash, seckey, <<1>>) end
  end

  test "sign/2 injects random nonce data", %{seckey: seckey} do
    msg_hash = :crypto.hash(:sha256, "hello")

    refute ECDSA.sign(msg_hash, seckey) == ECDSA.sign(msg_hash, seckey)
  end

  test "valid? returns false for compact signatures that fail parsing", %{
    pubkey_compressed: pubkey
  } do
    msg_hash = :binary.copy(<<0>>, 32)
    signature = :binary.copy(<<255>>, 64)

    assert ECDSA.valid?(signature, msg_hash, pubkey) == false
  end

  test "valid? returns false for compressed pubkeys that fail parsing", %{seckey: seckey} do
    msg_hash = :crypto.hash(:sha256, "hello")
    signature = ECDSA.sign(msg_hash, seckey)
    pubkey = :binary.copy(<<0>>, 33)

    assert ECDSA.valid?(signature, msg_hash, pubkey) == false
  end

  test "converts compact ECDSA signatures to and from strict DER" do
    assert ECDSA.serialize_der(@compact_signature) == @der_signature
    assert ECDSA.parse_der(@der_signature) == @compact_signature
  end

  test "parse_der rejects malformed DER" do
    assert_raise ArgumentError, fn -> ECDSA.parse_der(@der_signature <> <<0>>) end
    assert_raise FunctionClauseError, fn -> ECDSA.parse_der(<<1>>) end
  end

  test "normalize converts high-S signatures to the low-S form", %{
    seckey: seckey,
    pubkey_compressed: pubkey
  } do
    msg_hash = :crypto.hash(:sha256, "high-S normalization")

    <<r::binary-size(32), low_s::unsigned-big-256>> =
      low_signature = ECDSA.sign(msg_hash, seckey, nil)

    high_signature = <<r::binary, @curve_order - low_s::unsigned-big-256>>

    refute ECDSA.valid?(high_signature, msg_hash, pubkey)
    assert ECDSA.normalize(high_signature) == low_signature
    assert ECDSA.normalize(low_signature) == low_signature

    normalized_signature = ECDSA.normalize(high_signature)
    assert ECDSA.valid?(normalized_signature, msg_hash, pubkey)
  end

  test "parses and normalizes a high-S Bitcoin wire signature", %{
    seckey: seckey,
    pubkey_compressed: pubkey
  } do
    msg_hash = :crypto.hash(:sha256, "Bitcoin wire signature")
    <<r::binary-size(32), low_s::unsigned-big-256>> = ECDSA.sign(msg_hash, seckey, nil)
    high_signature = <<r::binary, @curve_order - low_s::unsigned-big-256>>
    wire_signature = ECDSA.serialize_der(high_signature) <> <<1>>
    der_size = byte_size(wire_signature) - 1
    <<der_signature::binary-size(^der_size), sighash_type>> = wire_signature

    compact_signature = ECDSA.parse_der(der_signature)
    refute ECDSA.valid?(compact_signature, msg_hash, pubkey)

    normalized_signature = ECDSA.normalize(compact_signature)
    assert ECDSA.valid?(normalized_signature, msg_hash, pubkey)
    assert sighash_type == 1
  end

  test "DER and normalization functions reject invalid compact signatures" do
    invalid_signature = :binary.copy(<<255>>, 64)

    assert_raise ArgumentError, fn -> ECDSA.serialize_der(invalid_signature) end
    assert_raise ArgumentError, fn -> ECDSA.normalize(invalid_signature) end
    assert_raise FunctionClauseError, fn -> ECDSA.serialize_der(<<1>>) end
    assert_raise FunctionClauseError, fn -> ECDSA.normalize(<<1>>) end
  end

  test "valid?/3 rejects invalid-sized binary arguments", %{
    seckey: seckey,
    pubkey_compressed: pubkey
  } do
    msg_hash = :crypto.hash(:sha256, "hello")
    signature = ECDSA.sign(msg_hash, seckey)

    assert_raise FunctionClauseError, fn -> ECDSA.valid?(<<1>>, msg_hash, pubkey) end
    assert_raise FunctionClauseError, fn -> ECDSA.valid?(signature, <<1>>, pubkey) end
    assert_raise FunctionClauseError, fn -> ECDSA.valid?(signature, msg_hash, <<1>>) end
  end
end
