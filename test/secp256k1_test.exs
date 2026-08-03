defmodule Secp256k1Test do
  use Secp256k1Test.Case, async: true

  doctest Secp256k1

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

  test "keypair", %{seckey: s, pubkey: p} do
    # compressed
    {seckey, pubkey} = Secp256k1.keypair(:compressed)

    assert byte_size(seckey) == 32
    assert byte_size(pubkey) == 33

    # uncompressed
    {seckey, pubkey} = Secp256k1.keypair(:uncompressed)

    assert byte_size(seckey) == 32
    assert byte_size(pubkey) == 65

    # x-only
    {seckey, pubkey} = Secp256k1.keypair(:xonly)

    assert byte_size(seckey) == 32
    assert byte_size(pubkey) == 32

    # with seckey
    {seckey, pubkey} = Secp256k1.keypair(s, :xonly)

    assert seckey == s
    assert pubkey == p
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

  test "ecdsa_valid?/3 accepts compressed and uncompressed public keys" do
    {seckey, compressed_pubkey} = Secp256k1.keypair(<<1::256>>, :compressed)
    uncompressed_pubkey = Secp256k1.pubkey(seckey, :uncompressed)
    msg_hash = :crypto.hash(:sha256, "hello")
    signature = Secp256k1.ecdsa_sign(msg_hash, seckey)

    assert Secp256k1.ecdsa_valid?(signature, msg_hash, compressed_pubkey)
    assert Secp256k1.ecdsa_valid?(signature, msg_hash, uncompressed_pubkey)
  end
end
