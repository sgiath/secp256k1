defmodule Secp256k1.MuSigNonceGenTest do
  use Secp256k1Test.Case, async: true

  import Secp256k1Test.MuSigFlow

  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr

  test "nonce_gen rejects a secret key that does not derive the signer public key" do
    [signer, other] = signers(2)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([signer.pubkey, other.pubkey])
    msg = :crypto.strong_rand_bytes(32)

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(signer.pubkey, seckey: other.seckey, msg: msg, cache: cache)
    end
  end

  test "nonce_gen rejects right-sized invalid secret-key scalars" do
    {_seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)
    curve_order = d("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

    for seckey <- [<<0::256>>, curve_order] do
      assert_raise ArgumentError, fn ->
        MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
      end
    end
  end

  test "nonce_gen optional inputs each produce a verifying signature" do
    signers = signers(2)
    msg = :crypto.strong_rand_bytes(32)
    pubkeys = Enum.map(signers, & &1.pubkey)
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    extra = :crypto.strong_rand_bytes(32)

    variants = [
      defaults: &MuSig.nonce_gen(&1.pubkey),
      explicit_nils: &MuSig.nonce_gen(&1.pubkey, seckey: nil, msg: nil, cache: nil, extra: nil),
      without_seckey: &MuSig.nonce_gen(&1.pubkey, msg: msg, cache: cache),
      without_msg: &MuSig.nonce_gen(&1.pubkey, seckey: &1.seckey, cache: cache),
      without_cache: &MuSig.nonce_gen(&1.pubkey, seckey: &1.seckey, msg: msg),
      with_extra:
        &MuSig.nonce_gen(&1.pubkey, seckey: &1.seckey, msg: msg, cache: cache, extra: extra)
    ]

    for {variant, nonce_gen} <- variants do
      signature = sign_with(signers, msg, cache, nonce_gen)
      assert Schnorr.valid?(signature, msg, agg_xonly_pubkey) == true, "#{variant}"
    end
  end

  test "nonce_gen rejects unknown options without echoing option values" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)

    for opts <- [[sekey: seckey], [seckey: seckey, message: <<1::256>>]] do
      error = assert_raise ArgumentError, fn -> MuSig.nonce_gen(pubkey, opts) end
      refute Exception.message(error) =~ inspect(seckey)
    end
  end

  test "nonce_gen raises FunctionClauseError for wrong-shaped option values" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)

    wrong_shapes = [
      seckey: binary_part(seckey, 0, 31),
      seckey: seckey <> <<0>>,
      seckey: :seckey,
      msg: binary_part(msg, 0, 31),
      msg: msg <> <<0>>,
      cache: <<0::197*8>>,
      extra: <<0::31*8>>,
      extra: <<0::33*8>>
    ]

    for {key, value} <- wrong_shapes do
      opts = Keyword.put([seckey: seckey, msg: msg, cache: cache], key, value)

      assert_raise FunctionClauseError, fn -> MuSig.nonce_gen(pubkey, opts) end
    end

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :nonce_gen, [pubkey, %{seckey: seckey}])
    end
  end

  test "nonce_gen requires a signer public key" do
    msg = :crypto.strong_rand_bytes(32)
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])

    assert_raise FunctionClauseError, fn ->
      apply(MuSig, :nonce_gen, [nil, [seckey: seckey, msg: msg, cache: cache]])
    end

    assert_raise ArgumentError, fn ->
      MuSig.nonce_gen(<<0::33*8>>, seckey: seckey, msg: msg, cache: cache)
    end
  end
end
