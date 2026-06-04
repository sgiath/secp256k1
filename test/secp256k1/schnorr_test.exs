defmodule Secp256k1Test.Schnorr do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.Schnorr

  doctest Secp256k1.Schnorr

  setup_all do
    {:ok,
     %{
       seckey: d("1111111111111111111111111111111111111111111111111111111111111111"),
       pubkey: d("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
       message: "Bip 340",
       message_hash: :crypto.hash(:sha256, "Bip 340")
     }}
  end

  test "successful", %{seckey: s, pubkey: p, message: msg, message_hash: msg_hash} do
    # custom length
    sig = Schnorr.sign(msg, s)

    assert Schnorr.valid?(sig, msg, p)
    refute Schnorr.valid?(sig, msg_hash, p)

    # 32 byte
    sig = Schnorr.sign(msg_hash, s)

    assert Schnorr.valid?(sig, msg_hash, p)
    refute Schnorr.valid?(sig, msg, p)

    # custom length
    sig = Schnorr.sign_custom(msg, s)

    assert Schnorr.valid?(sig, msg, p)
    refute Schnorr.valid?(sig, msg_hash, p)

    # 32 byte
    sig = Schnorr.sign_custom(msg_hash, s)

    assert Schnorr.valid?(sig, msg_hash, p)
    refute Schnorr.valid?(sig, msg, p)
  end

  test "valid? returns false for x-only pubkeys that fail parsing" do
    message = :binary.copy(<<0>>, 32)
    signature = :binary.copy(<<0>>, 64)

    assert Schnorr.valid?(signature, message, :binary.copy(<<0>>, 32)) == false
    assert Schnorr.valid?(signature, message, :binary.copy(<<255>>, 32)) == false
  end
end
