defmodule Secp256k1Test.SchnorrBIP340 do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.Extrakeys
  alias Secp256k1.Schnorr
  alias Secp256k1Test.Vectors

  @vectors Vectors.load_bip340()
  @signing_vectors Enum.filter(@vectors, &(&1.secret_key && &1.aux_rand))
  @pubkey_vectors Enum.filter(@vectors, & &1.secret_key)

  test "loads all 19 BIP-340 vectors" do
    assert Enum.map(@vectors, & &1.index) == Enum.to_list(0..18)
  end

  # A blanked secret key or AUX field would silently drop its generated check.
  test "generates 8 signing and 8 public-key checks" do
    assert length(@signing_vectors) == 8
    assert length(@pubkey_vectors) == 8
  end

  for vector <- @signing_vectors do
    test "BIP-340 ##{vector.index}: #{vector.comment} (signing)" do
      seckey = unquote(vector.secret_key)
      aux = unquote(vector.aux_rand)
      message = unquote(vector.message)

      sig =
        if byte_size(message) == 32 do
          Schnorr.sign32(message, seckey, aux)
        else
          Schnorr.sign_custom(message, seckey, aux)
        end

      assert sig == unquote(vector.signature)
    end
  end

  for vector <- @pubkey_vectors do
    test "BIP-340 ##{vector.index}: #{vector.comment} (pubkey)" do
      assert Extrakeys.xonly_pubkey(unquote(vector.secret_key)) == unquote(vector.public_key)
    end
  end

  for vector <- @vectors do
    test "BIP-340 ##{vector.index}: #{vector.comment} (verify)" do
      result =
        Schnorr.valid?(
          unquote(vector.signature),
          unquote(vector.message),
          unquote(vector.public_key)
        )

      assert result == unquote(vector.verification_result)
    end
  end
end
