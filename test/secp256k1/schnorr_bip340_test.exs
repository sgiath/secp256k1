defmodule Secp256k1Test.SchnorrBIP340 do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.Extrakeys
  alias Secp256k1.Schnorr
  alias Secp256k1Test.Vectors

  @vectors Vectors.load_bip340()

  for vector <- @vectors do
    index = vector.index
    comment = vector.comment

    if vector.secret_key && vector.aux_rand do
      test "BIP-340 ##{index}: #{comment} (signing)" do
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

      test "BIP-340 ##{index}: #{comment} (pubkey)" do
        assert Extrakeys.xonly_pubkey(unquote(vector.secret_key)) ==
                 unquote(vector.public_key)
      end
    end

    test "BIP-340 ##{index}: #{comment} (verify)" do
      result =
        Schnorr.valid?(
          unquote(vector.signature),
          unquote(vector.message),
          unquote(vector.public_key)
        )

      if unquote(vector.verification_result) do
        assert result == true
      else
        assert result == false or match?({:error, _}, result)
      end
    end
  end
end
