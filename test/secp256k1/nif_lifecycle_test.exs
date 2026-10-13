defmodule Secp256k1Test.NifLifecycle do
  @moduledoc false
  use Secp256k1Test.Case, async: false

  import Secp256k1Test.MuSigFlow

  alias Secp256k1.ECDSA
  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr

  test "NIF upgrade preserves resources and every feature family remains usable" do
    message = :crypto.hash(:sha256, "single NIF lifecycle")
    first_seckey = <<1::256>>
    second_seckey = <<2::256>>
    first_pubkey = ECDSA.pubkey(first_seckey)
    second_pubkey = ECDSA.pubkey(second_seckey)
    {:ok, _aggregate_xonly_pubkey, cache} = MuSig.pubkey_agg([first_pubkey, second_pubkey])
    expected_compressed_pubkey = MuSig.pubkey_get(cache)

    # Live secret nonces and session created before the upgrade, signed with after it.
    signers = signers(2)
    {:ok, live_xonly_pubkey, live_cache} = MuSig.pubkey_agg(Enum.map(signers, & &1.pubkey))
    live_flow = start_signing(signers, message, live_cache)

    # A nonce consumed before the upgrade must stay consumed after it.
    consumed_signer = hd(signers)

    {:ok, consumed_secnonce, _pubnonce} =
      MuSig.nonce_gen(consumed_signer.pubkey,
        seckey: consumed_signer.seckey,
        msg: message,
        cache: live_cache
      )

    assert <<_::binary-size(32)>> =
             MuSig.partial_sign(
               consumed_secnonce,
               consumed_signer.seckey,
               live_cache,
               live_flow.session
             )

    {mod, bin, file} = :code.get_object_code(Secp256k1.NIF)
    assert mod == Secp256k1.NIF

    :code.purge(mod)
    assert {:module, ^mod} = :code.load_binary(mod, file, bin)
    :code.purge(mod)

    ecdsa_signature = ECDSA.sign(message, first_seckey, nil)
    assert ECDSA.valid?(ecdsa_signature, message, first_pubkey)

    xonly_pubkey = Secp256k1.Extrakeys.xonly_pubkey(first_seckey)
    schnorr_signature = Schnorr.sign32(message, first_seckey, <<0::256>>)
    assert Schnorr.valid?(schnorr_signature, message, xonly_pubkey)

    assert byte_size(Secp256k1.ECDH.ecdh(first_seckey, second_pubkey)) == 32
    assert MuSig.pubkey_get(cache) == expected_compressed_pubkey

    assert MuSig.partial_sign(
             consumed_secnonce,
             consumed_signer.seckey,
             live_cache,
             live_flow.session
           ) == {:error, "nonce already used"}

    assert Schnorr.valid?(finish_signing(live_flow), message, live_xonly_pubkey) == true

    fresh_signers = signers(2)

    {:ok, fresh_xonly_pubkey, fresh_cache} =
      MuSig.pubkey_agg(Enum.map(fresh_signers, & &1.pubkey))

    signature = sign_with(fresh_signers, message, fresh_cache)
    assert Schnorr.valid?(signature, message, fresh_xonly_pubkey) == true
  end
end
