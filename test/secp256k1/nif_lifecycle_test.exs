defmodule Secp256k1Test.NifLifecycle do
  @moduledoc false
  use Secp256k1Test.Case, async: false

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
    live_flow = start_two_signer_flow(<<3::256>>, <<4::256>>, message)

    # A nonce consumed before the upgrade must stay consumed after it.
    consumed_signer = hd(live_flow.signers)

    {:ok, consumed_secnonce, _pubnonce} =
      MuSig.nonce_gen(
        consumed_signer.seckey,
        consumed_signer.pubkey,
        message,
        live_flow.cache,
        nil
      )

    assert <<_::binary-size(32)>> =
             MuSig.partial_sign(
               consumed_secnonce,
               consumed_signer.seckey,
               live_flow.cache,
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
             live_flow.cache,
             live_flow.session
           ) == {:error, "nonce already used"}

    finish_two_signer_flow(live_flow)

    <<5::256>>
    |> start_two_signer_flow(<<6::256>>, message)
    |> finish_two_signer_flow()
  end

  defp start_two_signer_flow(first_seckey, second_seckey, message) do
    signers =
      Enum.map([first_seckey, second_seckey], fn seckey ->
        %{seckey: seckey, pubkey: ECDSA.pubkey(seckey)}
      end)

    {:ok, aggregate_xonly_pubkey, cache} =
      signers
      |> Enum.map(& &1.pubkey)
      |> MuSig.pubkey_agg()

    signers =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} =
          MuSig.nonce_gen(signer.seckey, signer.pubkey, message, cache, nil)

        Map.merge(signer, %{secnonce: secnonce, pubnonce: pubnonce})
      end)

    aggregate_nonce =
      signers
      |> Enum.map(& &1.pubnonce)
      |> MuSig.nonce_agg()

    %{
      signers: signers,
      message: message,
      aggregate_xonly_pubkey: aggregate_xonly_pubkey,
      cache: cache,
      session: MuSig.nonce_process(aggregate_nonce, message, cache)
    }
  end

  defp finish_two_signer_flow(%{cache: cache, session: session} = flow) do
    partial_signatures =
      Enum.map(flow.signers, fn signer ->
        partial_signature =
          MuSig.partial_sign(signer.secnonce, signer.seckey, cache, session)

        assert MuSig.partial_sig_verify(
                 partial_signature,
                 signer.pubnonce,
                 signer.pubkey,
                 cache,
                 session
               )

        partial_signature
      end)

    final_signature = MuSig.partial_sig_agg(session, partial_signatures)

    assert Schnorr.valid?(final_signature, flow.message, flow.aggregate_xonly_pubkey)
  end
end
