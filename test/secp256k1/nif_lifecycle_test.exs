defmodule Secp256k1Test.NifLifecycle do
  @moduledoc false
  use Secp256k1Test.Case, async: false

  alias Secp256k1.ECDSA
  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr

  @legacy_nifs ~w(ecdsa.so schnorrsig.so ecdh.so extrakeys.so musig.so)

  test "package contains only the unified NIF shared object" do
    priv_files =
      :lib_secp256k1
      |> Application.app_dir("priv")
      |> File.ls!()

    assert "secp256k1_nif.so" in priv_files
    assert ["secp256k1_nif.so"] == Enum.filter(priv_files, &String.ends_with?(&1, ".so"))

    for legacy_nif <- @legacy_nifs do
      refute legacy_nif in priv_files
    end
  end

  test "NIF upgrade preserves resources and every feature family remains usable" do
    first_seckey = <<1::256>>
    second_seckey = <<2::256>>
    first_pubkey = ECDSA.pubkey(first_seckey)
    second_pubkey = ECDSA.pubkey(second_seckey)
    {:ok, _aggregate_xonly_pubkey, cache} = MuSig.pubkey_agg([first_pubkey, second_pubkey])
    expected_compressed_pubkey = MuSig.pubkey_get(cache)

    {mod, bin, file} = :code.get_object_code(Secp256k1.NIF)
    assert mod == Secp256k1.NIF

    :code.purge(mod)
    assert {:module, ^mod} = :code.load_binary(mod, file, bin)
    :code.purge(mod)

    message = :crypto.hash(:sha256, "single NIF lifecycle")
    ecdsa_signature = ECDSA.sign(message, first_seckey, nil)
    assert ECDSA.valid?(ecdsa_signature, message, first_pubkey)

    xonly_pubkey = Secp256k1.Extrakeys.xonly_pubkey(first_seckey)
    schnorr_signature = Schnorr.sign32(message, first_seckey, <<0::256>>)
    assert Schnorr.valid?(schnorr_signature, message, xonly_pubkey)

    assert byte_size(Secp256k1.ECDH.ecdh(first_seckey, second_pubkey)) == 32
    assert MuSig.pubkey_get(cache) == expected_compressed_pubkey

    assert_complete_two_signer_flow(<<3::256>>, <<4::256>>, message)
  end

  defp assert_complete_two_signer_flow(first_seckey, second_seckey, message) do
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

    session = MuSig.nonce_process(aggregate_nonce, message, cache)

    signers =
      Enum.map(signers, fn signer ->
        partial_signature =
          MuSig.partial_sign(signer.secnonce, signer.seckey, cache, session)

        assert MuSig.partial_sig_verify(
                 partial_signature,
                 signer.pubnonce,
                 signer.pubkey,
                 cache,
                 session
               )

        Map.put(signer, :partial_signature, partial_signature)
      end)

    final_signature =
      signers
      |> Enum.map(& &1.partial_signature)
      |> then(&MuSig.partial_sig_agg(session, &1))

    assert Schnorr.valid?(final_signature, message, aggregate_xonly_pubkey)
  end
end
