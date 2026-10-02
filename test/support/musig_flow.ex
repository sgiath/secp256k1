defmodule Secp256k1Test.MuSigFlow do
  @moduledoc false
  # Shared MuSig signing steps for tests: signer key pairs, sessions, and a full signing round.

  import ExUnit.Assertions

  alias Secp256k1.MuSig

  @doc "Fresh signers, compressed when given a count, or one per pubkey encoding."
  def signers(count) when is_integer(count), do: signers(List.duplicate(:compressed, count))

  def signers(encodings) when is_list(encodings) do
    for encoding <- encodings do
      {seckey, pubkey} = Secp256k1.keypair(encoding)
      %{seckey: seckey, pubkey: pubkey}
    end
  end

  @doc "Aggregates `pubnonces` and processes the aggregate nonce into a session."
  def session_for(pubnonces, msg, cache) do
    pubnonces
    |> MuSig.nonce_agg()
    |> MuSig.nonce_process(msg, cache)
  end

  @doc """
  Signs `msg` with every signer, asserting each partial signature verifies, and returns the
  aggregate signature. `nonce_gen` maps a signer to its `nonce_gen/2` result; by default it
  binds the signer's secret key, `msg`, and `cache`.
  """
  def sign_with(signers, msg, cache) do
    sign_with(
      signers,
      msg,
      cache,
      &MuSig.nonce_gen(&1.pubkey, seckey: &1.seckey, msg: msg, cache: cache)
    )
  end

  def sign_with(signers, msg, cache, nonce_gen) do
    nonces =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} = nonce_gen.(signer)
        {secnonce, pubnonce}
      end)

    session =
      nonces
      |> Enum.map(fn {_secnonce, pubnonce} -> pubnonce end)
      |> session_for(msg, cache)

    partial_sigs =
      Enum.zip_with(signers, nonces, fn signer, {secnonce, pubnonce} ->
        partial_sig = MuSig.partial_sign(secnonce, signer.seckey, cache, session)

        assert MuSig.partial_sig_verify(partial_sig, pubnonce, signer.pubkey, cache, session) ==
                 true

        partial_sig
      end)

    MuSig.partial_sig_agg(session, partial_sigs)
  end
end
