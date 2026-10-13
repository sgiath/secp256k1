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
  A completed one-signer transcript: `msg`, `seckey`, `pubkey`, `cache`, `pubnonce`,
  `aggnonce`, `session`, and the `partial_sig` that consumed the signer's secret nonce.
  """
  def signing_state do
    msg = :crypto.strong_rand_bytes(32)
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _agg_xonly_pubkey, cache} = MuSig.pubkey_agg([pubkey])
    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(pubkey, seckey: seckey, msg: msg, cache: cache)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)
    partial_sig = MuSig.partial_sign(secnonce, seckey, cache, session)

    %{
      msg: msg,
      seckey: seckey,
      pubkey: pubkey,
      cache: cache,
      pubnonce: pubnonce,
      aggnonce: aggnonce,
      session: session,
      partial_sig: partial_sig
    }
  end

  @doc """
  Signs `msg` with every signer, asserting each partial signature verifies, and returns the
  aggregate signature. `nonce_gen` maps a signer to its `nonce_gen/2` result; by default it
  binds the signer's secret key, `msg`, and `cache`.
  """
  def sign_with(signers, msg, cache) do
    signers
    |> start_signing(msg, cache)
    |> finish_signing()
  end

  def sign_with(signers, msg, cache, nonce_gen) do
    signers
    |> start_signing(msg, cache, nonce_gen)
    |> finish_signing()
  end

  @doc """
  The first half of `sign_with/3,4`: generates every signer's nonces and the session. Returns
  `%{signers: signers, cache: cache, session: session}`, each signer with its `secnonce` and
  `pubnonce`, for `finish_signing/1`.
  """
  def start_signing(signers, msg, cache) do
    start_signing(
      signers,
      msg,
      cache,
      &MuSig.nonce_gen(&1.pubkey, seckey: &1.seckey, msg: msg, cache: cache)
    )
  end

  def start_signing(signers, msg, cache, nonce_gen) do
    signers =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} = nonce_gen.(signer)
        Map.merge(signer, %{secnonce: secnonce, pubnonce: pubnonce})
      end)

    session =
      signers
      |> Enum.map(& &1.pubnonce)
      |> session_for(msg, cache)

    %{signers: signers, cache: cache, session: session}
  end

  @doc "The second half of `sign_with/3,4`: partial signatures, verified, then aggregated."
  def finish_signing(%{signers: signers, cache: cache, session: session}) do
    partial_sigs =
      Enum.map(signers, fn %{seckey: seckey, pubkey: pubkey} = signer ->
        partial_sig = MuSig.partial_sign(signer.secnonce, seckey, cache, session)

        assert MuSig.partial_sig_verify(partial_sig, signer.pubnonce, pubkey, cache, session) ==
                 true

        partial_sig
      end)

    MuSig.partial_sig_agg(session, partial_sigs)
  end
end
