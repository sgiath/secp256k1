defmodule Secp256k1.Extrakeys do
  @moduledoc """
  Module implementing extrakeys functions of secp256k1
  """

  import Secp256k1.Guards

  @doc """
  Derive xonly pubkey from seckey

  ## Examples

      iex> {seckey, _} = Secp256k1.keypair(:compressed)
      iex> xonly = Secp256k1.Extrakeys.xonly_pubkey(seckey)
      iex> byte_size(xonly)
      32

  """
  @spec xonly_pubkey(Secp256k1.seckey()) :: Secp256k1.xonly_pubkey()
  def xonly_pubkey(seckey) when is_seckey(seckey),
    do: Secp256k1.NIF.xonly_pubkey(seckey)
end
