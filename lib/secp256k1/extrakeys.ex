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
  def xonly_pubkey(seckey) when is_seckey(seckey), do: xonly_pubkey_nif(seckey)

  @doc false
  def xonly_pubkey_nif(_seckey), do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/extrakeys")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
