defmodule Secp256k1.ECDH do
  @moduledoc """
  Module implementing libsecp256k1 ECDH shared secret computation.

  This returns libsecp256k1's default hashed ECDH output, currently SHA256 over
  the compressed shared point. For generic raw ECDH, use `:crypto.compute_key/4`.

  ## Examples

      iex> seckey = <<1::256>>
      iex> pubkey = Secp256k1.pubkey(<<2::256>>, :compressed)
      iex> shared_secret = Secp256k1.ECDH.ecdh(seckey, pubkey)
      iex> byte_size(shared_secret)
      32

  """

  import Secp256k1.Guards

  @doc """
  Compute libsecp256k1's default hashed ECDH shared secret.
  """
  @spec ecdh(
          seckey :: Secp256k1.seckey(),
          pubkey :: Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
        ) :: Secp256k1.shared_secret()
  def ecdh(seckey, pubkey)
      when is_seckey(seckey) and
             (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) do
    ecdh_nif(seckey, pubkey)
  end

  @doc false
  @spec ecdh_nif(
          seckey :: Secp256k1.seckey(),
          pubkey :: Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
        ) :: Secp256k1.shared_secret()
  def ecdh_nif(_seckey, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/ecdh")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
