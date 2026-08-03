defmodule Secp256k1.Guards do
  @moduledoc """
  Common guards for secp256k1 functions
  """

  @doc """
  Is binary of specific size
  """
  defguard is_bin_size(data, size) when is_binary(data) and byte_size(data) == size

  @doc """
  Is hash (probably) - binary 32 bytes long
  """
  defguard is_hash(data) when is_bin_size(data, 32)

  @doc """
  Is seckey (probably) - binary 32 bytes long
  """
  defguard is_seckey(seckey) when is_bin_size(seckey, 32)

  @doc """
  Is scalar tweak (probably) - binary 32 bytes long
  """
  defguard is_tweak(tweak) when is_bin_size(tweak, 32)

  @doc """
  Is compressed pubkey (probably) - binary 33 bytes long
  """
  defguard is_compressed_pubkey(pubkey) when is_bin_size(pubkey, 33)

  @doc """
  Is uncompressed pubkey (probably) - binary 65 bytes long
  """
  defguard is_uncompressed_pubkey(pubkey) when is_bin_size(pubkey, 65)

  @doc """
  Is xonly pubkey (probably) - binary 32 bytes long
  """
  defguard is_xonly_pubkey(pubkey) when is_bin_size(pubkey, 32)

  @doc """
  Is any type of pubkey (probably)
  """
  defguard is_pubkey(pubkey)
           when is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey) or
                  is_xonly_pubkey(pubkey)

  @doc """
  Is ECDSA signature (probably) - binary 64 bytes long
  """
  defguard is_ecdsa_sig(sig) when is_bin_size(sig, 64)

  @doc """
  Is Schnorr signature (probably) - binary 64 bytes long
  """
  defguard is_schnorr_sig(sig) when is_bin_size(sig, 64)
end
