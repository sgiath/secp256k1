defmodule Secp256k1.NIF do
  @moduledoc false

  def ecdsa_compressed_pubkey(_seckey), do: :erlang.nif_error({:error, :not_loaded})
  def ecdsa_uncompressed_pubkey(_seckey), do: :erlang.nif_error({:error, :not_loaded})
  def ecdsa_compress_pubkey(_pubkey), do: :erlang.nif_error({:error, :not_loaded})
  def ecdsa_decompress_pubkey(_pubkey), do: :erlang.nif_error({:error, :not_loaded})

  def ecdsa_sign(_msg_hash, _seckey, _nonce_data), do: :erlang.nif_error({:error, :not_loaded})

  def ecdsa_serialize_der(_signature), do: :erlang.nif_error({:error, :not_loaded})
  def ecdsa_parse_der(_signature), do: :erlang.nif_error({:error, :not_loaded})
  def ecdsa_normalize(_signature), do: :erlang.nif_error({:error, :not_loaded})

  def ecdsa_valid?(_signature, _msg_hash, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  def schnorr_sign32(_message, _seckey, _auxiliary_rand), do: :erlang.nif_error({:error, :not_loaded})

  def schnorr_sign_custom(_message, _seckey, _auxiliary_rand), do: :erlang.nif_error({:error, :not_loaded})

  def schnorr_valid?(_signature, _message, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  def ecdh(_seckey, _pubkey), do: :erlang.nif_error({:error, :not_loaded})
  def valid_seckey?(_seckey), do: :erlang.nif_error({:error, :not_loaded})
  def valid_pubkey?(_pubkey), do: :erlang.nif_error({:error, :not_loaded})
  def xonly_pubkey(_seckey), do: :erlang.nif_error({:error, :not_loaded})
  def xonly_pubkey_from_pubkey(_pubkey), do: :erlang.nif_error({:error, :not_loaded})

  def ec_seckey_tweak_add(_seckey, _tweak), do: :erlang.nif_error({:error, :not_loaded})
  def ec_pubkey_tweak_add(_pubkey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  def xonly_seckey_tweak_add(_seckey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  def xonly_pubkey_tweak_add(_pubkey, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  def xonly_pubkey_tweak_add_check(_tweaked_pubkey, _parity, _internal_pubkey, _tweak),
    do: :erlang.nif_error({:error, :not_loaded})

  def musig_pubkey_agg(_pubkeys), do: :erlang.nif_error({:error, :not_loaded})
  def musig_pubkey_get(_keyagg_cache), do: :erlang.nif_error({:error, :not_loaded})

  def musig_pubkey_ec_tweak_add(_keyagg_cache, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  def musig_pubkey_xonly_tweak_add(_keyagg_cache, _tweak), do: :erlang.nif_error({:error, :not_loaded})

  def musig_nonce_gen(_seckey, _pubkey, _message, _keyagg_cache, _extra_input),
    do: :erlang.nif_error({:error, :not_loaded})

  def musig_nonce_agg(_pubnonces), do: :erlang.nif_error({:error, :not_loaded})

  def musig_nonce_process(_aggnonce, _message, _keyagg_cache), do: :erlang.nif_error({:error, :not_loaded})

  def musig_partial_sign(_secnonce, _seckey, _keyagg_cache, _session), do: :erlang.nif_error({:error, :not_loaded})

  def musig_partial_sig_verify(_partial_sig, _pubnonce, _pubkey, _keyagg_cache, _session),
    do: :erlang.nif_error({:error, :not_loaded})

  def musig_partial_sig_agg(_session, _partial_sigs), do: :erlang.nif_error({:error, :not_loaded})

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/secp256k1_nif")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
