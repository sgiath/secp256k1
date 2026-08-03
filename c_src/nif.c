#include "utils.h"
#include "nifs.h"

static ErlNifFunc nif_funcs[] = {
  {"ecdsa_compressed_pubkey", 1, secp256k1_nif_ecdsa_compressed_pubkey, 0},
  {"ecdsa_uncompressed_pubkey", 1, secp256k1_nif_ecdsa_uncompressed_pubkey, 0},
  {"ecdsa_compress_pubkey", 1, secp256k1_nif_ecdsa_compress_pubkey, 0},
  {"ecdsa_decompress_pubkey", 1, secp256k1_nif_ecdsa_decompress_pubkey, 0},
  {"ecdsa_sign", 3, secp256k1_nif_ecdsa_sign, 0},
  {"ecdsa_serialize_der", 1, secp256k1_nif_ecdsa_serialize_der, 0},
  {"ecdsa_parse_der", 1, secp256k1_nif_ecdsa_parse_der, 0},
  {"ecdsa_normalize", 1, secp256k1_nif_ecdsa_normalize, 0},
  {"ecdsa_valid?", 3, secp256k1_nif_ecdsa_valid, 0},
  {"schnorr_sign32", 3, secp256k1_nif_schnorr_sign32, 0},
  {"schnorr_sign_custom", 3, secp256k1_nif_schnorr_sign_custom, 0},
  {"schnorr_valid?", 3, secp256k1_nif_schnorr_valid, 0},
  {"ecdh", 2, secp256k1_nif_ecdh, 0},
  {"valid_seckey?", 1, secp256k1_nif_valid_seckey, 0},
  {"valid_pubkey?", 1, secp256k1_nif_valid_pubkey, 0},
  {"xonly_pubkey", 1, secp256k1_nif_xonly_pubkey, 0},
  {"xonly_pubkey_from_pubkey", 1, secp256k1_nif_xonly_pubkey_from_pubkey, 0},
  {"ec_seckey_tweak_add", 2, secp256k1_nif_ec_seckey_tweak_add, 0},
  {"ec_pubkey_tweak_add", 2, secp256k1_nif_ec_pubkey_tweak_add, 0},
  {"xonly_seckey_tweak_add", 2, secp256k1_nif_xonly_seckey_tweak_add, 0},
  {"xonly_pubkey_tweak_add", 2, secp256k1_nif_xonly_pubkey_tweak_add, 0},
  {"xonly_pubkey_tweak_add_check", 4, secp256k1_nif_xonly_pubkey_tweak_add_check, 0},
  {"musig_pubkey_agg", 1, secp256k1_nif_musig_pubkey_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"musig_pubkey_get", 1, secp256k1_nif_musig_pubkey_get, 0},
  {"musig_pubkey_ec_tweak_add", 2, secp256k1_nif_musig_pubkey_ec_tweak_add, 0},
  {"musig_pubkey_xonly_tweak_add", 2, secp256k1_nif_musig_pubkey_xonly_tweak_add, 0},
  {"musig_nonce_gen", 5, secp256k1_nif_musig_nonce_gen, 0},
  {"musig_nonce_agg", 1, secp256k1_nif_musig_nonce_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"musig_nonce_process", 3, secp256k1_nif_musig_nonce_process, 0},
  {"musig_partial_sign", 4, secp256k1_nif_musig_partial_sign, 0},
  {"musig_partial_sig_verify", 5, secp256k1_nif_musig_partial_sig_verify, 0},
  {"musig_partial_sig_agg", 2, secp256k1_nif_musig_partial_sig_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

static int
load_state(ErlNifEnv *env, void **priv_data)
{
  secp256k1_nif_state *state = secp256k1_nif_state_create();

  if (!state) {
    return -1;
  }

  if (!musig_open_resource_types(env, state)) {
    secp256k1_nif_state_destroy(state);
    return -1;
  }

  *priv_data = state;
  return 0;
}

static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
  (void)load_info;
  return load_state(env, priv_data);
}

static int
upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
  (void)old_priv_data;
  return load(env, priv_data, load_info);
}

static void
unload(ErlNifEnv *env, void *priv_data)
{
  (void)env;
  secp256k1_nif_state_destroy(priv_data);
}

ERL_NIF_INIT(Elixir.Secp256k1.NIF, nif_funcs, &load, NULL, &upgrade, &unload)
