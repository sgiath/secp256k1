#include "utils.h"
#include "nifs.h"

/*
 * Applies the libsecp256k1 callback contract after a NIF body ran: an
 * illegal-argument callback raises badarg, an internal-error callback returns
 * an error tuple. The NIF result is discarded in both cases unless the NIF
 * already raised an exception, which must be returned as is.
 */
static ERL_NIF_TERM
guard_result(ErlNifEnv *env, ERL_NIF_TERM result)
{
  int illegal = callback_illegal_fired();
  int internal = callback_internal_fired();

  if ((!illegal && !internal) || enif_is_exception(env, result)) {
    return result;
  }
  if (illegal) {
    return enif_make_badarg(env);
  }
  return error_result(env, "libsecp256k1 internal error");
}

#define GUARDED_NIF(name)                                                                 \
  static ERL_NIF_TERM guarded_##name(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) \
  {                                                                                       \
    ERL_NIF_TERM result;                                                                  \
    callback_flags_clear();                                                               \
    result = secp256k1_nif_##name(env, argc, argv);                                       \
    return guard_result(env, result);                                                     \
  }

GUARDED_NIF(ecdsa_compressed_pubkey)
GUARDED_NIF(ecdsa_uncompressed_pubkey)
GUARDED_NIF(ecdsa_compress_pubkey)
GUARDED_NIF(ecdsa_decompress_pubkey)
GUARDED_NIF(ecdsa_sign)
GUARDED_NIF(ecdsa_serialize_der)
GUARDED_NIF(ecdsa_parse_der)
GUARDED_NIF(ecdsa_normalize)
GUARDED_NIF(ecdsa_valid)
GUARDED_NIF(schnorr_sign32)
GUARDED_NIF(schnorr_sign_custom)
GUARDED_NIF(schnorr_valid)
GUARDED_NIF(ecdh)
GUARDED_NIF(valid_seckey)
GUARDED_NIF(valid_pubkey)
GUARDED_NIF(xonly_pubkey)
GUARDED_NIF(xonly_pubkey_from_pubkey)
GUARDED_NIF(ec_seckey_tweak_add)
GUARDED_NIF(ec_pubkey_tweak_add)
GUARDED_NIF(xonly_seckey_tweak_add)
GUARDED_NIF(xonly_pubkey_tweak_add)
GUARDED_NIF(xonly_pubkey_tweak_add_check)
GUARDED_NIF(musig_pubkey_agg)
GUARDED_NIF(musig_pubkey_get)
GUARDED_NIF(musig_pubkey_ec_tweak_add)
GUARDED_NIF(musig_pubkey_xonly_tweak_add)
GUARDED_NIF(musig_nonce_gen)
GUARDED_NIF(musig_nonce_agg)
GUARDED_NIF(musig_nonce_process)
GUARDED_NIF(musig_partial_sign)
GUARDED_NIF(musig_partial_sig_verify)
GUARDED_NIF(musig_partial_sig_agg)

static ErlNifFunc nif_funcs[] = {
  {"ecdsa_compressed_pubkey", 1, guarded_ecdsa_compressed_pubkey, 0},
  {"ecdsa_uncompressed_pubkey", 1, guarded_ecdsa_uncompressed_pubkey, 0},
  {"ecdsa_compress_pubkey", 1, guarded_ecdsa_compress_pubkey, 0},
  {"ecdsa_decompress_pubkey", 1, guarded_ecdsa_decompress_pubkey, 0},
  {"ecdsa_sign", 3, guarded_ecdsa_sign, 0},
  {"ecdsa_serialize_der", 1, guarded_ecdsa_serialize_der, 0},
  {"ecdsa_parse_der", 1, guarded_ecdsa_parse_der, 0},
  {"ecdsa_normalize", 1, guarded_ecdsa_normalize, 0},
  {"ecdsa_valid?", 3, guarded_ecdsa_valid, 0},
  {"schnorr_sign32", 3, guarded_schnorr_sign32, 0},
  {"schnorr_sign_custom", 3, guarded_schnorr_sign_custom, 0},
  {"schnorr_sign_custom_dirty", 3, guarded_schnorr_sign_custom, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"schnorr_valid?", 3, guarded_schnorr_valid, 0},
  {"schnorr_valid_dirty?", 3, guarded_schnorr_valid, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"ecdh", 2, guarded_ecdh, 0},
  {"valid_seckey?", 1, guarded_valid_seckey, 0},
  {"valid_pubkey?", 1, guarded_valid_pubkey, 0},
  {"xonly_pubkey", 1, guarded_xonly_pubkey, 0},
  {"xonly_pubkey_from_pubkey", 1, guarded_xonly_pubkey_from_pubkey, 0},
  {"ec_seckey_tweak_add", 2, guarded_ec_seckey_tweak_add, 0},
  {"ec_pubkey_tweak_add", 2, guarded_ec_pubkey_tweak_add, 0},
  {"xonly_seckey_tweak_add", 2, guarded_xonly_seckey_tweak_add, 0},
  {"xonly_pubkey_tweak_add", 2, guarded_xonly_pubkey_tweak_add, 0},
  {"xonly_pubkey_tweak_add_check", 4, guarded_xonly_pubkey_tweak_add_check, 0},
  {"musig_pubkey_agg", 1, guarded_musig_pubkey_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"musig_pubkey_get", 1, guarded_musig_pubkey_get, 0},
  {"musig_pubkey_ec_tweak_add", 2, guarded_musig_pubkey_ec_tweak_add, 0},
  {"musig_pubkey_xonly_tweak_add", 2, guarded_musig_pubkey_xonly_tweak_add, 0},
  {"musig_nonce_gen", 5, guarded_musig_nonce_gen, 0},
  {"musig_nonce_agg", 1, guarded_musig_nonce_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"musig_nonce_process", 3, guarded_musig_nonce_process, 0},
  {"musig_partial_sign", 4, guarded_musig_partial_sign, 0},
  {"musig_partial_sig_verify", 5, guarded_musig_partial_sig_verify, 0},
  {"musig_partial_sig_agg", 2, guarded_musig_partial_sig_agg, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
  secp256k1_nif_state *state;

  (void)load_info;

  callback_flags_clear();
  state = secp256k1_nif_state_create();
  if (!state) {
    return -1;
  }

  if (!musig_open_resource_types(env, state) || callback_illegal_fired() ||
      callback_internal_fired()) {
    secp256k1_nif_state_destroy(state);
    return -1;
  }

  *priv_data = state;
  return 0;
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
