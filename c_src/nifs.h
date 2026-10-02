#ifndef SECP256K1_NIF_NIFS_H
#define SECP256K1_NIF_NIFS_H

#include "utils.h"

/*
 * The single list of NIF entrypoints registered under Elixir.Secp256k1.NIF.
 * NIF(erl_name, fn, arity, flags) is implemented by secp256k1_nif_<fn>, which
 * this header declares and nif.c wraps in the callback guard as
 * guarded_<fn>. DIRTY_ALIAS(erl_name, fn, arity, flags) registers the
 * existing guarded_<fn> under another name and flags. Every name needs a
 * matching stub in lib/secp256k1/nif.ex.
 */
#define SECP256K1_NIF_LIST(NIF, DIRTY_ALIAS)                                                    \
  NIF("ecdsa_compressed_pubkey", ecdsa_compressed_pubkey, 1, 0)                                 \
  NIF("ecdsa_uncompressed_pubkey", ecdsa_uncompressed_pubkey, 1, 0)                             \
  NIF("ecdsa_compress_pubkey", ecdsa_compress_pubkey, 1, 0)                                     \
  NIF("ecdsa_decompress_pubkey", ecdsa_decompress_pubkey, 1, 0)                                 \
  NIF("ecdsa_sign", ecdsa_sign, 3, 0)                                                           \
  NIF("ecdsa_serialize_der", ecdsa_serialize_der, 1, 0)                                         \
  NIF("ecdsa_parse_der", ecdsa_parse_der, 1, 0)                                                 \
  NIF("ecdsa_normalize", ecdsa_normalize, 1, 0)                                                 \
  NIF("ecdsa_valid?", ecdsa_valid, 3, 0)                                                        \
  NIF("schnorr_sign32", schnorr_sign32, 3, 0)                                                   \
  NIF("schnorr_sign_custom", schnorr_sign_custom, 3, 0)                                         \
  DIRTY_ALIAS("schnorr_sign_custom_dirty", schnorr_sign_custom, 3, ERL_NIF_DIRTY_JOB_CPU_BOUND) \
  NIF("schnorr_valid?", schnorr_valid, 3, 0)                                                    \
  DIRTY_ALIAS("schnorr_valid_dirty?", schnorr_valid, 3, ERL_NIF_DIRTY_JOB_CPU_BOUND)            \
  NIF("ecdh", ecdh, 2, 0)                                                                       \
  NIF("valid_seckey?", valid_seckey, 1, 0)                                                      \
  NIF("valid_pubkey?", valid_pubkey, 1, 0)                                                      \
  NIF("xonly_pubkey", xonly_pubkey, 1, 0)                                                       \
  NIF("xonly_pubkey_from_pubkey", xonly_pubkey_from_pubkey, 1, 0)                               \
  NIF("ec_seckey_tweak_add", ec_seckey_tweak_add, 2, 0)                                         \
  NIF("ec_pubkey_tweak_add", ec_pubkey_tweak_add, 2, 0)                                         \
  NIF("xonly_seckey_tweak_add", xonly_seckey_tweak_add, 2, 0)                                   \
  NIF("xonly_pubkey_tweak_add", xonly_pubkey_tweak_add, 2, 0)                                   \
  NIF("xonly_pubkey_tweak_add_check", xonly_pubkey_tweak_add_check, 4, 0)                       \
  NIF("musig_pubkey_agg", musig_pubkey_agg, 1, ERL_NIF_DIRTY_JOB_CPU_BOUND)                     \
  NIF("musig_pubkey_get", musig_pubkey_get, 1, 0)                                               \
  NIF("musig_pubkey_ec_tweak_add", musig_pubkey_ec_tweak_add, 2, 0)                             \
  NIF("musig_pubkey_xonly_tweak_add", musig_pubkey_xonly_tweak_add, 2, 0)                       \
  NIF("musig_nonce_gen", musig_nonce_gen, 5, 0)                                                 \
  NIF("musig_nonce_agg", musig_nonce_agg, 1, ERL_NIF_DIRTY_JOB_CPU_BOUND)                       \
  NIF("musig_nonce_process", musig_nonce_process, 3, 0)                                         \
  NIF("musig_partial_sign", musig_partial_sign, 4, 0)                                           \
  NIF("musig_partial_sig_verify", musig_partial_sig_verify, 5, 0)                               \
  NIF("musig_partial_sig_agg", musig_partial_sig_agg, 2, ERL_NIF_DIRTY_JOB_CPU_BOUND)

#define SECP256K1_NIF_DECLARE(erl_name, fn, arity, flags) \
  ERL_NIF_TERM secp256k1_nif_##fn(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
#define SECP256K1_NIF_SKIP(erl_name, fn, arity, flags)

SECP256K1_NIF_LIST(SECP256K1_NIF_DECLARE, SECP256K1_NIF_SKIP)

int musig_open_resource_types(ErlNifEnv *env, secp256k1_nif_state *state);

#endif
