#ifndef SECP256K1_NIF_NIFS_H
#define SECP256K1_NIF_NIFS_H

#include "utils.h"

ERL_NIF_TERM secp256k1_nif_ecdsa_compressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_ecdsa_uncompressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_ecdsa_compress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_ecdsa_decompress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_ecdsa_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_ecdsa_valid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM secp256k1_nif_schnorr_sign32(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_schnorr_sign_custom(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_schnorr_valid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM secp256k1_nif_ecdh(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM secp256k1_nif_musig_pubkey_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_pubkey_get(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_pubkey_ec_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_pubkey_xonly_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_nonce_gen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_nonce_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_nonce_process(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_partial_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_partial_sig_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM secp256k1_nif_musig_partial_sig_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

int musig_open_resource_types(ErlNifEnv *env, secp256k1_nif_state *state);

#endif
