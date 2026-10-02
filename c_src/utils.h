#ifndef SECP256K1_NIF_UTILS_H
#define SECP256K1_NIF_UTILS_H

#include <stddef.h>

#include <erl_nif.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "fault.h"

/* Fixed sizes, in bytes, of values crossing the NIF boundary. */
#define SECKEY_SIZE 32
#define HASH_SIZE 32
#define TWEAK_SIZE 32
#define XONLY_PUBKEY_SIZE 32
#define COMPRESSED_PUBKEY_SIZE 33
#define UNCOMPRESSED_PUBKEY_SIZE 65
#define ECDSA_COMPACT_SIG_SIZE 64
#define ECDSA_DER_SIG_MIN_SIZE 8
#define ECDSA_DER_SIG_MAX_SIZE 72
#define ECDSA_NONCE_DATA_SIZE 32
#define SCHNORR_SIG_SIZE 64
#define SCHNORR_AUX_RAND_SIZE 32
#define ECDH_SHARED_SECRET_SIZE 32
#define CONTEXT_SEED_SIZE 32
#define MUSIG_PUBNONCE_SIZE 66
#define MUSIG_AGGNONCE_SIZE 66
#define MUSIG_PARTIAL_SIG_SIZE 32
#define MUSIG_SESSION_SECRAND_SIZE 32
#define MUSIG_EXTRA_INPUT_SIZE 32

typedef struct {
  /* Context created in `ctx_memory`, which this state owns (enif_alloc). */
  secp256k1_context *ctx;
  void *ctx_memory;
  ErlNifResourceType *keyagg_cache_rt;
  ErlNifResourceType *session_rt;
  ErlNifResourceType *secnonce_rt;
} secp256k1_nif_state;

secp256k1_nif_state *secp256k1_nif_state_create(void);
void secp256k1_nif_state_destroy(secp256k1_nif_state *state);
void secure_erase(void *ptr, size_t len);
int make_binary(ErlNifEnv *env, const unsigned char *data, size_t size, ERL_NIF_TERM *result);
ERL_NIF_TERM error_result(ErlNifEnv *env, const char *error_msg);
ERL_NIF_TERM allocation_failed(ErlNifEnv *env);

/* Inspects `term` as a 32-byte binary holding a valid secret scalar. */
int get_seckey(ErlNifEnv *env, ERL_NIF_TERM term, ErlNifBinary *seckey);

/*
 * Creates the keypair of the secret key `term`. Returns 1 on success.
 * Otherwise stores badarg (not a valid secret key) or an error result in
 * *result, leaves no secret in *keypair, and returns 0.
 */
int
get_keypair(ErlNifEnv *env, ERL_NIF_TERM term, secp256k1_keypair *keypair, ERL_NIF_TERM *result);

/*
 * libsecp256k1 illegal-argument and internal-error callbacks record events in
 * thread-local flags instead of printing. Clear before a libsecp256k1 call
 * sequence and inspect afterwards on the same thread.
 */
void callback_flags_clear(void);
int callback_illegal_fired(void);
int callback_internal_fired(void);

static inline secp256k1_nif_state *
nif_state(ErlNifEnv *env)
{
  return enif_priv_data(env);
}

static inline secp256k1_context *
nif_ctx(ErlNifEnv *env)
{
  return nif_state(env)->ctx;
}

#endif
