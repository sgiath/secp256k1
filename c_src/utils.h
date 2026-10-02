#ifndef SECP256K1_NIF_UTILS_H
#define SECP256K1_NIF_UTILS_H

#include <stddef.h>

#include <erl_nif.h>
#include <secp256k1.h>

typedef struct {
  secp256k1_context *ctx;
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
