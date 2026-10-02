#include "musig.h"
#include "nifs.h"

#include <stdint.h>
#include <string.h>

static void
destruct_keyagg_cache(ErlNifEnv *env, void *obj)
{
  (void)env;
  secure_erase(obj, sizeof(keyagg_cache_wrapper));
}

static void
destruct_session(ErlNifEnv *env, void *obj)
{
  (void)env;
  secure_erase(obj, sizeof(session_wrapper));
}

static void
destruct_secnonce(ErlNifEnv *env, void *obj)
{
  secnonce_wrapper *wrapper = obj;

  (void)env;

  if (wrapper->mutex) {
    enif_mutex_destroy(wrapper->mutex);
    wrapper->mutex = NULL;
  }

  secure_erase(obj, sizeof(secnonce_wrapper));
}

static ErlNifResourceType *
open_resource_type(ErlNifEnv *env, const char *name, ErlNifResourceDtor *destructor)
{
  return enif_open_resource_type(
    env,
    NULL,
    name,
    destructor,
    ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
    NULL
  );
}

int
musig_open_resource_types(ErlNifEnv *env, secp256k1_nif_state *state)
{
  state->keyagg_cache_rt = open_resource_type(env, "keyagg_cache_resource", destruct_keyagg_cache);
  state->session_rt = open_resource_type(env, "session_resource", destruct_session);
  state->secnonce_rt = open_resource_type(env, "secnonce_resource", destruct_secnonce);

  return state->keyagg_cache_rt && state->session_rt && state->secnonce_rt;
}

int
make_keyagg_cache_resource(
  ErlNifEnv *env,
  const secp256k1_musig_keyagg_cache *cache,
  ERL_NIF_TERM *term
)
{
  keyagg_cache_wrapper *wrapper =
    enif_alloc_resource(nif_state(env)->keyagg_cache_rt, sizeof(keyagg_cache_wrapper));

  if (!wrapper) {
    return 0;
  }

  memcpy(&wrapper->cache, cache, sizeof(wrapper->cache));
  *term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);
  return 1;
}

int
make_session_resource(
  ErlNifEnv *env,
  const secp256k1_musig_session *session,
  ERL_NIF_TERM *term
)
{
  session_wrapper *wrapper =
    enif_alloc_resource(nif_state(env)->session_rt, sizeof(session_wrapper));

  if (!wrapper) {
    return 0;
  }

  memcpy(&wrapper->session, session, sizeof(wrapper->session));
  *term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);
  return 1;
}

int
make_secnonce_resource(
  ErlNifEnv *env,
  const secp256k1_musig_secnonce *nonce,
  const secp256k1_pubkey *pubkey,
  ERL_NIF_TERM *term
)
{
  secnonce_wrapper *wrapper =
    enif_alloc_resource(nif_state(env)->secnonce_rt, sizeof(secnonce_wrapper));

  if (!wrapper) {
    return 0;
  }

  wrapper->used = 0;
  wrapper->mutex = enif_mutex_create("secp256k1_musig_secnonce");
  if (!wrapper->mutex) {
    enif_release_resource(wrapper);
    return 0;
  }

  memcpy(&wrapper->nonce, nonce, sizeof(wrapper->nonce));
  memcpy(&wrapper->pubkey, pubkey, sizeof(wrapper->pubkey));
  *term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);
  return 1;
}

int
get_keyagg_cache(ErlNifEnv *env, ERL_NIF_TERM term, keyagg_cache_wrapper **wrapper)
{
  void *obj;

  if (!enif_get_resource(env, term, nif_state(env)->keyagg_cache_rt, &obj)) {
    return 0;
  }
  *wrapper = obj;
  return 1;
}

int
get_session(ErlNifEnv *env, ERL_NIF_TERM term, session_wrapper **wrapper)
{
  void *obj;

  if (!enif_get_resource(env, term, nif_state(env)->session_rt, &obj)) {
    return 0;
  }
  *wrapper = obj;
  return 1;
}

int
get_secnonce(ErlNifEnv *env, ERL_NIF_TERM term, secnonce_wrapper **wrapper)
{
  void *obj;

  if (!enif_get_resource(env, term, nif_state(env)->secnonce_rt, &obj)) {
    return 0;
  }
  *wrapper = obj;
  return 1;
}

void *
musig_alloc_array(unsigned int count, size_t size)
{
  if (count > SIZE_MAX / size) {
    return NULL;
  }
  return enif_alloc((size_t)count * size);
}
