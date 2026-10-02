#include "musig.h"
#include "nifs.h"

#include <string.h>

static int
parse_pubkeys(
  ErlNifEnv *env,
  const secp256k1_context *ctx,
  ERL_NIF_TERM list,
  unsigned int count,
  secp256k1_pubkey *pubkeys,
  const secp256k1_pubkey **pubkey_ptrs
)
{
  ERL_NIF_TERM head;
  ErlNifBinary bin;
  unsigned int i;

  for (i = 0; i < count; i++) {
    if (!enif_get_list_cell(env, list, &head, &list) ||
        !enif_inspect_binary(env, head, &bin) ||
        !secp256k1_ec_pubkey_parse(ctx, &pubkeys[i], bin.data, bin.size)) {
      return 0;
    }
    pubkey_ptrs[i] = &pubkeys[i];
  }

  return 1;
}

static ERL_NIF_TERM
pubkey_agg_result(
  ErlNifEnv *env,
  const secp256k1_xonly_pubkey *agg_pk,
  const secp256k1_musig_keyagg_cache *cache
)
{
  unsigned char serialized_agg_pk[32];
  ERL_NIF_TERM agg_pk_term;
  ERL_NIF_TERM cache_term;

  if (!secp256k1_xonly_pubkey_serialize(nif_ctx(env), serialized_agg_pk, agg_pk)) {
    return error_result(env, "secp256k1_xonly_pubkey_serialize failed");
  }

  if (!make_binary(env, serialized_agg_pk, sizeof(serialized_agg_pk), &agg_pk_term) ||
      !make_keyagg_cache_resource(env, cache, &cache_term)) {
    return allocation_failed(env);
  }

  return enif_make_tuple3(env, enif_make_atom(env, "ok"), agg_pk_term, cache_term);
}

ERL_NIF_TERM
secp256k1_nif_musig_pubkey_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  unsigned int n_pubkeys;
  secp256k1_pubkey *pubkeys;
  const secp256k1_pubkey **pubkey_ptrs;
  secp256k1_xonly_pubkey agg_pk;
  secp256k1_musig_keyagg_cache cache;
  int parsed;
  int aggregated = 0;

  (void)argc;

  if (!enif_get_list_length(env, argv[0], &n_pubkeys) || n_pubkeys == 0) {
    return enif_make_badarg(env);
  }

  pubkeys = musig_alloc_array(n_pubkeys, sizeof(*pubkeys));
  pubkey_ptrs = musig_alloc_array(n_pubkeys, sizeof(*pubkey_ptrs));
  if (!pubkeys || !pubkey_ptrs) {
    if (pubkeys) enif_free(pubkeys);
    if (pubkey_ptrs) enif_free(pubkey_ptrs);
    return allocation_failed(env);
  }

  parsed = parse_pubkeys(env, ctx, argv[0], n_pubkeys, pubkeys, pubkey_ptrs);
  if (parsed) {
    aggregated = secp256k1_musig_pubkey_agg(ctx, &agg_pk, &cache, pubkey_ptrs, n_pubkeys);
  }

  enif_free(pubkeys);
  enif_free(pubkey_ptrs);

  if (!parsed) {
    return enif_make_badarg(env);
  }
  if (!aggregated) {
    return error_result(env, "secp256k1_musig_pubkey_agg failed");
  }

  return pubkey_agg_result(env, &agg_pk, &cache);
}

/*
 * Stores the compressed 33-byte pubkey binary in *term and returns 1. On
 * failure stores the error result in *term and returns 0.
 */
static int
compressed_pubkey_term(ErlNifEnv *env, const secp256k1_pubkey *pubkey, ERL_NIF_TERM *term)
{
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);

  if (!secp256k1_ec_pubkey_serialize(nif_ctx(env), serialized_pk, &len, pubkey, SECP256K1_EC_COMPRESSED)) {
    *term = error_result(env, "secp256k1_ec_pubkey_serialize failed");
    return 0;
  }

  if (!make_binary(env, serialized_pk, len, term)) {
    *term = allocation_failed(env);
    return 0;
  }

  return 1;
}

ERL_NIF_TERM
secp256k1_nif_musig_pubkey_get(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  keyagg_cache_wrapper *cache;
  secp256k1_pubkey agg_pk;
  ERL_NIF_TERM pubkey_term;

  (void)argc;

  if (!get_keyagg_cache(env, argv[0], &cache)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_musig_pubkey_get(nif_ctx(env), &agg_pk, &cache->cache)) {
    return error_result(env, "secp256k1_musig_pubkey_get failed");
  }

  compressed_pubkey_term(env, &agg_pk, &pubkey_term);
  return pubkey_term;
}

typedef int (*musig_pubkey_tweak_add_fn)(
  const secp256k1_context *,
  secp256k1_pubkey *,
  secp256k1_musig_keyagg_cache *,
  const unsigned char *
);

static ERL_NIF_TERM
musig_pubkey_tweak_add(
  ErlNifEnv *env,
  const ERL_NIF_TERM argv[],
  musig_pubkey_tweak_add_fn tweak_add,
  const char *tweak_error
)
{
  ErlNifBinary bin_tweak;
  keyagg_cache_wrapper *cache_wrapper;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey output_pk;
  ERL_NIF_TERM cache_term;
  ERL_NIF_TERM pubkey_term;

  if (!get_keyagg_cache(env, argv[0], &cache_wrapper) ||
      !enif_inspect_binary(env, argv[1], &bin_tweak) || bin_tweak.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, &cache_wrapper->cache, sizeof(cache));

  if (!tweak_add(nif_ctx(env), &output_pk, &cache, bin_tweak.data)) {
    return error_result(env, tweak_error);
  }

  if (!compressed_pubkey_term(env, &output_pk, &pubkey_term)) {
    return pubkey_term;
  }

  if (!make_keyagg_cache_resource(env, &cache, &cache_term)) {
    return allocation_failed(env);
  }

  return enif_make_tuple3(env, enif_make_atom(env, "ok"), cache_term, pubkey_term);
}

ERL_NIF_TERM
secp256k1_nif_musig_pubkey_ec_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return musig_pubkey_tweak_add(
    env,
    argv,
    secp256k1_musig_pubkey_ec_tweak_add,
    "secp256k1_musig_pubkey_ec_tweak_add failed"
  );
}

ERL_NIF_TERM
secp256k1_nif_musig_pubkey_xonly_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return musig_pubkey_tweak_add(
    env,
    argv,
    secp256k1_musig_pubkey_xonly_tweak_add,
    "secp256k1_musig_pubkey_xonly_tweak_add failed"
  );
}
