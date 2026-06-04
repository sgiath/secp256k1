#include "utils.h"

#include <secp256k1_musig.h>

#define MUSIG_PUBNONCE_SERIALIZED_SIZE 66
#define MUSIG_AGGNONCE_SERIALIZED_SIZE 66
#define MUSIG_PARTIAL_SIG_SERIALIZED_SIZE 32

// Resource types for MuSig state that has no upstream wire format.
static ErlNifResourceType *keyagg_cache_resource_type;
static ErlNifResourceType *session_resource_type;
static ErlNifResourceType *secnonce_resource_type;

typedef struct {
  secp256k1_musig_keyagg_cache cache;
} keyagg_cache_wrapper;

typedef struct {
  secp256k1_musig_session session;
} session_wrapper;

typedef struct {
  secp256k1_musig_secnonce nonce;
  int used;
} secnonce_wrapper;

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
  (void)env;
  secure_erase(obj, sizeof(secnonce_wrapper));
}

static int
make_keyagg_cache_resource(
  ErlNifEnv *env,
  const secp256k1_musig_keyagg_cache *cache,
  ERL_NIF_TERM *term
)
{
  keyagg_cache_wrapper *wrapper =
    enif_alloc_resource(keyagg_cache_resource_type, sizeof(keyagg_cache_wrapper));

  if (!wrapper) {
    return 0;
  }

  memcpy(&wrapper->cache, cache, sizeof(wrapper->cache));
  *term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);
  return 1;
}

static int
make_session_resource(
  ErlNifEnv *env,
  const secp256k1_musig_session *session,
  ERL_NIF_TERM *term
)
{
  session_wrapper *wrapper =
    enif_alloc_resource(session_resource_type, sizeof(session_wrapper));

  if (!wrapper) {
    return 0;
  }

  memcpy(&wrapper->session, session, sizeof(wrapper->session));
  *term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);
  return 1;
}

static int
is_nil(ErlNifEnv *env, ERL_NIF_TERM term)
{
  return enif_is_identical(term, enif_make_atom(env, "nil"));
}

static int
open_musig_resource_types(ErlNifEnv *env)
{
  int flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;

  keyagg_cache_resource_type = enif_open_resource_type(
    env,
    NULL,
    "keyagg_cache_resource",
    destruct_keyagg_cache,
    flags,
    NULL
  );

  session_resource_type = enif_open_resource_type(
    env,
    NULL,
    "session_resource",
    destruct_session,
    flags,
    NULL
  );

  secnonce_resource_type = enif_open_resource_type(
    env,
    NULL,
    "secnonce_resource",
    destruct_secnonce,
    flags,
    NULL
  );

  return keyagg_cache_resource_type && session_resource_type && secnonce_resource_type;
}

static void
destroy_context_on_load_failure(void)
{
  if (ctx) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
  }
}

static int
musig_load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info)
{
  if (load(env, priv, load_info) != 0) {
    return -1;
  }

  if (!open_musig_resource_types(env)) {
    destroy_context_on_load_failure();
    return -1;
  }

  return 0;
}

static int
musig_upgrade(ErlNifEnv *env, void **priv, void **old_priv, ERL_NIF_TERM load_info)
{
  if (upgrade(env, priv, old_priv, load_info) != 0) {
    return -1;
  }

  if (!open_musig_resource_types(env)) {
    destroy_context_on_load_failure();
    return -1;
  }

  return 0;
}

static ERL_NIF_TERM
pubkey_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM head, tail, list = argv[0];
  unsigned int n_pubkeys;
  secp256k1_pubkey *pubkeys;
  const secp256k1_pubkey **pubkeys_ptrs;
  secp256k1_xonly_pubkey agg_pk;
  secp256k1_musig_keyagg_cache cache;
  unsigned char serialized_agg_pk[32];
  ErlNifBinary bin_agg_pk;
  ERL_NIF_TERM cache_term;
  unsigned int i;

  if (!enif_get_list_length(env, list, &n_pubkeys) || n_pubkeys == 0) {
    return enif_make_badarg(env);
  }

  // Allocate memory for pubkeys and pointers
  pubkeys = enif_alloc(n_pubkeys * sizeof(secp256k1_pubkey));
  pubkeys_ptrs = enif_alloc(n_pubkeys * sizeof(secp256k1_pubkey *));
  if (!pubkeys || !pubkeys_ptrs) {
    if (pubkeys) enif_free(pubkeys);
    if (pubkeys_ptrs) enif_free(pubkeys_ptrs);
    return error_result(env, "enif_alloc failed");
  }

  // Parse pubkeys from list
  for (i = 0; i < n_pubkeys; i++) {
    ErlNifBinary bin;
    if (!enif_get_list_cell(env, list, &head, &tail)) {
      goto bad_arg;
    }
    if (!enif_inspect_binary(env, head, &bin) ||
        !secp256k1_ec_pubkey_parse(ctx, &pubkeys[i], bin.data, bin.size)) {
      goto bad_arg;
    }
    pubkeys_ptrs[i] = &pubkeys[i];
    list = tail;
  }

  if (!secp256k1_musig_pubkey_agg(ctx, &agg_pk, &cache, pubkeys_ptrs, n_pubkeys)) {
    enif_free(pubkeys);
    enif_free(pubkeys_ptrs);
    return error_result(env, "secp256k1_musig_pubkey_agg failed");
  }

  enif_free(pubkeys);
  enif_free(pubkeys_ptrs);

  if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_agg_pk, &agg_pk)) {
    return error_result(env, "secp256k1_xonly_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(sizeof(serialized_agg_pk), &bin_agg_pk)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_agg_pk.data, serialized_agg_pk, sizeof(serialized_agg_pk));

  if (!make_keyagg_cache_resource(env, &cache, &cache_term)) {
    enif_release_binary(&bin_agg_pk);
    return error_result(env, "enif_alloc_resource failed");
  }

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    enif_make_binary(env, &bin_agg_pk),
    cache_term
  );

bad_arg:
  enif_free(pubkeys);
  enif_free(pubkeys_ptrs);
  return enif_make_badarg(env);
}

static ERL_NIF_TERM
pubkey_get(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  keyagg_cache_wrapper *cache;
  secp256k1_pubkey agg_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_pk;

  if (!enif_get_resource(env, argv[0], keyagg_cache_resource_type, (void **)&cache)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_musig_pubkey_get(ctx, &agg_pk, &cache->cache)) {
    return error_result(env, "secp256k1_musig_pubkey_get failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &len, &agg_pk, SECP256K1_EC_COMPRESSED)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(len, &bin_pk)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_pk.data, serialized_pk, len);

  return enif_make_binary(env, &bin_pk);
}

static ERL_NIF_TERM
pubkey_ec_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_tweak;
  keyagg_cache_wrapper *cache_wrapper;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey output_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_pk;
  ERL_NIF_TERM cache_term;

  if (!enif_get_resource(env, argv[0], keyagg_cache_resource_type, (void **)&cache_wrapper) ||
      !enif_inspect_binary(env, argv[1], &bin_tweak) || bin_tweak.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, &cache_wrapper->cache, sizeof(cache));

  if (!secp256k1_musig_pubkey_ec_tweak_add(ctx, &output_pk, &cache, bin_tweak.data)) {
    return error_result(env, "secp256k1_musig_pubkey_ec_tweak_add failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &len, &output_pk, SECP256K1_EC_COMPRESSED)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(len, &bin_pk)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_pk.data, serialized_pk, len);

  if (!make_keyagg_cache_resource(env, &cache, &cache_term)) {
    enif_release_binary(&bin_pk);
    return error_result(env, "enif_alloc_resource failed");
  }

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    cache_term,
    enif_make_binary(env, &bin_pk)
  );
}

static ERL_NIF_TERM
pubkey_xonly_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_tweak;
  keyagg_cache_wrapper *cache_wrapper;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey output_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_pk;
  ERL_NIF_TERM cache_term;

  if (!enif_get_resource(env, argv[0], keyagg_cache_resource_type, (void **)&cache_wrapper) ||
      !enif_inspect_binary(env, argv[1], &bin_tweak) || bin_tweak.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, &cache_wrapper->cache, sizeof(cache));

  if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_pk, &cache, bin_tweak.data)) {
    return error_result(env, "secp256k1_musig_pubkey_xonly_tweak_add failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &len, &output_pk, SECP256K1_EC_COMPRESSED)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(len, &bin_pk)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_pk.data, serialized_pk, len);

  if (!make_keyagg_cache_resource(env, &cache, &cache_term)) {
    enif_release_binary(&bin_pk);
    return error_result(env, "enif_alloc_resource failed");
  }

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    cache_term,
    enif_make_binary(env, &bin_pk)
  );
}

static ERL_NIF_TERM
nonce_gen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_seckey, bin_pubkey, bin_msg, bin_extra;
  secp256k1_musig_secnonce secnonce;
  secp256k1_musig_pubnonce pubnonce;
  unsigned char session_secrand[32];
  ErlNifBinary bin_pubnonce;
  secnonce_wrapper *wrapper;
  ERL_NIF_TERM resource_term;

  const unsigned char *seckey = NULL;
  secp256k1_pubkey pubkey_struct;
  const unsigned char *msg = NULL;
  keyagg_cache_wrapper *cache_wrapper;
  const secp256k1_musig_keyagg_cache *cache = NULL;
  const unsigned char *extra = NULL;

  if (!is_nil(env, argv[0])) {
    if (!enif_inspect_binary(env, argv[0], &bin_seckey)) {
      return enif_make_badarg(env);
    }
    if (bin_seckey.size != 32) return enif_make_badarg(env);
    seckey = bin_seckey.data;
  }

  if (is_nil(env, argv[1]) ||
      !enif_inspect_binary(env, argv[1], &bin_pubkey) ||
      !secp256k1_ec_pubkey_parse(ctx, &pubkey_struct, bin_pubkey.data, bin_pubkey.size)) {
    return enif_make_badarg(env);
  }

  if (!is_nil(env, argv[2])) {
    if (!enif_inspect_binary(env, argv[2], &bin_msg)) {
      return enif_make_badarg(env);
    }
    if (bin_msg.size != 32) return enif_make_badarg(env);
    msg = bin_msg.data;
  }

  if (!is_nil(env, argv[3])) {
    if (!enif_get_resource(env, argv[3], keyagg_cache_resource_type, (void **)&cache_wrapper)) {
      return enif_make_badarg(env);
    }
    cache = &cache_wrapper->cache;
  }

  if (!is_nil(env, argv[4])) {
    if (!enif_inspect_binary(env, argv[4], &bin_extra)) {
      return enif_make_badarg(env);
    }
    if (bin_extra.size != 32) return enif_make_badarg(env);
    extra = bin_extra.data;
  }

  if (!fill_random(session_secrand, sizeof(session_secrand))) {
    secure_erase(session_secrand, sizeof(session_secrand));
    return error_result(env, "RNG failed");
  }

  if (!secp256k1_musig_nonce_gen(
      ctx,
      &secnonce,
      &pubnonce,
      session_secrand,
      seckey,
      &pubkey_struct,
      msg,
      cache,
      extra
    )) {
    secure_erase(session_secrand, sizeof(session_secrand));
    return error_result(env, "secp256k1_musig_nonce_gen failed");
  }
  secure_erase(session_secrand, sizeof(session_secrand));

  if (!enif_alloc_binary(MUSIG_PUBNONCE_SERIALIZED_SIZE, &bin_pubnonce)) {
    secure_erase(&secnonce, sizeof(secnonce));
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }

  if (!secp256k1_musig_pubnonce_serialize(ctx, bin_pubnonce.data, &pubnonce)) {
    enif_release_binary(&bin_pubnonce);
    secure_erase(&secnonce, sizeof(secnonce));
    return error_result(env, "secp256k1_musig_pubnonce_serialize failed");
  }

  wrapper = enif_alloc_resource(secnonce_resource_type, sizeof(secnonce_wrapper));
  if (!wrapper) {
    enif_release_binary(&bin_pubnonce);
    secure_erase(&secnonce, sizeof(secnonce));
    return error_result(env, "enif_alloc_resource failed");
  }
  memcpy(&wrapper->nonce, &secnonce, sizeof(secnonce));
  wrapper->used = 0;
  secure_erase(&secnonce, sizeof(secnonce));

  resource_term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    resource_term,
    enif_make_binary(env, &bin_pubnonce)
  );
}

static ERL_NIF_TERM
nonce_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM head, tail, list = argv[0];
  unsigned int n_nonces;
  secp256k1_musig_pubnonce *nonces;
  const secp256k1_musig_pubnonce **nonces_ptrs;
  secp256k1_musig_aggnonce aggnonce;
  ErlNifBinary bin_aggnonce;
  unsigned int i;

  if (!enif_get_list_length(env, list, &n_nonces) || n_nonces == 0) {
    return enif_make_badarg(env);
  }

  nonces = enif_alloc(n_nonces * sizeof(secp256k1_musig_pubnonce));
  nonces_ptrs = enif_alloc(n_nonces * sizeof(secp256k1_musig_pubnonce *));
  if (!nonces || !nonces_ptrs) {
    if (nonces) enif_free(nonces);
    if (nonces_ptrs) enif_free(nonces_ptrs);
    return error_result(env, "enif_alloc failed");
  }

  for (i = 0; i < n_nonces; i++) {
    ErlNifBinary bin;
    if (!enif_get_list_cell(env, list, &head, &tail)) goto bad_arg;
    if (!enif_inspect_binary(env, head, &bin) ||
        bin.size != MUSIG_PUBNONCE_SERIALIZED_SIZE ||
        !secp256k1_musig_pubnonce_parse(ctx, &nonces[i], bin.data)) {
      goto bad_arg;
    }
    nonces_ptrs[i] = &nonces[i];
    list = tail;
  }

  if (!secp256k1_musig_nonce_agg(ctx, &aggnonce, nonces_ptrs, n_nonces)) {
    enif_free(nonces);
    enif_free(nonces_ptrs);
    return error_result(env, "secp256k1_musig_nonce_agg failed");
  }

  enif_free(nonces);
  enif_free(nonces_ptrs);

  if (!enif_alloc_binary(MUSIG_AGGNONCE_SERIALIZED_SIZE, &bin_aggnonce)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  if (!secp256k1_musig_aggnonce_serialize(ctx, bin_aggnonce.data, &aggnonce)) {
    enif_release_binary(&bin_aggnonce);
    return error_result(env, "secp256k1_musig_aggnonce_serialize failed");
  }

  return enif_make_binary(env, &bin_aggnonce);

bad_arg:
  enif_free(nonces);
  enif_free(nonces_ptrs);
  return enif_make_badarg(env);
}

static ERL_NIF_TERM
nonce_process(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_aggnonce, bin_msg;
  secp256k1_musig_aggnonce aggnonce;
  keyagg_cache_wrapper *cache;
  secp256k1_musig_session session;
  ERL_NIF_TERM session_term;

  if (!enif_inspect_binary(env, argv[0], &bin_aggnonce) ||
      bin_aggnonce.size != MUSIG_AGGNONCE_SERIALIZED_SIZE ||
      !secp256k1_musig_aggnonce_parse(ctx, &aggnonce, bin_aggnonce.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[1], &bin_msg) || bin_msg.size != 32) {
    return enif_make_badarg(env);
  }
  if (!enif_get_resource(env, argv[2], keyagg_cache_resource_type, (void **)&cache)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce, bin_msg.data, &cache->cache)) {
    return error_result(env, "secp256k1_musig_nonce_process failed");
  }

  if (!make_session_resource(env, &session, &session_term)) {
    return error_result(env, "enif_alloc_resource failed");
  }

  return session_term;
}

static ERL_NIF_TERM
partial_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  secnonce_wrapper *wrapper;
  keyagg_cache_wrapper *cache;
  session_wrapper *session;
  ErlNifBinary bin_seckey;
  secp256k1_keypair keypair;
  secp256k1_musig_partial_sig partial_sig;
  ErlNifBinary bin_partial_sig;

  if (!enif_get_resource(env, argv[0], secnonce_resource_type, (void **)&wrapper)) {
    return enif_make_badarg(env);
  }
  if (wrapper->used) {
    return error_result(env, "nonce already used");
  }

  if (!enif_get_resource(env, argv[2], keyagg_cache_resource_type, (void **)&cache) ||
      !enif_get_resource(env, argv[3], session_resource_type, (void **)&session)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &bin_seckey) ||
      bin_seckey.size != 32 ||
      !secp256k1_keypair_create(ctx, &keypair, bin_seckey.data)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_musig_partial_sign(
      ctx,
      &partial_sig,
      &wrapper->nonce,
      &keypair,
      &cache->cache,
      &session->session
    )) {
    secure_erase(&keypair, sizeof(keypair));
    return error_result(env, "secp256k1_musig_partial_sign failed");
  }
  wrapper->used = 1;
  secure_erase(&keypair, sizeof(keypair));

  if (!enif_alloc_binary(MUSIG_PARTIAL_SIG_SERIALIZED_SIZE, &bin_partial_sig)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  if (!secp256k1_musig_partial_sig_serialize(ctx, bin_partial_sig.data, &partial_sig)) {
     enif_release_binary(&bin_partial_sig);
     return error_result(env, "secp256k1_musig_partial_sig_serialize failed");
  }

  return enif_make_binary(env, &bin_partial_sig);
}

static ERL_NIF_TERM
partial_sig_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_psig, bin_pubnonce, bin_pubkey;
  secp256k1_musig_partial_sig partial_sig;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_pubkey pubkey;
  keyagg_cache_wrapper *cache;
  session_wrapper *session;

  if (!enif_inspect_binary(env, argv[0], &bin_psig) ||
      bin_psig.size != MUSIG_PARTIAL_SIG_SERIALIZED_SIZE ||
      !secp256k1_musig_partial_sig_parse(ctx, &partial_sig, bin_psig.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[1], &bin_pubnonce) ||
      bin_pubnonce.size != MUSIG_PUBNONCE_SERIALIZED_SIZE ||
      !secp256k1_musig_pubnonce_parse(ctx, &pubnonce, bin_pubnonce.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[2], &bin_pubkey) ||
      !secp256k1_ec_pubkey_parse(ctx, &pubkey, bin_pubkey.data, bin_pubkey.size)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_resource(env, argv[3], keyagg_cache_resource_type, (void **)&cache) ||
      !enif_get_resource(env, argv[4], session_resource_type, (void **)&session)) {
    return enif_make_badarg(env);
  }

  if (secp256k1_musig_partial_sig_verify(
      ctx,
      &partial_sig,
      &pubnonce,
      &pubkey,
      &cache->cache,
      &session->session
    )) {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}

static ERL_NIF_TERM
partial_sig_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM head, tail, list = argv[1];
  session_wrapper *session;
  unsigned int n_sigs;
  secp256k1_musig_partial_sig *sigs;
  const secp256k1_musig_partial_sig **sigs_ptrs;
  unsigned char sig64[64];
  ErlNifBinary bin_sig64;
  unsigned int i;

  if (!enif_get_resource(env, argv[0], session_resource_type, (void **)&session)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_list_length(env, list, &n_sigs) || n_sigs == 0) {
    return enif_make_badarg(env);
  }

  sigs = enif_alloc(n_sigs * sizeof(secp256k1_musig_partial_sig));
  sigs_ptrs = enif_alloc(n_sigs * sizeof(secp256k1_musig_partial_sig *));
  if (!sigs || !sigs_ptrs) {
    if (sigs) enif_free(sigs);
    if (sigs_ptrs) enif_free(sigs_ptrs);
    return error_result(env, "enif_alloc failed");
  }

  for (i = 0; i < n_sigs; i++) {
    ErlNifBinary bin;
    if (!enif_get_list_cell(env, list, &head, &tail)) goto bad_arg;
    if (!enif_inspect_binary(env, head, &bin) ||
        bin.size != MUSIG_PARTIAL_SIG_SERIALIZED_SIZE ||
        !secp256k1_musig_partial_sig_parse(ctx, &sigs[i], bin.data)) {
      goto bad_arg;
    }
    sigs_ptrs[i] = &sigs[i];
    list = tail;
  }

  if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &session->session, sigs_ptrs, n_sigs)) {
    enif_free(sigs);
    enif_free(sigs_ptrs);
    return error_result(env, "secp256k1_musig_partial_sig_agg failed");
  }

  enif_free(sigs);
  enif_free(sigs_ptrs);

  if (!enif_alloc_binary(sizeof(sig64), &bin_sig64)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_sig64.data, sig64, sizeof(sig64));

  return enif_make_binary(env, &bin_sig64);

bad_arg:
  enif_free(sigs);
  enif_free(sigs_ptrs);
  return enif_make_badarg(env);
}

static ErlNifFunc nif_funcs[] = {
  {"pubkey_agg", 1, pubkey_agg},
  {"pubkey_get", 1, pubkey_get},
  {"pubkey_ec_tweak_add", 2, pubkey_ec_tweak_add},
  {"pubkey_xonly_tweak_add", 2, pubkey_xonly_tweak_add},
  {"nonce_gen", 5, nonce_gen},
  {"nonce_agg", 1, nonce_agg},
  {"nonce_process", 3, nonce_process},
  {"partial_sign", 4, partial_sign},
  {"partial_sig_verify", 5, partial_sig_verify},
  {"partial_sig_agg", 2, partial_sig_agg}
};

ERL_NIF_INIT(Elixir.Secp256k1.MuSig, nif_funcs, &musig_load, NULL, &musig_upgrade, &unload)
