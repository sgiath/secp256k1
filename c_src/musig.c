#include "utils.h"

#include <secp256k1_musig.h>

// Resource type for secret nonces to prevent copying and allow secure erasure
static ErlNifResourceType *secnonce_resource_type;

typedef struct {
  secp256k1_musig_secnonce nonce;
  int used;
} secnonce_wrapper;

static void
destruct_secnonce(ErlNifEnv *env, void *obj)
{
  secure_erase(obj, sizeof(secnonce_wrapper));
}

static int
musig_load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info)
{
  // Initialize the library context via utils.h's load
  if (load(env, priv, load_info) != 0) {
    return -1;
  }

  secnonce_resource_type = enif_open_resource_type(
    env,
    NULL,
    "secnonce_resource",
    destruct_secnonce,
    ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
    NULL
  );

  if (!secnonce_resource_type) {
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

  secnonce_resource_type = enif_open_resource_type(
    env,
    NULL,
    "secnonce_resource",
    destruct_secnonce,
    ERL_NIF_RT_TAKEOVER,
    NULL
  );

  if (!secnonce_resource_type) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
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
  ErlNifBinary bin_cache, bin_agg_pk;
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

  if (!enif_alloc_binary(sizeof(cache), &bin_cache)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_cache.data, &cache, sizeof(cache));

  if (!enif_alloc_binary(sizeof(serialized_agg_pk), &bin_agg_pk)) {
    enif_release_binary(&bin_cache);
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_agg_pk.data, serialized_agg_pk, sizeof(serialized_agg_pk));

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    enif_make_binary(env, &bin_agg_pk),
    enif_make_binary(env, &bin_cache)
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

  ErlNifBinary bin_cache;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey agg_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_pk;

  if (!enif_inspect_binary(env, argv[0], &bin_cache) || bin_cache.size != sizeof(cache)) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));

  if (!secp256k1_musig_pubkey_get(ctx, &agg_pk, &cache)) {
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

  ErlNifBinary bin_cache, bin_tweak;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey output_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_new_cache, bin_pk;

  if (!enif_inspect_binary(env, argv[0], &bin_cache) || bin_cache.size != sizeof(cache) ||
      !enif_inspect_binary(env, argv[1], &bin_tweak) || bin_tweak.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));

  if (!secp256k1_musig_pubkey_ec_tweak_add(ctx, &output_pk, &cache, bin_tweak.data)) {
    return error_result(env, "secp256k1_musig_pubkey_ec_tweak_add failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &len, &output_pk, SECP256K1_EC_COMPRESSED)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(sizeof(cache), &bin_new_cache)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_new_cache.data, &cache, sizeof(cache));

  if (!enif_alloc_binary(len, &bin_pk)) {
    enif_release_binary(&bin_new_cache);
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_pk.data, serialized_pk, len);

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    enif_make_binary(env, &bin_new_cache),
    enif_make_binary(env, &bin_pk)
  );
}

static ERL_NIF_TERM
pubkey_xonly_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_cache, bin_tweak;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_pubkey output_pk;
  unsigned char serialized_pk[33];
  size_t len = sizeof(serialized_pk);
  ErlNifBinary bin_new_cache, bin_pk;

  if (!enif_inspect_binary(env, argv[0], &bin_cache) || bin_cache.size != sizeof(cache) ||
      !enif_inspect_binary(env, argv[1], &bin_tweak) || bin_tweak.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));

  if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_pk, &cache, bin_tweak.data)) {
    return error_result(env, "secp256k1_musig_pubkey_xonly_tweak_add failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &len, &output_pk, SECP256K1_EC_COMPRESSED)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!enif_alloc_binary(sizeof(cache), &bin_new_cache)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_new_cache.data, &cache, sizeof(cache));

  if (!enif_alloc_binary(len, &bin_pk)) {
    enif_release_binary(&bin_new_cache);
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_pk.data, serialized_pk, len);

  return enif_make_tuple3(env,
    enif_make_atom(env, "ok"),
    enif_make_binary(env, &bin_new_cache),
    enif_make_binary(env, &bin_pk)
  );
}

static ERL_NIF_TERM
nonce_gen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary bin_seckey, bin_pubkey, bin_msg, bin_cache, bin_extra;
  secp256k1_musig_secnonce secnonce;
  secp256k1_musig_pubnonce pubnonce;
  unsigned char session_secrand[32];
  ErlNifBinary bin_pubnonce;
  secnonce_wrapper *wrapper;
  ERL_NIF_TERM resource_term;

  const unsigned char *seckey = NULL;
  secp256k1_pubkey pubkey_struct;
  const secp256k1_pubkey *pubkey = NULL;
  const unsigned char *msg = NULL;
  secp256k1_musig_keyagg_cache cache_struct;
  const secp256k1_musig_keyagg_cache *cache = NULL;
  const unsigned char *extra = NULL;

  // Optional arguments
  if (enif_inspect_binary(env, argv[0], &bin_seckey)) {
    if (bin_seckey.size != 32) return enif_make_badarg(env);
    seckey = bin_seckey.data;
  }
  if (enif_inspect_binary(env, argv[1], &bin_pubkey)) {
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_struct, bin_pubkey.data, bin_pubkey.size)) {
        return enif_make_badarg(env);
    }
    pubkey = &pubkey_struct;
  }
  if (enif_inspect_binary(env, argv[2], &bin_msg)) {
    if (bin_msg.size != 32) return enif_make_badarg(env);
    msg = bin_msg.data;
  }
  if (enif_inspect_binary(env, argv[3], &bin_cache)) {
    if (bin_cache.size != sizeof(cache_struct)) return enif_make_badarg(env);
    memcpy(&cache_struct, bin_cache.data, sizeof(cache_struct));
    cache = &cache_struct;
  }
  if (enif_inspect_binary(env, argv[4], &bin_extra)) {
    if (bin_extra.size != 32) return enif_make_badarg(env);
    extra = bin_extra.data;
  }

  // Generate random session ID
  if (!fill_random(session_secrand, sizeof(session_secrand))) {
    return error_result(env, "RNG failed");
  }

  if (!secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_secrand, seckey, pubkey, msg, cache, extra)) {
    secure_erase(session_secrand, sizeof(session_secrand));
    return error_result(env, "secp256k1_musig_nonce_gen failed");
  }
  secure_erase(session_secrand, sizeof(session_secrand));

  // Allocate resource
  wrapper = enif_alloc_resource(secnonce_resource_type, sizeof(secnonce_wrapper));
  if (!wrapper) {
    secure_erase(&secnonce, sizeof(secnonce));
    return error_result(env, "enif_alloc_resource failed");
  }
  memcpy(&wrapper->nonce, &secnonce, sizeof(secnonce));
  wrapper->used = 0;
  secure_erase(&secnonce, sizeof(secnonce)); // Clear stack copy

  resource_term = enif_make_resource(env, wrapper);
  enif_release_resource(wrapper);

  if (!enif_alloc_binary(sizeof(pubnonce), &bin_pubnonce)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  if (!secp256k1_musig_pubnonce_serialize(ctx, bin_pubnonce.data, &pubnonce)) {
     enif_release_binary(&bin_pubnonce);
     return error_result(env, "secp256k1_musig_pubnonce_serialize failed");
  }

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

  if (!enif_alloc_binary(sizeof(aggnonce), &bin_aggnonce)) {
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

  ErlNifBinary bin_aggnonce, bin_msg, bin_cache;
  secp256k1_musig_aggnonce aggnonce;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_musig_session session;
  ErlNifBinary bin_session;

  if (!enif_inspect_binary(env, argv[0], &bin_aggnonce) ||
      !secp256k1_musig_aggnonce_parse(ctx, &aggnonce, bin_aggnonce.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[1], &bin_msg) || bin_msg.size != 32) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[2], &bin_cache) || bin_cache.size != sizeof(cache)) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));

  if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce, bin_msg.data, &cache)) {
    return error_result(env, "secp256k1_musig_nonce_process failed");
  }

  if (!enif_alloc_binary(sizeof(session), &bin_session)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin_session.data, &session, sizeof(session));

  return enif_make_binary(env, &bin_session);
}

static ERL_NIF_TERM
partial_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  secnonce_wrapper *wrapper;
  ErlNifBinary bin_seckey, bin_cache, bin_session;
  secp256k1_keypair keypair;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_musig_session session;
  secp256k1_musig_partial_sig partial_sig;
  ErlNifBinary bin_partial_sig;

  if (!enif_get_resource(env, argv[0], secnonce_resource_type, (void **)&wrapper)) {
    return enif_make_badarg(env);
  }
  if (wrapper->used) {
    return error_result(env, "nonce already used");
  }

  if (!enif_inspect_binary(env, argv[1], &bin_seckey) ||
      bin_seckey.size != 32 ||
      !secp256k1_keypair_create(ctx, &keypair, bin_seckey.data)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[2], &bin_cache) || bin_cache.size != sizeof(cache)) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));

  if (!enif_inspect_binary(env, argv[3], &bin_session) || bin_session.size != sizeof(session)) {
    return enif_make_badarg(env);
  }
  memcpy(&session, bin_session.data, sizeof(session));

  if (!secp256k1_musig_partial_sign(ctx, &partial_sig, &wrapper->nonce, &keypair, &cache, &session)) {
    secure_erase(&keypair, sizeof(keypair));
    return error_result(env, "secp256k1_musig_partial_sign failed");
  }
  wrapper->used = 1;
  // The library zeroes the nonce in secp256k1_musig_partial_sign, but we explicitly double-check destruction in destructor.
  // We also clear keypair
  secure_erase(&keypair, sizeof(keypair));

  if (!enif_alloc_binary(sizeof(partial_sig), &bin_partial_sig)) {
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

  ErlNifBinary bin_psig, bin_pubnonce, bin_pubkey, bin_cache, bin_session;
  secp256k1_musig_partial_sig partial_sig;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_pubkey pubkey;
  secp256k1_musig_keyagg_cache cache;
  secp256k1_musig_session session;

  if (!enif_inspect_binary(env, argv[0], &bin_psig) ||
      !secp256k1_musig_partial_sig_parse(ctx, &partial_sig, bin_psig.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[1], &bin_pubnonce) ||
      !secp256k1_musig_pubnonce_parse(ctx, &pubnonce, bin_pubnonce.data)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[2], &bin_pubkey) ||
      !secp256k1_ec_pubkey_parse(ctx, &pubkey, bin_pubkey.data, bin_pubkey.size)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[3], &bin_cache) || bin_cache.size != sizeof(cache)) {
    return enif_make_badarg(env);
  }
  memcpy(&cache, bin_cache.data, sizeof(cache));
  if (!enif_inspect_binary(env, argv[4], &bin_session) || bin_session.size != sizeof(session)) {
    return enif_make_badarg(env);
  }
  memcpy(&session, bin_session.data, sizeof(session));

  if (secp256k1_musig_partial_sig_verify(ctx, &partial_sig, &pubnonce, &pubkey, &cache, &session)) {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}

static ERL_NIF_TERM
partial_sig_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM head, tail, list = argv[1];
  ErlNifBinary bin_session;
  secp256k1_musig_session session;
  unsigned int n_sigs;
  secp256k1_musig_partial_sig *sigs;
  const secp256k1_musig_partial_sig **sigs_ptrs;
  unsigned char sig64[64];
  ErlNifBinary bin_sig64;
  unsigned int i;

  if (!enif_inspect_binary(env, argv[0], &bin_session) || bin_session.size != sizeof(session)) {
    return enif_make_badarg(env);
  }
  memcpy(&session, bin_session.data, sizeof(session));

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
        !secp256k1_musig_partial_sig_parse(ctx, &sigs[i], bin.data)) {
      goto bad_arg;
    }
    sigs_ptrs[i] = &sigs[i];
    list = tail;
  }

  if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &session, sigs_ptrs, n_sigs)) {
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
