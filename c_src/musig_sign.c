#include "musig.h"
#include "nifs.h"

#include <string.h>

#include <secp256k1_extrakeys.h>

/* Marks the nonce used under its mutex. Returns 0 when it was already used. */
static int
claim_secnonce(secnonce_wrapper *wrapper)
{
  int claimed;

  enif_mutex_lock(wrapper->mutex);
  claimed = !wrapper->used;
  wrapper->used = 1;
  enif_mutex_unlock(wrapper->mutex);

  return claimed;
}

static int
keypair_matches_secnonce(
  const secp256k1_context *ctx,
  const secp256k1_keypair *keypair,
  const secnonce_wrapper *wrapper
)
{
  secp256k1_pubkey keypair_pubkey;

  return secp256k1_keypair_pub(ctx, &keypair_pubkey, keypair) &&
         secp256k1_ec_pubkey_cmp(ctx, &keypair_pubkey, &wrapper->pubkey) == 0;
}

static ERL_NIF_TERM
partial_sig_result(ErlNifEnv *env, const secp256k1_musig_partial_sig *partial_sig)
{
  unsigned char serialized[MUSIG_PARTIAL_SIG_SIZE];
  ERL_NIF_TERM result;

  if (!secp256k1_musig_partial_sig_serialize(nif_ctx(env), serialized, partial_sig)) {
    return error_result(env, "secp256k1_musig_partial_sig_serialize failed");
  }
  if (!make_binary(env, serialized, sizeof(serialized), &result)) {
    return allocation_failed(env);
  }

  return result;
}

ERL_NIF_TERM
secp256k1_nif_musig_partial_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  secnonce_wrapper *wrapper;
  keyagg_cache_wrapper *cache;
  session_wrapper *session;
  ErlNifBinary bin_seckey;
  secp256k1_keypair keypair;
  secp256k1_musig_partial_sig partial_sig;
  ERL_NIF_TERM result;
  int claimed = 0;

  (void)argc;

  if (!get_secnonce(env, argv[0], &wrapper) || !get_keyagg_cache(env, argv[2], &cache) ||
      !get_session(env, argv[3], &session) || !enif_inspect_binary(env, argv[1], &bin_seckey) ||
      bin_seckey.size != SECKEY_SIZE) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, bin_seckey.data)) {
    result = enif_make_badarg(env);
    goto cleanup;
  }

  claimed = claim_secnonce(wrapper);
  if (!claimed) {
    result = error_result(env, "nonce already used");
    goto cleanup;
  }

  /* From here on this call owns the nonce bytes and must erase them. */
  if (!keyagg_cache_equal(&cache->cache, &session->cache)) {
    result = error_result(env, "keyagg cache does not match session");
  } else if (wrapper->has_cache && !keyagg_cache_equal(&wrapper->cache, &cache->cache)) {
    result = error_result(env, "secnonce was generated for a different keyagg cache");
  } else if (wrapper->has_msg && memcmp(wrapper->msg, session->msg, sizeof(wrapper->msg)) != 0) {
    result = error_result(env, "secnonce was generated for a different message");
  } else if (!keypair_matches_secnonce(ctx, &keypair, wrapper)) {
    result = error_result(env, "secret key does not match secnonce public key");
  } else if (!secp256k1_musig_partial_sign(
               ctx,
               &partial_sig,
               &wrapper->nonce,
               &keypair,
               &cache->cache,
               &session->session
             )) {
    result = error_result(env, "secp256k1_musig_partial_sign failed");
  } else {
    result = partial_sig_result(env, &partial_sig);
  }

cleanup:
  secure_erase(&keypair, sizeof(keypair));
  if (claimed) {
    secure_erase(&wrapper->nonce, sizeof(wrapper->nonce));
  }
  return result;
}

ERL_NIF_TERM
secp256k1_nif_musig_partial_sig_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  ErlNifBinary bin_psig, bin_pubnonce, bin_pubkey;
  secp256k1_musig_partial_sig partial_sig;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_pubkey pubkey;
  keyagg_cache_wrapper *cache;
  session_wrapper *session;

  (void)argc;

  if (!enif_inspect_binary(env, argv[0], &bin_psig) || bin_psig.size != MUSIG_PARTIAL_SIG_SIZE ||
      !secp256k1_musig_partial_sig_parse(ctx, &partial_sig, bin_psig.data) ||
      !enif_inspect_binary(env, argv[1], &bin_pubnonce) ||
      bin_pubnonce.size != MUSIG_PUBNONCE_SIZE ||
      !secp256k1_musig_pubnonce_parse(ctx, &pubnonce, bin_pubnonce.data) ||
      !enif_inspect_binary(env, argv[2], &bin_pubkey) ||
      !secp256k1_ec_pubkey_parse(ctx, &pubkey, bin_pubkey.data, bin_pubkey.size) ||
      !get_keyagg_cache(env, argv[3], &cache) || !get_session(env, argv[4], &session)) {
    return enif_make_badarg(env);
  }

  if (!keyagg_cache_equal(&cache->cache, &session->cache)) {
    return enif_make_atom(env, "false");
  }

  return enif_make_atom(
    env,
    secp256k1_musig_partial_sig_verify(
      ctx,
      &partial_sig,
      &pubnonce,
      &pubkey,
      &cache->cache,
      &session->session
    )
      ? "true"
      : "false"
  );
}

static int
parse_partial_sigs(
  ErlNifEnv *env,
  const secp256k1_context *ctx,
  ERL_NIF_TERM list,
  unsigned int count,
  secp256k1_musig_partial_sig *sigs,
  const secp256k1_musig_partial_sig **sig_ptrs
)
{
  ERL_NIF_TERM head;
  ErlNifBinary bin;
  unsigned int i;

  for (i = 0; i < count; i++) {
    if (!enif_get_list_cell(env, list, &head, &list) || !enif_inspect_binary(env, head, &bin) ||
        bin.size != MUSIG_PARTIAL_SIG_SIZE ||
        !secp256k1_musig_partial_sig_parse(ctx, &sigs[i], bin.data)) {
      return 0;
    }
    sig_ptrs[i] = &sigs[i];
  }

  return 1;
}

ERL_NIF_TERM
secp256k1_nif_musig_partial_sig_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  session_wrapper *session;
  unsigned int n_sigs;
  secp256k1_musig_partial_sig *sigs;
  const secp256k1_musig_partial_sig **sig_ptrs;
  void *elems;
  unsigned char sig64[SCHNORR_SIG_SIZE];
  ERL_NIF_TERM result;
  int parsed;
  int aggregated = 0;

  (void)argc;

  if (!get_session(env, argv[0], &session) || !enif_get_list_length(env, argv[1], &n_sigs) ||
      n_sigs == 0) {
    return enif_make_badarg(env);
  }

  sig_ptrs = musig_alloc_list(n_sigs, sizeof(*sig_ptrs), sizeof(*sigs), &elems);
  if (!sig_ptrs) {
    return allocation_failed(env);
  }
  sigs = elems;

  parsed = parse_partial_sigs(env, ctx, argv[1], n_sigs, sigs, sig_ptrs);
  if (parsed) {
    aggregated = secp256k1_musig_partial_sig_agg(ctx, sig64, &session->session, sig_ptrs, n_sigs);
  }

  enif_free(sig_ptrs);

  if (!parsed) {
    return enif_make_badarg(env);
  }
  if (!aggregated) {
    return error_result(env, "secp256k1_musig_partial_sig_agg failed");
  }
  if (!make_binary(env, sig64, sizeof(sig64), &result)) {
    return allocation_failed(env);
  }

  return result;
}
