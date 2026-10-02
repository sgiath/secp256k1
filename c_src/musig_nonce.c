#include "musig.h"
#include "nifs.h"
#include "random.h"

typedef struct {
  const unsigned char *seckey;
  secp256k1_pubkey pubkey;
  const unsigned char *msg;
  const secp256k1_musig_keyagg_cache *cache;
  const unsigned char *extra;
} nonce_gen_input;

static int
is_nil(ErlNifEnv *env, ERL_NIF_TERM term)
{
  return enif_is_identical(term, enif_make_atom(env, "nil"));
}

/* Accepts nil (stores NULL) or a binary of exactly `size` bytes. */
static int
get_optional_binary(ErlNifEnv *env, ERL_NIF_TERM term, size_t size, const unsigned char **data)
{
  ErlNifBinary bin;

  if (is_nil(env, term)) {
    *data = NULL;
    return 1;
  }
  if (!enif_inspect_binary(env, term, &bin) || bin.size != size) {
    return 0;
  }
  *data = bin.data;
  return 1;
}

/* A provided seckey must be a valid scalar whose public key is the signer pubkey. */
static int
seckey_matches_pubkey(
  const secp256k1_context *ctx,
  const unsigned char *seckey,
  const secp256k1_pubkey *pubkey
)
{
  secp256k1_pubkey derived;

  return secp256k1_ec_pubkey_create(ctx, &derived, seckey) &&
         secp256k1_ec_pubkey_cmp(ctx, &derived, pubkey) == 0;
}

static int
parse_nonce_gen_input(ErlNifEnv *env, const ERL_NIF_TERM argv[], nonce_gen_input *input)
{
  secp256k1_context *ctx = nif_ctx(env);
  ErlNifBinary bin_pubkey;
  keyagg_cache_wrapper *cache_wrapper;

  if (!get_optional_binary(env, argv[0], SECKEY_SIZE, &input->seckey) ||
      !enif_inspect_binary(env, argv[1], &bin_pubkey) ||
      !secp256k1_ec_pubkey_parse(ctx, &input->pubkey, bin_pubkey.data, bin_pubkey.size) ||
      !get_optional_binary(env, argv[2], HASH_SIZE, &input->msg) ||
      !get_optional_binary(env, argv[4], MUSIG_EXTRA_INPUT_SIZE, &input->extra)) {
    return 0;
  }

  input->cache = NULL;
  if (!is_nil(env, argv[3])) {
    if (!get_keyagg_cache(env, argv[3], &cache_wrapper)) {
      return 0;
    }
    input->cache = &cache_wrapper->cache;
  }

  return input->seckey == NULL || seckey_matches_pubkey(ctx, input->seckey, &input->pubkey);
}

static ERL_NIF_TERM
nonce_gen_result(
  ErlNifEnv *env,
  const secp256k1_musig_secnonce *secnonce,
  const secp256k1_musig_pubnonce *pubnonce,
  const nonce_gen_input *input
)
{
  unsigned char serialized_pubnonce[MUSIG_PUBNONCE_SIZE];
  ERL_NIF_TERM pubnonce_term;
  ERL_NIF_TERM secnonce_term;

  if (!secp256k1_musig_pubnonce_serialize(nif_ctx(env), serialized_pubnonce, pubnonce)) {
    return error_result(env, "secp256k1_musig_pubnonce_serialize failed");
  }

  if (!make_binary(env, serialized_pubnonce, sizeof(serialized_pubnonce), &pubnonce_term) ||
      !make_secnonce_resource(
        env,
        secnonce,
        &input->pubkey,
        input->msg,
        input->cache,
        &secnonce_term
      )) {
    return allocation_failed(env);
  }

  return enif_make_tuple3(env, enif_make_atom(env, "ok"), secnonce_term, pubnonce_term);
}

ERL_NIF_TERM
secp256k1_nif_musig_nonce_gen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  nonce_gen_input input;
  secp256k1_musig_secnonce secnonce;
  secp256k1_musig_pubnonce pubnonce;
  unsigned char session_secrand[MUSIG_SESSION_SECRAND_SIZE];
  ERL_NIF_TERM result;

  (void)argc;

  if (!parse_nonce_gen_input(env, argv, &input)) {
    return enif_make_badarg(env);
  }

  if (!fill_random(session_secrand, sizeof(session_secrand))) {
    result = error_result(env, "RNG failed");
    goto cleanup;
  }

  if (!secp256k1_musig_nonce_gen(
        nif_ctx(env),
        &secnonce,
        &pubnonce,
        session_secrand,
        input.seckey,
        &input.pubkey,
        input.msg,
        input.cache,
        input.extra
      )) {
    result = error_result(env, "secp256k1_musig_nonce_gen failed");
    goto cleanup;
  }

  result = nonce_gen_result(env, &secnonce, &pubnonce, &input);

cleanup:
  secure_erase(session_secrand, sizeof(session_secrand));
  secure_erase(&secnonce, sizeof(secnonce));
  return result;
}

static int
parse_pubnonces(
  ErlNifEnv *env,
  const secp256k1_context *ctx,
  ERL_NIF_TERM list,
  unsigned int count,
  secp256k1_musig_pubnonce *nonces,
  const secp256k1_musig_pubnonce **nonce_ptrs
)
{
  ERL_NIF_TERM head;
  ErlNifBinary bin;
  unsigned int i;

  for (i = 0; i < count; i++) {
    if (!enif_get_list_cell(env, list, &head, &list) || !enif_inspect_binary(env, head, &bin) ||
        bin.size != MUSIG_PUBNONCE_SIZE ||
        !secp256k1_musig_pubnonce_parse(ctx, &nonces[i], bin.data)) {
      return 0;
    }
    nonce_ptrs[i] = &nonces[i];
  }

  return 1;
}

ERL_NIF_TERM
secp256k1_nif_musig_nonce_agg(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  unsigned int n_nonces;
  secp256k1_musig_pubnonce *nonces;
  const secp256k1_musig_pubnonce **nonce_ptrs;
  void *elems;
  secp256k1_musig_aggnonce aggnonce;
  unsigned char serialized_aggnonce[MUSIG_AGGNONCE_SIZE];
  ERL_NIF_TERM result;
  int parsed;
  int aggregated = 0;

  (void)argc;

  if (!enif_get_list_length(env, argv[0], &n_nonces) || n_nonces == 0) {
    return enif_make_badarg(env);
  }

  nonce_ptrs = musig_alloc_list(n_nonces, sizeof(*nonce_ptrs), sizeof(*nonces), &elems);
  if (!nonce_ptrs) {
    return allocation_failed(env);
  }
  nonces = elems;

  parsed = parse_pubnonces(env, ctx, argv[0], n_nonces, nonces, nonce_ptrs);
  if (parsed) {
    aggregated = secp256k1_musig_nonce_agg(ctx, &aggnonce, nonce_ptrs, n_nonces);
  }

  enif_free(nonce_ptrs);

  if (!parsed) {
    return enif_make_badarg(env);
  }
  if (!aggregated) {
    return error_result(env, "secp256k1_musig_nonce_agg failed");
  }

  if (!secp256k1_musig_aggnonce_serialize(ctx, serialized_aggnonce, &aggnonce)) {
    return error_result(env, "secp256k1_musig_aggnonce_serialize failed");
  }
  if (!make_binary(env, serialized_aggnonce, sizeof(serialized_aggnonce), &result)) {
    return allocation_failed(env);
  }

  return result;
}

ERL_NIF_TERM
secp256k1_nif_musig_nonce_process(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  ErlNifBinary bin_aggnonce, bin_msg;
  secp256k1_musig_aggnonce aggnonce;
  keyagg_cache_wrapper *cache;
  secp256k1_musig_session session;
  ERL_NIF_TERM session_term;

  (void)argc;

  if (!enif_inspect_binary(env, argv[0], &bin_aggnonce) ||
      bin_aggnonce.size != MUSIG_AGGNONCE_SIZE ||
      !secp256k1_musig_aggnonce_parse(ctx, &aggnonce, bin_aggnonce.data) ||
      !enif_inspect_binary(env, argv[1], &bin_msg) || bin_msg.size != HASH_SIZE ||
      !get_keyagg_cache(env, argv[2], &cache)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce, bin_msg.data, &cache->cache)) {
    return error_result(env, "secp256k1_musig_nonce_process failed");
  }

  if (!make_session_resource(env, &session, &cache->cache, bin_msg.data, &session_term)) {
    return allocation_failed(env);
  }

  return session_term;
}
