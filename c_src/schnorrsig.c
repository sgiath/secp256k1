#include "utils.h"
#include "nifs.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

/*
 * Shared Schnorr signer arguments: argv[0] message, argv[1] seckey, argv[2]
 * 32-byte aux randomness. Returns 1 with the keypair created. Otherwise
 * stores badarg or the error in *result and returns 0 with no secret in
 * *keypair.
 */
static int
schnorr_signer_args(
  ErlNifEnv *env,
  const ERL_NIF_TERM argv[],
  ErlNifBinary *message,
  ErlNifBinary *aux_rand,
  secp256k1_keypair *keypair,
  ERL_NIF_TERM *result
)
{
  if (!enif_inspect_binary(env, argv[0], message) || !enif_inspect_binary(env, argv[2], aux_rand) ||
      aux_rand->size != SCHNORR_AUX_RAND_SIZE) {
    *result = enif_make_badarg(env);
    return 0;
  }
  return get_keypair(env, argv[1], keypair, result);
}

static ERL_NIF_TERM
signature_result(ErlNifEnv *env, const unsigned char *signature)
{
  ERL_NIF_TERM result;

  if (!make_binary(env, signature, SCHNORR_SIG_SIZE, &result)) {
    return allocation_failed(env);
  }
  return result;
}

// API

ERL_NIF_TERM
secp256k1_nif_schnorr_sign32(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary message, aux_rand;
  secp256k1_keypair keypair;
  unsigned char signature[SCHNORR_SIG_SIZE];
  ERL_NIF_TERM result;

  (void)argc;

  if (!schnorr_signer_args(env, argv, &message, &aux_rand, &keypair, &result)) {
    return result;
  }

  if (message.size != HASH_SIZE) {
    result = enif_make_badarg(env);
  } else if (!secp256k1_schnorrsig_sign32(
               nif_ctx(env),
               signature,
               message.data,
               &keypair,
               aux_rand.data
             )) {
    result = error_result(env, "secp256k1_schnorrsig_sign32 failed");
  } else {
    result = signature_result(env, signature);
  }

  secure_erase(&keypair, sizeof(keypair));
  return result;
}

ERL_NIF_TERM
secp256k1_nif_schnorr_sign_custom(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary message, aux_rand;
  secp256k1_keypair keypair;
  secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  unsigned char signature[SCHNORR_SIG_SIZE];
  ERL_NIF_TERM result;

  (void)argc;

  if (!schnorr_signer_args(env, argv, &message, &aux_rand, &keypair, &result)) {
    return result;
  }

  extraparams.ndata = aux_rand.data;
  if (!secp256k1_schnorrsig_sign_custom(
        nif_ctx(env),
        signature,
        message.data,
        message.size,
        &keypair,
        &extraparams
      )) {
    result = error_result(env, "secp256k1_schnorrsig_sign_custom failed");
  } else {
    result = signature_result(env, signature);
  }

  secure_erase(&keypair, sizeof(keypair));
  return result;
}

ERL_NIF_TERM
secp256k1_nif_schnorr_valid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ErlNifBinary signature, message, pubkey;

  secp256k1_xonly_pubkey xonly_pubkey;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &signature) ||
      !enif_inspect_binary(env, argv[1], &message) || !enif_inspect_binary(env, argv[2], &pubkey)) {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (signature.size != SCHNORR_SIG_SIZE || pubkey.size != XONLY_PUBKEY_SIZE) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, pubkey.data)) {
    return enif_make_atom(env, "false");
  }

  if (secp256k1_schnorrsig_verify(ctx, signature.data, message.data, message.size, &xonly_pubkey)) {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}
