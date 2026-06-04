#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

// API

static ERL_NIF_TERM
sign32(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary message, seckey, auxiliary_rand;

  secp256k1_keypair keypair;

  unsigned char signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &seckey) ||
      !enif_inspect_binary(env, argv[2], &auxiliary_rand))
  {
    return enif_make_badarg(env);
  }

  /* check expected arguments size */
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data)))
  {
    return enif_make_badarg(env);
  }

  if (message.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (auxiliary_rand.size != 32)
  {
    return enif_make_badarg(env);
  }

  /* create key pair from secret key */
  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  /* Generate a Schnorr signature */
  if (!secp256k1_schnorrsig_sign32(ctx, signature, message.data, &keypair, auxiliary_rand.data))
  {
    result = error_result(env, "secp256k1_schnorrsig_sign32 failed");
    goto cleanup;
  }

  /* Convert signature to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(signature), &result);
  memcpy(finished, signature, sizeof(signature));

cleanup:
  secure_erase(&keypair, sizeof(keypair));
  return result;
}

static ERL_NIF_TERM
sign_custom(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary message, seckey, auxiliary_rand;

  secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  secp256k1_keypair keypair;

  unsigned char signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &seckey) ||
      !enif_inspect_binary(env, argv[2], &auxiliary_rand))
  {
    return enif_make_badarg(env);
  }

  if (auxiliary_rand.size != 32)
  {
    return enif_make_badarg(env);
  }

  /* check expected arguments size */
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data)))
  {
    return enif_make_badarg(env);
  }

  /* create key pair from secret key */
  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  /* Assign the randomness to the extraparams data field */
  extraparams.ndata = auxiliary_rand.data;

  /* Generate a Schnorr signature */
  if (!secp256k1_schnorrsig_sign_custom(ctx, signature, message.data, message.size, &keypair, &extraparams))
  {
    result = error_result(env, "secp256k1_schnorrsig_sign_custom failed");
    goto cleanup;
  }

  /* Convert signature to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(signature), &result);
  memcpy(finished, signature, sizeof(signature));

cleanup:
  secure_erase(&keypair, sizeof(keypair));
  return result;
}

static ERL_NIF_TERM
verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary signature, message, pubkey;

  secp256k1_xonly_pubkey xonly_pubkey;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &signature) ||
      !enif_inspect_binary(env, argv[1], &message) ||
      !enif_inspect_binary(env, argv[2], &pubkey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (signature.size != 64 || pubkey.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, pubkey.data))
  {
    return enif_make_atom(env, "false");
  }

  if (secp256k1_schnorrsig_verify(ctx, signature.data, message.data, message.size, &xonly_pubkey))
  {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}

static ErlNifFunc nif_funcs[] = {
    {"sign32", 3, sign32},
    {"sign_custom", 3, sign_custom},
    {"valid?", 3, verify},
};

ERL_NIF_INIT(Elixir.Secp256k1.Schnorr, nif_funcs, &load, NULL, &upgrade, &unload)
