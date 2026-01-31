#include "utils.h"

#include <secp256k1_ecdh.h>

// API

static ERL_NIF_TERM
ecdh(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;
  ErlNifBinary pubkey;

  secp256k1_pubkey pubkey_parsed;

  unsigned char shared_secret[32];
  unsigned char *finished;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &seckey) ||
      !enif_inspect_binary(env, argv[1], &pubkey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data) && (pubkey.size == 33 || pubkey.size == 65)))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_parsed, pubkey.data, pubkey.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  if (!secp256k1_ecdh(ctx, shared_secret, &pubkey_parsed, seckey.data, NULL, NULL))
  {
    return error_result(env, "secp256k1_ecdh failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(shared_secret), &result);
  memcpy(finished, shared_secret, sizeof(shared_secret));
  secure_erase(shared_secret, sizeof(shared_secret));
  return result;
}

static ErlNifFunc nif_funcs[] = {
    {"ecdh", 2, ecdh},
};

ERL_NIF_INIT(Elixir.Secp256k1.ECDH, nif_funcs, &load, NULL, &upgrade, &unload)
