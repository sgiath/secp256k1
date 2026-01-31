#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

// API

static ERL_NIF_TERM
xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair;

  unsigned char serialized_pubkey[32];
  unsigned char *finished;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &seckey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data)))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  if (!secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair))
  {
    return error_result(env, "secp256k1_keypair_xonly_pub failed");
  }

  if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey))
  {
    return error_result(env, "secp256k1_xonly_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  secure_erase(&keypair, sizeof(keypair));
  return result;
}

static ErlNifFunc nif_funcs[] = {
    {"xonly_pubkey", 1, xonly_pubkey},
};

ERL_NIF_INIT(Elixir.Secp256k1.Extrakeys, nif_funcs, &load, NULL, &upgrade, &unload)
