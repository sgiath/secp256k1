#include "utils.h"
#include "nifs.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

// API

ERL_NIF_TERM
secp256k1_nif_xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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
    result = error_result(env, "secp256k1_keypair_xonly_pub failed");
    goto cleanup;
  }

  if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey))
  {
    result = error_result(env, "secp256k1_xonly_pubkey_serialize failed");
    goto cleanup;
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));

cleanup:
  secure_erase(&keypair, sizeof(keypair));
  return result;
}
