#include "utils.h"
#include "nifs.h"

#include <secp256k1_ecdh.h>

// API

ERL_NIF_TERM
secp256k1_nif_ecdh(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;
  ErlNifBinary pubkey;

  secp256k1_pubkey pubkey_parsed;

  unsigned char shared_secret[ECDH_SHARED_SECRET_SIZE];

  if (!get_seckey(env, argv[0], &seckey) || !enif_inspect_binary(env, argv[1], &pubkey) ||
      (pubkey.size != COMPRESSED_PUBKEY_SIZE && pubkey.size != UNCOMPRESSED_PUBKEY_SIZE)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_parsed, pubkey.data, pubkey.size)) {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  if (!secp256k1_ecdh(ctx, shared_secret, &pubkey_parsed, seckey.data, NULL, NULL)) {
    result = error_result(env, "secp256k1_ecdh failed");
  } else if (!make_binary(env, shared_secret, sizeof(shared_secret), &result)) {
    result = allocation_failed(env);
  }

  secure_erase(shared_secret, sizeof(shared_secret));
  return result;
}
