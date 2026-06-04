#include "utils.h"

// API

static ERL_NIF_TERM
compressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[33];
  unsigned char *finished;
  size_t len;

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

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data))
  {
    return error_result(env, "secp256k1_ec_pubkey_create failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
uncompressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[65];
  unsigned char *finished;
  size_t len;

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

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data))
  {
    return error_result(env, "secp256k1_ec_pubkey_create failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
compress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary input;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[33];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &input))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (input.size != 65)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
decompress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary input;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[65];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &input))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (input.size != 33)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary msg_hash, seckey, auxiliary_rand;

  secp256k1_ecdsa_signature sig;

  unsigned char serialized_signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &msg_hash) ||
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

  if (msg_hash.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (auxiliary_rand.size != 32)
  {
    return enif_make_badarg(env);
  }

  /* Generate a ECDSA signature */
  if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash.data, seckey.data, NULL, auxiliary_rand.data))
  {
    return error_result(env, "secp256k1_ecdsa_sign failed");
  }

  /* Serialize a ECDSA signature */
  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig))
  {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  /* Convert signature to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_signature), &result);
  memcpy(finished, serialized_signature, sizeof(serialized_signature));
  return result;
}

static ERL_NIF_TERM
verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary serialized_sig, msg_hash, serialized_pubkey;

  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pubkey;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &serialized_sig) ||
      !enif_inspect_binary(env, argv[1], &msg_hash) ||
      !enif_inspect_binary(env, argv[2], &serialized_pubkey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (serialized_sig.size != 64 || msg_hash.size != 32 || serialized_pubkey.size != 33)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data))
  {
    return enif_make_atom(env, "false");
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, serialized_pubkey.data, serialized_pubkey.size))
  {
    return enif_make_atom(env, "false");
  }

  if (secp256k1_ecdsa_verify(ctx, &sig, msg_hash.data, &pubkey))
  {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}

static ErlNifFunc nif_funcs[] = {
    {"compressed_pubkey", 1, compressed_pubkey},
    {"uncompressed_pubkey", 1, uncompressed_pubkey},
    {"compress_pubkey", 1, compress_pubkey},
    {"decompress_pubkey", 1, decompress_pubkey},
    {"sign", 3, sign},
    {"valid?", 3, verify},
};

ERL_NIF_INIT(Elixir.Secp256k1.ECDSA, nif_funcs, &load, NULL, &upgrade, &unload)
