#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

// API

static int
make_binary(ErlNifEnv *env, const unsigned char *data, size_t size, ERL_NIF_TERM *result)
{
  ErlNifBinary bin;

  if (!enif_alloc_binary(size, &bin)) {
    return 0;
  }

  memcpy(bin.data, data, size);
  *result = enif_make_binary(env, &bin);
  return 1;
}

static ERL_NIF_TERM
xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair = {0};

  unsigned char serialized_pubkey[32];

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
    secure_erase(&keypair, sizeof(keypair));
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

  if (!make_binary(env, serialized_pubkey, sizeof(serialized_pubkey), &result))
  {
    result = error_result(env, "enif_alloc_binary failed");
  }

cleanup:
  secure_erase(&keypair, sizeof(keypair));
  return result;
}

static ERL_NIF_TERM
ec_seckey_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey, tweak;
  unsigned char tweaked_seckey[32];

  if (!enif_inspect_binary(env, argv[0], &seckey) ||
      !enif_inspect_binary(env, argv[1], &tweak) ||
      seckey.size != sizeof(tweaked_seckey) ||
      tweak.size != 32 ||
      !secp256k1_ec_seckey_verify(ctx, seckey.data))
  {
    return enif_make_badarg(env);
  }

  memcpy(tweaked_seckey, seckey.data, sizeof(tweaked_seckey));
  if (!secp256k1_ec_seckey_tweak_add(ctx, tweaked_seckey, tweak.data))
  {
    secure_erase(tweaked_seckey, sizeof(tweaked_seckey));
    return error_result(env, "secp256k1_ec_seckey_tweak_add failed");
  }

  if (!make_binary(env, tweaked_seckey, sizeof(tweaked_seckey), &result))
  {
    secure_erase(tweaked_seckey, sizeof(tweaked_seckey));
    return error_result(env, "enif_alloc_binary failed");
  }

  secure_erase(tweaked_seckey, sizeof(tweaked_seckey));
  return result;
}

static ERL_NIF_TERM
ec_pubkey_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary input, tweak;
  secp256k1_pubkey pubkey;
  unsigned char serialized_pubkey[65];
  size_t serialized_size;
  unsigned int serialization_flags;

  if (!enif_inspect_binary(env, argv[0], &input) ||
      !enif_inspect_binary(env, argv[1], &tweak) ||
      (input.size != 33 && input.size != 65) ||
      tweak.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak.data))
  {
    return error_result(env, "secp256k1_ec_pubkey_tweak_add failed");
  }

  serialized_size = input.size;
  serialization_flags = input.size == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  if (!secp256k1_ec_pubkey_serialize(
      ctx,
      serialized_pubkey,
      &serialized_size,
      &pubkey,
      serialization_flags
    ))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!make_binary(env, serialized_pubkey, serialized_size, &result))
  {
    return error_result(env, "enif_alloc_binary failed");
  }

  return result;
}

static ERL_NIF_TERM
xonly_seckey_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary seckey, tweak;
  secp256k1_keypair keypair = {0};
  unsigned char tweaked_seckey[32] = {0};

  if (!enif_inspect_binary(env, argv[0], &seckey) ||
      !enif_inspect_binary(env, argv[1], &tweak) ||
      seckey.size != 32 ||
      tweak.size != 32 ||
      !secp256k1_ec_seckey_verify(ctx, seckey.data))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    secure_erase(&keypair, sizeof(keypair));
    return error_result(env, "secp256k1_keypair_create failed");
  }

  if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak.data))
  {
    result = error_result(env, "secp256k1_keypair_xonly_tweak_add failed");
    goto cleanup_keypair;
  }

  if (!secp256k1_keypair_sec(ctx, tweaked_seckey, &keypair))
  {
    result = error_result(env, "secp256k1_keypair_sec failed");
    goto cleanup_secrets;
  }

  if (!make_binary(env, tweaked_seckey, sizeof(tweaked_seckey), &result))
  {
    result = error_result(env, "enif_alloc_binary failed");
  }

cleanup_secrets:
  secure_erase(tweaked_seckey, sizeof(tweaked_seckey));

cleanup_keypair:
  secure_erase(&keypair, sizeof(keypair));
  return result;
}

static ERL_NIF_TERM
xonly_pubkey_tweak_add(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ERL_NIF_TERM pubkey_term;
  ErlNifBinary internal_pubkey, tweak;
  secp256k1_xonly_pubkey parsed_internal_pubkey, tweaked_xonly_pubkey;
  secp256k1_pubkey tweaked_pubkey;
  unsigned char serialized_pubkey[32];
  int parity;

  if (!enif_inspect_binary(env, argv[0], &internal_pubkey) ||
      !enif_inspect_binary(env, argv[1], &tweak) ||
      internal_pubkey.size != sizeof(serialized_pubkey) ||
      tweak.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &parsed_internal_pubkey, internal_pubkey.data))
  {
    return error_result(env, "secp256k1_xonly_pubkey_parse failed");
  }

  if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pubkey, &parsed_internal_pubkey, tweak.data))
  {
    return error_result(env, "secp256k1_xonly_pubkey_tweak_add failed");
  }

  if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly_pubkey, &parity, &tweaked_pubkey))
  {
    return error_result(env, "secp256k1_xonly_pubkey_from_pubkey failed");
  }

  if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &tweaked_xonly_pubkey))
  {
    return error_result(env, "secp256k1_xonly_pubkey_serialize failed");
  }

  if (!make_binary(env, serialized_pubkey, sizeof(serialized_pubkey), &pubkey_term))
  {
    return error_result(env, "enif_alloc_binary failed");
  }

  return enif_make_tuple3(
    env,
    enif_make_atom(env, "ok"),
    pubkey_term,
    enif_make_int(env, parity)
  );
}

static ERL_NIF_TERM
xonly_pubkey_tweak_add_check(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;

  ErlNifBinary tweaked_pubkey, internal_pubkey, tweak;
  secp256k1_xonly_pubkey parsed_internal_pubkey;
  int parity;

  if (!enif_inspect_binary(env, argv[0], &tweaked_pubkey) ||
      !enif_get_int(env, argv[1], &parity) ||
      !enif_inspect_binary(env, argv[2], &internal_pubkey) ||
      !enif_inspect_binary(env, argv[3], &tweak) ||
      tweaked_pubkey.size != 32 ||
      (parity != 0 && parity != 1) ||
      internal_pubkey.size != 32 ||
      tweak.size != 32 ||
      !secp256k1_xonly_pubkey_parse(ctx, &parsed_internal_pubkey, internal_pubkey.data))
  {
    return enif_make_atom(env, "false");
  }

  if (secp256k1_xonly_pubkey_tweak_add_check(
      ctx,
      tweaked_pubkey.data,
      parity,
      &parsed_internal_pubkey,
      tweak.data
    ))
  {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}

static ErlNifFunc nif_funcs[] = {
    {"xonly_pubkey_nif", 1, xonly_pubkey},
    {"ec_seckey_tweak_add_nif", 2, ec_seckey_tweak_add},
    {"ec_pubkey_tweak_add_nif", 2, ec_pubkey_tweak_add},
    {"xonly_seckey_tweak_add_nif", 2, xonly_seckey_tweak_add},
    {"xonly_pubkey_tweak_add_nif", 2, xonly_pubkey_tweak_add},
    {"xonly_pubkey_tweak_add_check_nif", 4, xonly_pubkey_tweak_add_check},
};

ERL_NIF_INIT(Elixir.Secp256k1.Extrakeys, nif_funcs, &load, NULL, &upgrade, &unload)
