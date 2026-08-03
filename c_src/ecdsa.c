#include "utils.h"
#include "nifs.h"

// API

ERL_NIF_TERM
secp256k1_nif_ecdsa_compressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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

ERL_NIF_TERM
secp256k1_nif_ecdsa_uncompressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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

ERL_NIF_TERM
secp256k1_nif_ecdsa_compress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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

ERL_NIF_TERM
secp256k1_nif_ecdsa_decompress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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

ERL_NIF_TERM
secp256k1_nif_ecdsa_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary msg_hash, seckey, nonce_data;
  const unsigned char *ndata = NULL;

  secp256k1_ecdsa_signature sig;

  unsigned char serialized_signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &msg_hash) ||
      !enif_inspect_binary(env, argv[1], &seckey))
  {
    return enif_make_badarg(env);
  }

  if (!enif_is_identical(argv[2], enif_make_atom(env, "nil")))
  {
    if (!enif_inspect_binary(env, argv[2], &nonce_data) || nonce_data.size != 32)
    {
      return enif_make_badarg(env);
    }
    ndata = nonce_data.data;
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

  /* Generate a ECDSA signature */
  if (!secp256k1_ecdsa_sign(
      ctx,
      &sig,
      msg_hash.data,
      seckey.data,
      secp256k1_nonce_function_rfc6979,
      ndata
    ))
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

ERL_NIF_TERM
secp256k1_nif_ecdsa_serialize_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary serialized_sig;
  secp256k1_ecdsa_signature sig;
  unsigned char der[72];
  unsigned char *finished;
  size_t der_len = sizeof(der);

  if (!enif_inspect_binary(env, argv[0], &serialized_sig) || serialized_sig.size != 64)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig))
  {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_der failed");
  }

  finished = enif_make_new_binary(env, der_len, &result);
  if (!finished)
  {
    return error_result(env, "enif_make_new_binary failed");
  }
  memcpy(finished, der, der_len);
  return result;
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_parse_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary der;
  secp256k1_ecdsa_signature sig;
  unsigned char serialized_sig[64];
  unsigned char *finished;

  if (!enif_inspect_binary(env, argv[0], &der) || der.size < 8 || der.size > 72)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, der.data, der.size))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_sig, &sig))
  {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  finished = enif_make_new_binary(env, sizeof(serialized_sig), &result);
  if (!finished)
  {
    return error_result(env, "enif_make_new_binary failed");
  }
  memcpy(finished, serialized_sig, sizeof(serialized_sig));
  return result;
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_normalize(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  (void)argc;

  ERL_NIF_TERM result;
  ErlNifBinary serialized_sig;
  secp256k1_ecdsa_signature sig;
  secp256k1_ecdsa_signature normalized_sig;
  unsigned char normalized[64];
  unsigned char *finished;

  if (!enif_inspect_binary(env, argv[0], &serialized_sig) || serialized_sig.size != 64)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data))
  {
    return enif_make_badarg(env);
  }

  secp256k1_ecdsa_signature_normalize(ctx, &normalized_sig, &sig);

  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, normalized, &normalized_sig))
  {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  finished = enif_make_new_binary(env, sizeof(normalized), &result);
  if (!finished)
  {
    return error_result(env, "enif_make_new_binary failed");
  }
  memcpy(finished, normalized, sizeof(normalized));
  return result;
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_valid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
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
  if (serialized_sig.size != 64 || msg_hash.size != 32 ||
      (serialized_pubkey.size != 33 && serialized_pubkey.size != 65))
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
