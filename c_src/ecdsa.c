#include "utils.h"
#include "nifs.h"

// API

static ERL_NIF_TERM
ecdsa_seckey_pubkey(ErlNifEnv *env, const ERL_NIF_TERM argv[], unsigned int serialization_flags)
{
  secp256k1_context *ctx = nif_ctx(env);
  ErlNifBinary seckey;
  secp256k1_pubkey pubkey;
  unsigned char serialized_pubkey[UNCOMPRESSED_PUBKEY_SIZE];
  size_t len = sizeof(serialized_pubkey);
  ERL_NIF_TERM result;

  if (!get_seckey(env, argv[0], &seckey)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data)) {
    return error_result(env, "secp256k1_ec_pubkey_create failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, serialization_flags)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!make_binary(env, serialized_pubkey, len, &result)) {
    return allocation_failed(env);
  }
  return result;
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_compressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return ecdsa_seckey_pubkey(env, argv, SECP256K1_EC_COMPRESSED);
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_uncompressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return ecdsa_seckey_pubkey(env, argv, SECP256K1_EC_UNCOMPRESSED);
}

static ERL_NIF_TERM
ecdsa_parse_pubkey(
  ErlNifEnv *env,
  const ERL_NIF_TERM argv[],
  size_t input_size,
  unsigned int serialization_flags
)
{
  secp256k1_context *ctx = nif_ctx(env);
  ErlNifBinary input;
  secp256k1_pubkey pubkey;
  unsigned char serialized_pubkey[UNCOMPRESSED_PUBKEY_SIZE];
  size_t len = sizeof(serialized_pubkey);
  ERL_NIF_TERM result;

  if (!enif_inspect_binary(env, argv[0], &input)) {
    return enif_make_badarg(env);
  }

  if (input.size != input_size) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size)) {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, serialization_flags)) {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  if (!make_binary(env, serialized_pubkey, len, &result)) {
    return allocation_failed(env);
  }
  return result;
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_compress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return ecdsa_parse_pubkey(env, argv, UNCOMPRESSED_PUBKEY_SIZE, SECP256K1_EC_COMPRESSED);
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_decompress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  (void)argc;
  return ecdsa_parse_pubkey(env, argv, COMPRESSED_PUBKEY_SIZE, SECP256K1_EC_UNCOMPRESSED);
}

ERL_NIF_TERM
secp256k1_nif_ecdsa_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  secp256k1_context *ctx = nif_ctx(env);
  ERL_NIF_TERM result;
  ErlNifBinary msg_hash, seckey, nonce_data;
  const unsigned char *ndata = NULL;
  secp256k1_ecdsa_signature sig;
  unsigned char serialized_signature[ECDSA_COMPACT_SIG_SIZE];

  (void)argc;

  if (!enif_inspect_binary(env, argv[0], &msg_hash) || msg_hash.size != HASH_SIZE ||
      !get_seckey(env, argv[1], &seckey)) {
    return enif_make_badarg(env);
  }

  if (!enif_is_identical(argv[2], enif_make_atom(env, "nil"))) {
    if (!enif_inspect_binary(env, argv[2], &nonce_data) ||
        nonce_data.size != ECDSA_NONCE_DATA_SIZE) {
      return enif_make_badarg(env);
    }
    ndata = nonce_data.data;
  }

  /* Generate a ECDSA signature */
  if (!secp256k1_ecdsa_sign(
        ctx,
        &sig,
        msg_hash.data,
        seckey.data,
        secp256k1_nonce_function_rfc6979,
        ndata
      )) {
    return error_result(env, "secp256k1_ecdsa_sign failed");
  }

  /* Serialize a ECDSA signature */
  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig)) {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  if (!make_binary(env, serialized_signature, sizeof(serialized_signature), &result)) {
    return allocation_failed(env);
  }
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
  unsigned char der[ECDSA_DER_SIG_MAX_SIZE];
  size_t der_len = sizeof(der);

  if (!enif_inspect_binary(env, argv[0], &serialized_sig) ||
      serialized_sig.size != ECDSA_COMPACT_SIG_SIZE) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig)) {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_der failed");
  }

  if (!make_binary(env, der, der_len, &result)) {
    return allocation_failed(env);
  }
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
  unsigned char serialized_sig[ECDSA_COMPACT_SIG_SIZE];

  if (!enif_inspect_binary(env, argv[0], &der) || der.size < ECDSA_DER_SIG_MIN_SIZE ||
      der.size > ECDSA_DER_SIG_MAX_SIZE) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, der.data, der.size)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_sig, &sig)) {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  if (!make_binary(env, serialized_sig, sizeof(serialized_sig), &result)) {
    return allocation_failed(env);
  }
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
  unsigned char normalized[ECDSA_COMPACT_SIG_SIZE];

  if (!enif_inspect_binary(env, argv[0], &serialized_sig) ||
      serialized_sig.size != ECDSA_COMPACT_SIG_SIZE) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data)) {
    return enif_make_badarg(env);
  }

  secp256k1_ecdsa_signature_normalize(ctx, &normalized_sig, &sig);

  if (!secp256k1_ecdsa_signature_serialize_compact(ctx, normalized, &normalized_sig)) {
    return error_result(env, "secp256k1_ecdsa_signature_serialize_compact failed");
  }

  if (!make_binary(env, normalized, sizeof(normalized), &result)) {
    return allocation_failed(env);
  }
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
      !enif_inspect_binary(env, argv[2], &serialized_pubkey)) {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (serialized_sig.size != ECDSA_COMPACT_SIG_SIZE || msg_hash.size != HASH_SIZE ||
      (serialized_pubkey.size != COMPRESSED_PUBKEY_SIZE &&
       serialized_pubkey.size != UNCOMPRESSED_PUBKEY_SIZE)) {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_sig.data)) {
    return enif_make_atom(env, "false");
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, serialized_pubkey.data, serialized_pubkey.size)) {
    return enif_make_atom(env, "false");
  }

  if (secp256k1_ecdsa_verify(ctx, &sig, msg_hash.data, &pubkey)) {
    return enif_make_atom(env, "true");
  }

  return enif_make_atom(env, "false");
}
