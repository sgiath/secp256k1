#ifndef SECP256K1_NIF_UTILS_H
#define SECP256K1_NIF_UTILS_H

#include <erl_nif.h>
#include <secp256k1.h>
#include <string.h>
#include <assert.h>

#if defined(_MSC_VER)
#include <Windows.h>
#endif

#include "random.h"

static secp256k1_context *ctx = NULL;

static void
secure_erase(void *ptr, size_t len)
{
#if defined(_MSC_VER)
  SecureZeroMemory(ptr, len);
#elif defined(__GNUC__)
  memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
  void *(*volatile const volatile_memset)(void *, int, size_t) = memset;
  volatile_memset(ptr, 0, len);
#endif
}

static int
load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info)
{
  int return_val;
  unsigned char randomize[32];
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!fill_random(randomize, sizeof(randomize)))
  {
    return -1;
  }
  return_val = secp256k1_context_randomize(ctx, randomize);
  assert(return_val);
  secure_erase(randomize, sizeof(randomize));
  return 0;
}

static int
upgrade(ErlNifEnv *env, void **priv, void **old_priv, ERL_NIF_TERM load_info)
{
  int return_val;
  unsigned char randomize[32];

  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!ctx) {
    return -1;
  }

  if (!fill_random(randomize, sizeof(randomize))) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return -1;
  }

  return_val = secp256k1_context_randomize(ctx, randomize);
  secure_erase(randomize, sizeof(randomize));
  if (!return_val) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return -1;
  }

  return 0;
}

static void
unload(ErlNifEnv *env, void *priv)
{
  secp256k1_context_destroy(ctx);
  return;
}

static ERL_NIF_TERM
error_result(ErlNifEnv *env, char *error_msg)
{
  ErlNifBinary bin;
  size_t len = strlen(error_msg);

  if (!enif_alloc_binary(len, &bin)) {
    return enif_make_tuple2(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, "allocation_failed")
    );
  }
  memcpy(bin.data, error_msg, len);

  return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_binary(env, &bin));
}

#endif /* SECP256K1_NIF_UTILS_H */
