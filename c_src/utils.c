#include "utils.h"

#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#include <Windows.h>
#endif

#include "random.h"

static void
secp256k1_nif_illegal_callback(const char *message, void *data)
{
  (void)data;
  fprintf(stderr, "[libsecp256k1 NIF] illegal argument: %s\n", message ? message : "(null)");
  fflush(stderr);
}

static void
secp256k1_nif_error_callback(const char *message, void *data)
{
  (void)data;
  fprintf(stderr, "[libsecp256k1 NIF] internal error: %s\n", message ? message : "(null)");
  fflush(stderr);
}

static void
install_context_callbacks(secp256k1_context *context)
{
  secp256k1_context_set_illegal_callback(context, secp256k1_nif_illegal_callback, NULL);
  secp256k1_context_set_error_callback(context, secp256k1_nif_error_callback, NULL);
}

void
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

secp256k1_nif_state *
secp256k1_nif_state_create(void)
{
  secp256k1_nif_state *state = NULL;
  unsigned char randomize[32] = {0};
  int success = 0;

  state = enif_alloc(sizeof(*state));
  if (!state) {
    goto cleanup;
  }
  memset(state, 0, sizeof(*state));

  state->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!state->ctx) {
    goto cleanup;
  }
  install_context_callbacks(state->ctx);

  if (!fill_random(randomize, sizeof(randomize))) {
    goto cleanup;
  }
  if (!secp256k1_context_randomize(state->ctx, randomize)) {
    goto cleanup;
  }

  success = 1;

cleanup:
  secure_erase(randomize, sizeof(randomize));
  if (!success) {
    secp256k1_nif_state_destroy(state);
    return NULL;
  }
  return state;
}

void
secp256k1_nif_state_destroy(secp256k1_nif_state *state)
{
  if (!state) {
    return;
  }
  if (state->ctx) {
    secp256k1_context_destroy(state->ctx);
  }
  enif_free(state);
}

ERL_NIF_TERM
error_result(ErlNifEnv *env, const char *error_msg)
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
