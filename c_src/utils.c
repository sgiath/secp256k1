#include "utils.h"

#include <string.h>

#include <secp256k1_preallocated.h>

#if defined(_MSC_VER)
#include <Windows.h>
#define SECP256K1_NIF_THREAD_LOCAL __declspec(thread)
#else
#define SECP256K1_NIF_THREAD_LOCAL __thread
#endif

#include "random.h"

static SECP256K1_NIF_THREAD_LOCAL int illegal_fired;
static SECP256K1_NIF_THREAD_LOCAL int internal_fired;

static void
secp256k1_nif_illegal_callback(const char *message, void *data)
{
  (void)message;
  (void)data;
  illegal_fired = 1;
}

static void
secp256k1_nif_error_callback(const char *message, void *data)
{
  (void)message;
  (void)data;
  internal_fired = 1;
}

static void
install_context_callbacks(secp256k1_context *context)
{
  secp256k1_context_set_illegal_callback(context, secp256k1_nif_illegal_callback, NULL);
  secp256k1_context_set_error_callback(context, secp256k1_nif_error_callback, NULL);
}

void
callback_flags_clear(void)
{
  illegal_fired = 0;
  internal_fired = 0;
}

int
callback_illegal_fired(void)
{
  return illegal_fired;
}

int
callback_internal_fired(void)
{
  return internal_fired;
}

#ifdef SECP256K1_NIF_FAULT_INJECTION
void
callback_fire(int internal)
{
  if (internal) {
    internal_fired = 1;
  } else {
    illegal_fired = 1;
  }
}
#endif

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

int
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

secp256k1_nif_state *
secp256k1_nif_state_create(void)
{
  secp256k1_nif_state *state = NULL;
  unsigned char randomize[CONTEXT_SEED_SIZE] = {0};
  int success = 0;

  state = enif_alloc(sizeof(*state));
  if (!state) {
    goto cleanup;
  }
  memset(state, 0, sizeof(*state));

  /*
   * Allocate the context with enif_alloc so that running out of memory fails
   * the load instead of aborting the VM (secp256k1_context_create aborts).
   */
  state->ctx_memory = enif_alloc(secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE));
  if (!state->ctx_memory) {
    goto cleanup;
  }
  /*
   * Upstream runs its self-test here and reports a failure through the default
   * error callback, which aborts: a library failing its self-test is
   * miscompiled and must not be used.
   */
  state->ctx = secp256k1_context_preallocated_create(state->ctx_memory, SECP256K1_CONTEXT_NONE);
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
    secp256k1_context_preallocated_destroy(state->ctx);
  }
  if (state->ctx_memory) {
    enif_free(state->ctx_memory);
  }
  enif_free(state);
}

ERL_NIF_TERM
allocation_failed(ErlNifEnv *env)
{
  return enif_make_tuple2(
    env,
    enif_make_atom(env, "error"),
    enif_make_atom(env, "allocation_failed")
  );
}

ERL_NIF_TERM
error_result(ErlNifEnv *env, const char *error_msg)
{
  ERL_NIF_TERM reason;

  if (!make_binary(env, (const unsigned char *)error_msg, strlen(error_msg), &reason)) {
    return allocation_failed(env);
  }

  return enif_make_tuple2(env, enif_make_atom(env, "error"), reason);
}

int
get_seckey(ErlNifEnv *env, ERL_NIF_TERM term, ErlNifBinary *seckey)
{
  return enif_inspect_binary(env, term, seckey) && seckey->size == SECKEY_SIZE &&
         secp256k1_ec_seckey_verify(nif_ctx(env), seckey->data);
}

int
get_keypair(ErlNifEnv *env, ERL_NIF_TERM term, secp256k1_keypair *keypair, ERL_NIF_TERM *result)
{
  ErlNifBinary seckey;

  if (!get_seckey(env, term, &seckey)) {
    *result = enif_make_badarg(env);
    return 0;
  }
  if (!secp256k1_keypair_create(nif_ctx(env), keypair, seckey.data)) {
    secure_erase(keypair, sizeof(*keypair));
    *result = error_result(env, "secp256k1_keypair_create failed");
    return 0;
  }
  return 1;
}
