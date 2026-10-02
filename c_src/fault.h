#ifndef SECP256K1_NIF_FAULT_H
#define SECP256K1_NIF_FAULT_H

/*
 * Test-only fault injection, compiled only with -DSECP256K1_NIF_FAULT_INJECTION.
 * Normal builds contain none of this code.
 *
 * Every first-party enif_alloc, enif_alloc_binary, enif_alloc_resource,
 * enif_mutex_create, and fill_random call is a fault point. After
 * fault_arm(n) the nth fault point hit on the calling thread fails (returns
 * NULL or 0); every other point passes. Fault points are counted and the net
 * number of enif_alloc minus enif_free calls is tracked per thread, so a test
 * NIF that arms, calls a NIF body, and disarms on one thread sees only that
 * call. Live MuSig resources are counted globally.
 */

#ifdef SECP256K1_NIF_FAULT_INJECTION

#include <stddef.h>

#include <erl_nif.h>

typedef enum {
  FAULT_RESOURCE_KEYAGG_CACHE,
  FAULT_RESOURCE_SESSION,
  FAULT_RESOURCE_SECNONCE,
  FAULT_RESOURCE_KINDS
} fault_resource_kind;

typedef struct {
  /* Fault points hit since fault_arm. */
  unsigned long hits;
  /* enif_alloc minus enif_free calls since fault_arm. */
  long net_allocs;
  /* Name of the fault point that failed, or NULL. */
  const char *failed;
} fault_stats;

/* Fails the `fail_at`th fault point from now on this thread; 0 fails none. */
void fault_arm(unsigned long fail_at);
/* Stops failing fault points and returns what this thread saw since fault_arm. */
fault_stats fault_disarm(void);
/* Counts a fault point named `name`; returns 1 when it must fail. */
int fault_point(const char *name);

void *fault_enif_alloc(size_t size);
void fault_enif_free(void *ptr);
int fault_enif_alloc_binary(size_t size, ErlNifBinary *bin);
void *fault_enif_alloc_resource(ErlNifResourceType *type, size_t size);
ErlNifMutex *fault_enif_mutex_create(char *name);

void fault_resource_live(fault_resource_kind kind, long delta);
long fault_resource_count(fault_resource_kind kind);

/* Sets the libsecp256k1 callback flag as if the callback had fired. */
void callback_fire(int internal);

#define enif_alloc(size) fault_enif_alloc(size)
#define enif_free(ptr) fault_enif_free(ptr)
#define enif_alloc_binary(size, bin) fault_enif_alloc_binary(size, bin)
#define enif_alloc_resource(type, size) fault_enif_alloc_resource(type, size)
#define enif_mutex_create(name) fault_enif_mutex_create(name)

#define FAULT_RESOURCE_LIVE(kind, delta) fault_resource_live(kind, delta)

#else

#define FAULT_RESOURCE_LIVE(kind, delta) ((void)0)

#endif

#endif
