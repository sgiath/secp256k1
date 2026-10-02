#include "utils.h"

#ifdef SECP256K1_NIF_FAULT_INJECTION

/*
 * The wrappers call the real functions through parenthesized names, which the
 * function-like macros in fault.h do not expand.
 */

static __thread unsigned long fault_fail_at;
static __thread fault_stats fault_current;

static long fault_live[FAULT_RESOURCE_KINDS];

void
fault_arm(unsigned long fail_at)
{
  fault_fail_at = fail_at;
  fault_current.hits = 0;
  fault_current.net_allocs = 0;
  fault_current.failed = NULL;
}

fault_stats
fault_disarm(void)
{
  fault_fail_at = 0;
  return fault_current;
}

int
fault_point(const char *name)
{
  fault_current.hits++;
  if (fault_current.hits != fault_fail_at) {
    return 0;
  }
  fault_current.failed = name;
  return 1;
}

void *
fault_enif_alloc(size_t size)
{
  void *ptr;

  if (fault_point("enif_alloc")) {
    return NULL;
  }
  ptr = (enif_alloc)(size);
  if (ptr) {
    fault_current.net_allocs++;
  }
  return ptr;
}

void
fault_enif_free(void *ptr)
{
  if (ptr) {
    fault_current.net_allocs--;
  }
  (enif_free)(ptr);
}

int
fault_enif_alloc_binary(size_t size, ErlNifBinary *bin)
{
  if (fault_point("enif_alloc_binary")) {
    return 0;
  }
  return (enif_alloc_binary)(size, bin);
}

void *
fault_enif_alloc_resource(ErlNifResourceType *type, size_t size)
{
  if (fault_point("enif_alloc_resource")) {
    return NULL;
  }
  return (enif_alloc_resource)(type, size);
}

ErlNifMutex *
fault_enif_mutex_create(char *name)
{
  if (fault_point("enif_mutex_create")) {
    return NULL;
  }
  return (enif_mutex_create)(name);
}

void
fault_resource_live(fault_resource_kind kind, long delta)
{
  __atomic_add_fetch(&fault_live[kind], delta, __ATOMIC_SEQ_CST);
}

long
fault_resource_count(fault_resource_kind kind)
{
  return __atomic_load_n(&fault_live[kind], __ATOMIC_SEQ_CST);
}

#endif
