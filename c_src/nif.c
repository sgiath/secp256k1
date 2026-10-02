#include "utils.h"
#include "nifs.h"

#ifdef SECP256K1_NIF_FAULT_INJECTION
#include <stdlib.h>
#include <string.h>
#endif

/*
 * Applies the libsecp256k1 callback contract after a NIF body ran: an
 * illegal-argument callback raises badarg, an internal-error callback returns
 * an error tuple. The NIF result is discarded in both cases unless the NIF
 * already raised an exception, which must be returned as is.
 */
static ERL_NIF_TERM
guard_result(ErlNifEnv *env, ERL_NIF_TERM result)
{
  int illegal = callback_illegal_fired();
  int internal = callback_internal_fired();

  if ((!illegal && !internal) || enif_is_exception(env, result)) {
    return result;
  }
  if (illegal) {
    return enif_make_badarg(env);
  }
  return error_result(env, "libsecp256k1 internal error");
}

#define SECP256K1_NIF_GUARDED(erl_name, fn, arity, flags)                               \
  static ERL_NIF_TERM guarded_##fn(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) \
  {                                                                                     \
    ERL_NIF_TERM result;                                                                \
    callback_flags_clear();                                                             \
    result = secp256k1_nif_##fn(env, argc, argv);                                       \
    return guard_result(env, result);                                                   \
  }

SECP256K1_NIF_LIST(SECP256K1_NIF_GUARDED, SECP256K1_NIF_SKIP)

#define SECP256K1_NIF_ENTRY(erl_name, fn, arity, flags) {erl_name, arity, guarded_##fn, flags},

static int
load_state(ErlNifEnv *env, void **priv_data)
{
  secp256k1_nif_state *state;

  callback_flags_clear();
  state = secp256k1_nif_state_create();
  if (!state) {
    return -1;
  }

  if (!musig_open_resource_types(env, state) || callback_illegal_fired() ||
      callback_internal_fired()) {
    secp256k1_nif_state_destroy(state);
    return -1;
  }

  *priv_data = state;
  return 0;
}

#ifdef SECP256K1_NIF_FAULT_INJECTION

/* Test-only NIFs driving the fault-injection harness (fault.h). */

#define FAULT_MAX_ARITY 5

typedef struct {
  const char *name;
  int arity;
  ERL_NIF_TERM (*body)(ErlNifEnv *, int, const ERL_NIF_TERM[]);
  ERL_NIF_TERM (*guarded)(ErlNifEnv *, int, const ERL_NIF_TERM[]);
} fault_target;

#define FAULT_TARGET(erl_name, fn, arity, flags) \
  {erl_name, arity, secp256k1_nif_##fn, guarded_##fn},

static const fault_target fault_targets[] = {SECP256K1_NIF_LIST(FAULT_TARGET, FAULT_TARGET)};

/*
 * Finds the registered NIF named by the atom `name` whose arity is the length
 * of the list `args`, and copies the list into `argv`.
 */
static const fault_target *
fault_lookup(ErlNifEnv *env, ERL_NIF_TERM name, ERL_NIF_TERM args, ERL_NIF_TERM argv[])
{
  char name_buf[64];
  unsigned int argc;
  unsigned int i;

  if (!enif_get_atom(env, name, name_buf, sizeof(name_buf), ERL_NIF_LATIN1) ||
      !enif_get_list_length(env, args, &argc) || argc > FAULT_MAX_ARITY) {
    return NULL;
  }
  for (i = 0; i < argc; i++) {
    enif_get_list_cell(env, args, &argv[i], &args);
  }
  for (i = 0; i < sizeof(fault_targets) / sizeof(fault_targets[0]); i++) {
    if (fault_targets[i].arity == (int)argc && strcmp(fault_targets[i].name, name_buf) == 0) {
      return &fault_targets[i];
    }
  }
  return NULL;
}

/*
 * fault_call(fail_at, name, args) calls the guarded NIF `name` with the
 * fail_at-th fault point failing (0: none) and returns its result or raises
 * its exception. It first sends {secp256k1_fault, hits, net_allocs, failed}
 * to the caller, where `failed` names the failed fault point or is nil.
 */
static ERL_NIF_TERM
fault_call(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM args[FAULT_MAX_ARITY];
  const fault_target *target;
  unsigned long fail_at;
  ERL_NIF_TERM result;
  ERL_NIF_TERM stats_term;
  fault_stats stats;
  ErlNifPid self;

  (void)argc;

  target = fault_lookup(env, argv[1], argv[2], args);
  if (!enif_get_ulong(env, argv[0], &fail_at) || !target) {
    return enif_make_badarg(env);
  }

  fault_arm(fail_at);
  result = target->guarded(env, target->arity, args);
  stats = fault_disarm();

  stats_term = enif_make_tuple4(
    env,
    enif_make_atom(env, "secp256k1_fault"),
    enif_make_ulong(env, stats.hits),
    enif_make_long(env, stats.net_allocs),
    enif_make_atom(env, stats.failed ? stats.failed : "nil")
  );
  enif_send(env, enif_self(env, &self), NULL, stats_term);
  return result;
}

/*
 * fault_call_with_callback(kind, name, args) runs the raw NIF body, then
 * fires the :illegal or :internal libsecp256k1 callback flag, then applies the
 * callback guard to the body's result.
 */
static ERL_NIF_TERM
fault_call_with_callback(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM args[FAULT_MAX_ARITY];
  const fault_target *target;
  int internal = enif_is_identical(argv[0], enif_make_atom(env, "internal"));
  ERL_NIF_TERM result;

  (void)argc;

  target = fault_lookup(env, argv[1], argv[2], args);
  if (!target || (!internal && !enif_is_identical(argv[0], enif_make_atom(env, "illegal")))) {
    return enif_make_badarg(env);
  }

  callback_flags_clear();
  result = target->body(env, target->arity, args);
  callback_fire(internal);
  return guard_result(env, result);
}

/* fault_live_resources() returns the live MuSig resources of each type. */
static ERL_NIF_TERM
fault_live_resources(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM keys[FAULT_RESOURCE_KINDS];
  ERL_NIF_TERM values[FAULT_RESOURCE_KINDS];
  ERL_NIF_TERM map;
  int kind;

  (void)argc;
  (void)argv;

  keys[FAULT_RESOURCE_KEYAGG_CACHE] = enif_make_atom(env, "keyagg_cache");
  keys[FAULT_RESOURCE_SESSION] = enif_make_atom(env, "session");
  keys[FAULT_RESOURCE_SECNONCE] = enif_make_atom(env, "secnonce");
  for (kind = 0; kind < FAULT_RESOURCE_KINDS; kind++) {
    values[kind] = enif_make_long(env, fault_resource_count((fault_resource_kind)kind));
  }
  enif_make_map_from_arrays(env, keys, values, FAULT_RESOURCE_KINDS, &map);
  return map;
}

/*
 * Loads with the fault point SECP256K1_NIF_FAULT_LOAD names (a decimal
 * count, unset: none) failing. A failed load that leaves first-party
 * allocations behind aborts, so a test can detect the leak in a child BEAM.
 */
static int
fault_load_state(ErlNifEnv *env, void **priv_data)
{
  char value[32];
  size_t size = sizeof(value);
  unsigned long fail_at = 0;
  fault_stats stats;
  int status;

  if (enif_getenv("SECP256K1_NIF_FAULT_LOAD", value, &size) == 0) {
    fail_at = strtoul(value, NULL, 10);
  }

  fault_arm(fail_at);
  status = load_state(env, priv_data);
  stats = fault_disarm();

  if (status != 0 && stats.net_allocs != 0) {
    abort();
  }
  return status;
}

#define FAULT_NIF_ENTRIES                                                                         \
  {"fault_call", 3, fault_call, 0}, {"fault_call_with_callback", 3, fault_call_with_callback, 0}, \
    {"fault_live_resources", 0, fault_live_resources, 0},

#else

#define FAULT_NIF_ENTRIES

#endif

static ErlNifFunc nif_funcs[] = {SECP256K1_NIF_LIST(SECP256K1_NIF_ENTRY, SECP256K1_NIF_ENTRY)
                                   FAULT_NIF_ENTRIES};

static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
  (void)load_info;
#ifdef SECP256K1_NIF_FAULT_INJECTION
  return fault_load_state(env, priv_data);
#else
  return load_state(env, priv_data);
#endif
}

static int
upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
  (void)old_priv_data;
  return load(env, priv_data, load_info);
}

static void
unload(ErlNifEnv *env, void *priv_data)
{
  (void)env;
  secp256k1_nif_state_destroy(priv_data);
}

ERL_NIF_INIT(Elixir.Secp256k1.NIF, nif_funcs, &load, NULL, &upgrade, &unload)
