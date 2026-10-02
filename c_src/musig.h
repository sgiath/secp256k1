#ifndef SECP256K1_NIF_MUSIG_H
#define SECP256K1_NIF_MUSIG_H

#include "utils.h"

#include <secp256k1_musig.h>

/*
 * Resource type names carry this ABI version. An upgraded NIF instance takes
 * over resources only from a library with the same version, so it never runs
 * its destructors or accessors on a wrapper with a different layout. After an
 * upgrade across versions, older resources stay owned by the old library and
 * fail get_* (ArgumentError). Bump this whenever a wrapper struct below
 * changes or the vendored libsecp256k1 version changes (upstream MuSig opaque
 * types are not portable between versions). Version 1 (lib_secp256k1 0.8.0
 * and earlier) used unversioned names.
 */
#define MUSIG_RESOURCE_ABI "2"

typedef struct {
  secp256k1_musig_keyagg_cache cache;
} keyagg_cache_wrapper;

/*
 * Signing session plus the transcript it was processed from: a copy of the
 * keyagg cache and the message given to nonce_process. All fields are
 * immutable after creation. partial_sign and partial_sig_verify reject a cache
 * whose bytes differ from `cache`.
 */
typedef struct {
  secp256k1_musig_session session;
  secp256k1_musig_keyagg_cache cache;
  unsigned char msg[HASH_SIZE];
} session_wrapper;

/*
 * One-use secret nonce. `pubkey` is the signer public key given to nonce_gen;
 * `msg` (when `has_msg`) and `cache` (when `has_cache`) are copies of the
 * optional message and keyagg cache given to nonce_gen. partial_sign refuses
 * (and consumes the nonce) when the signing key, the session message, or the
 * cache differs from these. `used` is guarded by `mutex`; every other field is
 * immutable until the thread that flips `used` erases `nonce`.
 */
typedef struct {
  secp256k1_musig_secnonce nonce;
  secp256k1_pubkey pubkey;
  secp256k1_musig_keyagg_cache cache;
  unsigned char msg[HASH_SIZE];
  int has_cache;
  int has_msg;
  ErlNifMutex *mutex;
  int used;
} secnonce_wrapper;

int make_keyagg_cache_resource(
  ErlNifEnv *env,
  const secp256k1_musig_keyagg_cache *cache,
  ERL_NIF_TERM *term
);
int make_session_resource(
  ErlNifEnv *env,
  const secp256k1_musig_session *session,
  const secp256k1_musig_keyagg_cache *cache,
  const unsigned char *msg,
  ERL_NIF_TERM *term
);
/* `msg` and `cache` may be NULL when nonce_gen was called without them. */
int make_secnonce_resource(
  ErlNifEnv *env,
  const secp256k1_musig_secnonce *nonce,
  const secp256k1_pubkey *pubkey,
  const unsigned char *msg,
  const secp256k1_musig_keyagg_cache *cache,
  ERL_NIF_TERM *term
);

int get_keyagg_cache(ErlNifEnv *env, ERL_NIF_TERM term, keyagg_cache_wrapper **wrapper);
int get_session(ErlNifEnv *env, ERL_NIF_TERM term, session_wrapper **wrapper);
int get_secnonce(ErlNifEnv *env, ERL_NIF_TERM term, secnonce_wrapper **wrapper);

/* Compares the opaque cache bytes; caches built from the same inputs are equal. */
int
keyagg_cache_equal(const secp256k1_musig_keyagg_cache *a, const secp256k1_musig_keyagg_cache *b);

/*
 * Allocates, in one block, an array of `count` pointers of `ptr_size` bytes
 * followed by `count` elements of `elem_size` bytes, the layout upstream MuSig
 * aggregation functions take. Returns the pointer array and stores the element
 * array in *elems; freeing the pointer array with enif_free frees both. Returns
 * NULL on size overflow or allocation failure.
 */
void *musig_alloc_list(unsigned int count, size_t ptr_size, size_t elem_size, void **elems);

#endif
