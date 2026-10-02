#ifndef SECP256K1_NIF_MUSIG_H
#define SECP256K1_NIF_MUSIG_H

#include "utils.h"

#include <secp256k1_musig.h>

#define MUSIG_PUBNONCE_SERIALIZED_SIZE 66
#define MUSIG_AGGNONCE_SERIALIZED_SIZE 66
#define MUSIG_PARTIAL_SIG_SERIALIZED_SIZE 32

typedef struct {
  secp256k1_musig_keyagg_cache cache;
} keyagg_cache_wrapper;

typedef struct {
  secp256k1_musig_session session;
} session_wrapper;

/*
 * One-use secret nonce. `pubkey` is the signer public key given to nonce_gen;
 * partial_sign refuses (and consumes the nonce) when the signing key differs.
 * `used` is guarded by `mutex`; `nonce` and `pubkey` are immutable until the
 * thread that flips `used` erases `nonce`.
 */
typedef struct {
  secp256k1_musig_secnonce nonce;
  secp256k1_pubkey pubkey;
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
  ERL_NIF_TERM *term
);
int make_secnonce_resource(
  ErlNifEnv *env,
  const secp256k1_musig_secnonce *nonce,
  const secp256k1_pubkey *pubkey,
  ERL_NIF_TERM *term
);

int get_keyagg_cache(ErlNifEnv *env, ERL_NIF_TERM term, keyagg_cache_wrapper **wrapper);
int get_session(ErlNifEnv *env, ERL_NIF_TERM term, session_wrapper **wrapper);
int get_secnonce(ErlNifEnv *env, ERL_NIF_TERM term, secnonce_wrapper **wrapper);

/* Allocates `count` elements of `size` bytes; NULL on overflow or allocation failure. */
void *musig_alloc_array(unsigned int count, size_t size);

#endif
