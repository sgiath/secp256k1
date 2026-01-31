## Why

`enif_alloc_binary()` can fail under memory pressure but its return value is never checked throughout the NIF codebase. This leads to undefined behavior (writing to uninitialized pointers) and potential VM crashes. Additionally, some error paths leak allocated binaries.

## What Changes

- Add return value checks to all `enif_alloc_binary()` calls in `utils.h` and `musig.c`
- Fix memory leaks on error paths where binaries are allocated but not released before early return
- Update `error_result()` in `utils.h` to use atom fallback when allocation fails (can't call itself recursively)

## Capabilities

### New Capabilities

None - this is a bug fix, not a new feature.

### Modified Capabilities

None - external behavior unchanged; functions still return `{:error, reason}` tuples, they just won't crash on allocation failure.

## Impact

- `c_src/utils.h`: `error_result()` function (1 site)
- `c_src/musig.c`: 12 call sites across 9 functions
  - `pubkey_agg()`, `pubkey_get()`, `pubkey_ec_tweak_add()`, `pubkey_xonly_tweak_add()`
  - `nonce_gen()`, `nonce_agg()`, `nonce_process()`
  - `partial_sign()`, `partial_sig_agg()`
