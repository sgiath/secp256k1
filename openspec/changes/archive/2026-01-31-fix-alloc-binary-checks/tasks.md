## 1. Fix error_result() in utils.h

- [x] 1.1 Add allocation check with atom fallback in `error_result()` (L55)
- [x] 1.2 Return `{:error, :allocation_failed}` directly at each `enif_alloc_binary()` failure site

## 2. Fix single-allocation sites in musig.c

- [x] 2.1 Add check in `pubkey_get()` (L137)
- [x] 2.2 Add check in `nonce_process()` (L378)
- [x] 2.3 Add check in `partial_sig_agg()` (L523)

## 3. Fix cascade-cleanup sites in musig.c

- [x] 3.1 Add checks in `pubkey_agg()` (L96, L99) with cleanup on second failure
- [x] 3.2 Add checks in `pubkey_ec_tweak_add()` (L167, L170) with cleanup on second failure
- [x] 3.3 Add checks in `pubkey_xonly_tweak_add()` (L204, L207) with cleanup on second failure

## 4. Fix leak-on-error sites in musig.c

- [x] 4.1 Add check and release in `nonce_gen()` (L285) - release before serialize error return
- [x] 4.2 Add check and release in `nonce_agg()` (L340) - release before serialize error return
- [x] 4.3 Add check and release in `partial_sign()` (L427) - release before serialize error return

## 5. Verify

- [x] 5.1 Run `mix compile` to ensure NIF compiles without errors
- [x] 5.2 Run `mix test` to ensure existing tests still pass
