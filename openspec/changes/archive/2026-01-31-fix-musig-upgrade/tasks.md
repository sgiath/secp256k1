## 1. Upgrade Lifecycle

- [x] 1.1 Implement `upgrade()` in `c_src/utils.h` to create and randomize `secp256k1_context`
- [x] 1.2 Ensure upgrade failure paths return `-1` and clean up any allocated context

## 2. MuSig Resource Takeover

- [x] 2.1 Add `musig_upgrade()` in `c_src/musig.c` that calls `upgrade()` then takes over `secnonce_resource`
- [x] 2.2 Wire `ERL_NIF_INIT` in `c_src/musig.c` to use `musig_upgrade`

## 3. Verification

- [x] 3.1 Compile NIFs (e.g., `mix compile`) to confirm upgrade changes build cleanly
