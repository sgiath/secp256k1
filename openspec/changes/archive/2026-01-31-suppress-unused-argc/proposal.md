## Why

All NIF functions receive an `argc` parameter that is never used (arity is declared in the function registration table). This can cause compiler warnings when building with `-Wextra` or strict Clang settings. The secp256k1 library itself uses `(void)arg;` to suppress such warnings - we should follow the same pattern for consistency.

## What Changes

- Add `(void)argc;` statement at the start of all 21 NIF functions across 5 C source files
- Follows the same pattern used by the upstream secp256k1 library

## Capabilities

### New Capabilities

None - this is a code quality improvement with no behavior change.

### Modified Capabilities

None - no specification-level changes.

## Impact

- `c_src/ecdsa.c` - 6 functions
- `c_src/schnorrsig.c` - 3 functions
- `c_src/extrakeys.c` - 1 function
- `c_src/ecdh.c` - 1 function
- `c_src/musig.c` - 10 functions

No API changes. No behavior changes. Pure code hygiene.
