## Why

Both `utils.h` and `random.h` lack include guards. While the current architecture (each NIF compiles to a separate `.so`) prevents double-inclusion issues today, missing guards violate C conventions and create fragility for future refactoring.

## What Changes

- Add `#ifndef`/`#define`/`#endif` include guards to `c_src/utils.h`
- Add `#ifndef`/`#define`/`#endif` include guards to `c_src/random.h`

## Capabilities

### New Capabilities

None - this is an internal code quality fix with no behavioral changes.

### Modified Capabilities

None - include guards don't change any requirements or behavior.

## Impact

- `c_src/utils.h` - wrapped with `SECP256K1_NIF_UTILS_H` guard
- `c_src/random.h` - wrapped with `SECP256K1_NIF_RANDOM_H` guard
- No runtime behavior changes
- No API changes
