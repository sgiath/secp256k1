## Context

The NIF headers `utils.h` and `random.h` lack standard C include guards. While the current build (separate `.so` per NIF) prevents double-inclusion issues, this violates C conventions and creates fragility.

## Goals / Non-Goals

**Goals:**

- Add include guards to both header files
- Follow standard C naming conventions for guards

**Non-Goals:**

- Consolidating NIFs into a shared context (separate issue #8 in TODO.md)
- Changing the build architecture

## Decisions

### Guard naming convention

Use `SECP256K1_NIF_<FILENAME>_H` pattern:

- `utils.h``SECP256K1_NIF_UTILS_H`
- `random.h``SECP256K1_NIF_RANDOM_H`

**Rationale**: Follows common convention of `PROJECT_FILENAME_H`, prefixed with project name to avoid collisions.

**Alternatives considered**:

- `__UTILS_H__` - Reserved identifiers (double underscore), not portable
- `UTILS_H` - Too generic, collision risk

## Risks / Trade-offs

None. Include guards are zero-cost and purely additive.
