## Context

NIF functions in Erlang have a required signature:

```c
ERL_NIF_TERM func(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
```

The `argc` parameter is always passed but never used in this codebase - arity is declared in the function registration table. The upstream secp256k1 library uses `(void)arg;` to suppress warnings about unused parameters.

## Goals / Non-Goals

**Goals:**

- Suppress compiler warnings when building with `-Wextra` or strict Clang settings
- Follow the same pattern as the upstream secp256k1 library

**Non-Goals:**

- Changing function signatures or behavior
- Refactoring NIF function structure

## Decisions

### Use `(void)argc;` pattern

**Choice**: Add `(void)argc;` as the first statement in each NIF function body.

**Alternatives considered**:

- `__attribute__((unused))` in signature - GCC/Clang specific, not portable
- `UNUSED(argc)` macro - adds indirection, more infrastructure
- Do nothing - leaves potential warnings with `-Wextra`

**Rationale**: Portable C, matches upstream library pattern, simple and grep-able.

## Risks / Trade-offs

No risks. This is a mechanical change with no behavior impact.
