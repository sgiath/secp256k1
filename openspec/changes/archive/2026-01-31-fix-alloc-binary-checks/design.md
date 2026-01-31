## Context

The NIF codebase uses `enif_alloc_binary()` to allocate memory for binary data returned to Erlang. This function can fail under memory pressure, returning 0. Currently, no call sites check this return value - they immediately `memcpy()` to `bin.data`, which is undefined behavior if allocation failed.

Additionally, several error paths in `musig.c` leak already-allocated binaries when a subsequent operation fails.

## Goals / Non-Goals

**Goals:**

- Prevent undefined behavior from unchecked allocation failures
- Fix memory leaks on error paths
- Keep changes minimal and focused on the specific issue

**Non-Goals:**

- Refactoring the overall error handling pattern
- Adding macros or abstractions (explicit checks preferred)
- Changing external API behavior

## Decisions

### Decision 1: Explicit local checks over helper macro

**Choice**: Add `if (!enif_alloc_binary(...))` checks at each call site.

**Rationale**: While a macro would reduce boilerplate, it hides control flow (`return` inside macro). For security-critical code, explicit is better. 13 call sites is manageable.

**Alternatives considered**:

- Helper macro `ALLOC_BINARY_OR_FAIL(size, bin)` - rejected due to hidden return

### Decision 2: Atom return on allocation failure

**Choice**: Whenever `enif_alloc_binary()` fails, return `{:error, :allocation_failed}` directly at the call site. `error_result()` should also use this atom fallback if its own allocation fails.

**Rationale**:

- Avoids any further allocations on a low-memory path
- Keeps the behavior consistent across all call sites
- Keeps error recoverable on Elixir side (vs raising exception which would crash VM)

**Alternatives considered**:

- `enif_raise_exception()` - rejected because NIFs crashing the VM is catastrophic

### Decision 3: Allocation failures use atom, not message

**Choice**: Allocation failures return `{:error, :allocation_failed}` with no message payload.

**Rationale**: Message allocation is unsafe when allocation already failed; the atom is sufficient for callers to branch on failure.

## Risks / Trade-offs

**[Risk]** Cascade cleanup ordering errors  
→ Careful attention to release order; functions allocate at most 2 binaries

**[Risk]** Missing a call site  
→ TODO.md lists all 13 sites; verify each is addressed

**[Trade-off]** More verbose code  
→ Acceptable for explicit error handling in security-critical NIF code
