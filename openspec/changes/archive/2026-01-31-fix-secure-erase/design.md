## Context

The current `secure_erase` function in `c_src/utils.h` uses a volatile pointer cast:

```c
volatile unsigned char *p = (volatile unsigned char *)ptr;
while (len--) { *p++ = 0; }
```

This pattern is widely used but unreliable. Compilers can argue the underlying memory isn't volatile, only the pointer is, and optimize away the zeroing as a dead store.

The secp256k1 library provides a battle-tested implementation in their examples (`examples/examples_util.h`) using memory barriers, which is the same technique used by the Linux kernel's `memzero_explicit()`.

## Goals / Non-Goals

**Goals:**

- Replace weak volatile pointer technique with proven memory barrier approach
- Match the implementation recommended by secp256k1 maintainers
- Add Windows support for future portability

**Non-Goals:**

- Adding platform detection for `explicit_bzero` / `memset_s` (unnecessary complexity)
- Changing the function signature or call sites

## Decisions

### Use secp256k1's recommended implementation

**Decision**: Copy the `secure_erase` from `c_src/secp256k1/examples/examples_util.h`

**Rationale**:

- CC0 licensed (public domain)
- Same technique as Linux kernel `memzero_explicit()`
- Proven in production crypto code
- Drop-in replacement (same function name)

**Alternatives considered**:

- `explicit_bzero`: Requires glibc 2.25+, needs feature detection
- `memset_s`: C11 Annex K is optional, glibc doesn't implement it
- Keep current with improvements: No reliable improvement without memory barriers

### Three-tier platform support

```c
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);           // Windows: MS-guaranteed
#elif defined(__GNUC__)
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");  // GCC/Clang: barrier
#else
    volatile function pointer to memset   // Fallback: indirect call
#endif
```

**Rationale**: GCC/Clang covers Linux, macOS, BSDs. MSVC covers Windows. Fallback handles exotic compilers.

## Risks / Trade-offs

**[Minimal risk]** The volatile function pointer fallback is stronger than current implementation but still not guaranteed by the C standard.
→ Acceptable because all realistic targets use GCC, Clang, or MSVC.

**[None]** No API changes, no behavioral changes visible to callers.
