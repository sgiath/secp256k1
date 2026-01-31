## Why

The current `secure_erase` function in `utils.h` uses a volatile pointer cast that compilers may optimize away, leaving sensitive data (private keys, nonces) in memory. This is a security risk for cryptographic code.

## What Changes

- Replace the volatile pointer loop with secp256k1's recommended implementation using memory barriers
- Add Windows support via `SecureZeroMemory` for future portability
- Use volatile function pointer as fallback for non-GCC/MSVC compilers

## Capabilities

### New Capabilities

None - this is an internal implementation fix.

### Modified Capabilities

None - no requirement changes, only implementation hardening.

## Impact

- `c_src/utils.h`: Replace `secure_erase` function
- All NIF modules benefit (ecdsa, schnorr, musig, extrakeys, ecdh) without code changes
