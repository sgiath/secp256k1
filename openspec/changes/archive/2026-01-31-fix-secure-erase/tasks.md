## 1. Update secure_erase Implementation

- [x] 1.1 Add Windows header include guard for SecureZeroMemory
- [x] 1.2 Replace secure_erase function with secp256k1's recommended implementation

## 2. Verify

- [x] 2.1 Run `mix compile` to ensure NIF compiles successfully
- [x] 2.2 Run `mix test` to verify functionality unchanged
