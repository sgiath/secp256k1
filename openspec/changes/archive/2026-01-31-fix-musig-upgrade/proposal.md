## Why

Hot upgrades of the NIF currently leave critical state uninitialized: the shared `secp256k1_context` is never recreated and MuSig resource types are not taken over. This can lead to undefined behavior or crashes if a hot upgrade is ever performed. Fixing this closes a correctness gap and makes the library safer under upgrade scenarios.

## What Changes

- Initialize `secp256k1_context` during NIF upgrade (same behavior as load) so upgraded modules have a valid context.
- Add a MuSig-specific upgrade path that takes over the `secnonce_resource` type.
- Use the MuSig upgrade handler in NIF initialization to ensure resource takeover is executed.

## Capabilities

### New Capabilities

- `nif-hot-upgrade`: NIF modules support safe hot upgrades by recreating context and taking over resource types where applicable.

### Modified Capabilities

-

## Impact

- `c_src/utils.h`: upgrade lifecycle logic for all NIF modules.
- `c_src/musig.c`: resource type takeover and NIF init wiring.
- Hot upgrade behavior for existing deployments (no change for cold restart workflows).
