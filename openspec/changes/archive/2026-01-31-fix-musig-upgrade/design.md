## Context

The NIF lifecycle uses shared helpers in `c_src/utils.h`. The current `upgrade()` function is a no-op, so hot upgrades do not reinitialize the `secp256k1_context`. MuSig additionally defines a `secnonce_resource` type in `musig_load()`, but on upgrade the resource type is never taken over. A hot upgrade can therefore leave `ctx` unset and resource types invalid, leading to undefined behavior.

## Goals / Non-Goals

**Goals:**

- Ensure hot upgrades reinitialize `secp256k1_context` for all NIF modules.
- Ensure MuSig upgrades take over the `secnonce_resource` type so existing resources remain valid.
- Keep behavior unchanged for cold restart workflows.

**Non-Goals:**

- Changing cryptographic behavior or public Elixir APIs.
- Adding comprehensive hot-upgrade tests in this change.

## Decisions

- **Recreate context in upgrade (utils.h).**
  - **Decision:** Implement `upgrade()` to mirror `load()` by creating and randomizing a new `secp256k1_context`.
  - **Alternatives:** Return `-1` to disallow hot upgrade; attempt to share old `ctx` across module versions.
  - **Rationale:** Safe, minimal change that aligns with `load()` behavior and prevents null context use.

- **Add MuSig-specific upgrade handler.**
  - **Decision:** Implement `musig_upgrade()` to call `upgrade()` and then call `enif_open_resource_type(..., ERL_NIF_RT_TAKEOVER, ...)` for `secnonce_resource`.
  - **Alternatives:** Rely on `musig_load()` (not called on upgrade); abandon resource takeover and invalidate old resources.
  - **Rationale:** Standard NIF pattern for resource takeover with minimal code changes.

- **Preserve resource layout and name.**
  - **Decision:** Keep `secnonce_wrapper` layout unchanged and resource type name stable.
  - **Alternatives:** Bump resource type name to invalidate old resources on upgrade.
  - **Rationale:** Allows safe takeover of existing resources and preserves hot-upgrade continuity.

## Risks / Trade-offs

- **[Resource layout changes in the future] → Mitigation:** Document the layout constraint and require a new resource type name if the struct changes.
- **[Upgrade failure due to RNG or allocation] → Mitigation:** Return `-1` to abort upgrade, preserving existing module.

## Migration Plan

- No data migration required.
- Deploy as a normal code upgrade; BEAM hot upgrade becomes safe.
- Rollback by reverting the module or restarting the VM.

## Open Questions

- None.
