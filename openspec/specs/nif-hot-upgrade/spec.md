## Requirements

### Requirement: Upgrade initializes secp256k1 context

During a hot upgrade, the NIF module SHALL create and randomize a new `secp256k1_context` before any exported NIF function uses it.

#### Scenario: Successful hot upgrade reinitializes context

- **WHEN** the BEAM hot-upgrades a secp256k1 NIF module
- **THEN** the upgraded module has a valid, randomized `secp256k1_context` available for all NIF calls

### Requirement: MuSig resource types are taken over on upgrade

During a hot upgrade of the MuSig NIF, the module SHALL take over the `secnonce_resource` type so existing resources remain valid in the upgraded module.

#### Scenario: Pre-upgrade secnonce resources remain usable

- **WHEN** a `secnonce_resource` created before upgrade is used after upgrade
- **THEN** the resource is accepted by the MuSig NIF without a type mismatch
