## ADDED Requirements

### Requirement: NIF allocation failures return error tuples

All NIF functions SHALL check the return value of `enif_alloc_binary()` and return an error tuple if allocation fails, rather than causing undefined behavior.

#### Scenario: Allocation failure in normal NIF function

- **WHEN** `enif_alloc_binary()` fails during NIF execution
- **THEN** the function returns `{:error, :allocation_failed}`

#### Scenario: Allocation failure in error_result helper

- **WHEN** `enif_alloc_binary()` fails inside `error_result()`
- **THEN** the function returns `{:error, :allocation_failed}` using atoms

### Requirement: NIF error paths release allocated resources

All NIF functions SHALL release any previously allocated binaries before returning an error, preventing memory leaks.

#### Scenario: Subsequent operation fails after allocation

- **WHEN** a binary is allocated successfully but a subsequent operation fails
- **THEN** `enif_release_binary()` is called before returning the error
