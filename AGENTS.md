# Secp256k1 Library - Agent Guidelines

Elixir NIF bindings for Bitcoin's secp256k1 cryptographic library. Implements ECDSA, Schnorr (BIP340), and MuSig2 (BIP327) signatures.

## Build Commands

```bash
mix deps.get              # fetch dependencies
mix compile               # compile elixir + C NIFs (uses elixir_make)
mix test                  # run all tests
mix test path/to/test.exs # run specific test file
mix check                 # run all checks (compiler, formatter, credo, tests)
```

### Clean/Rebuild

```bash
mix clean                 # clean elixir build artifacts
make clean                # clean NIF .so files
make distclean            # clean everything including fetched C library
```

## Project Structure

```
lib/
  secp256k1.ex           # main public API module (delegates to submodules)
  secp256k1/
    ecdsa.ex             # ECDSA signatures (NIF: priv/ecdsa.so)
    schnorr.ex           # Schnorr signatures (NIF: priv/schnorrsig.so)
    extrakeys.ex         # x-only pubkey derivation (NIF: priv/extrakeys.so)
    musig.ex             # MuSig2 multi-signatures (NIF: priv/musig.so) [EXPERIMENTAL]
    guards.ex            # custom guards (is_seckey, is_hash, etc.)
test/
  support/
    case.ex              # base test case template
    format.ex            # test helpers: d/1 (decode hex), e/1 (encode hex)
    vectors.ex           # loads BIP340, Wycheproof, MuSig2 test vectors
    der.ex               # DER signature parsing for Wycheproof
  secp256k1_test.exs     # main module tests
  secp256k1/
    ecdsa_test.exs       # ECDSA tests
    schnorr_test.exs     # Schnorr tests
    schnorr_bip340_test.exs   # BIP340 vector tests
    ecdsa_wycheproof_test.exs # Wycheproof vector tests
    extrakeys_test.exs   # extrakeys tests
    musig_test.exs       # MuSig integration tests
    musig_vectors_test.exs    # MuSig2 vector tests
c_src/
  *.c                    # NIF implementations (one .c → one .so)
  *.h                    # shared utilities (random.h, utils.h)
  secp256k1/             # cloned bitcoin-core/secp256k1 v0.7.1 (auto-fetched)
```

## Code Style

### Guards

Use guards from `Secp256k1.Guards` for input validation:

```elixir
import Secp256k1.Guards

def sign(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
  # ...
end
```

Available guards:

- `is_bin_size(data, size)` - binary of exact byte size
- `is_hash(data)` - 32 bytes
- `is_seckey(seckey)` - 32 bytes
- `is_compressed_pubkey(pubkey)` - 33 bytes
- `is_uncompressed_pubkey(pubkey)` - 65 bytes
- `is_xonly_pubkey(pubkey)` - 32 bytes
- `is_pubkey(pubkey)` - any pubkey type (32, 33, or 65 bytes)
- `is_ecdsa_sig(sig)` - 64 bytes
- `is_schnorr_sig(sig)` - 64 bytes

### NIF Module Pattern

Each NIF module loads its own `.so` file via `@on_load`:

```elixir
@on_load :load_nifs

defp load_nifs do
  :lib_secp256k1
  |> Application.app_dir("priv/ecdsa")
  |> String.to_charlist()
  |> :erlang.load_nif(0)
end

# NIF stubs return error if not loaded
def nif_func(_arg), do: :erlang.nif_error({:error, :not_loaded})
```

Return patterns from NIFs:

- Success: raw binary or `{:ok, result}` or `{:ok, a, b}`
- Failure: `{:error, reason}` or `enif_make_badarg(env)`

### MuSig2 Security

**CRITICAL**: Never reuse nonces in MuSig2. Call `nonce_gen/5` fresh for every signature attempt. Reusing a nonce leaks the secret key.

The `secnonce` is returned as an Erlang resource (not binary) to prevent copying. It's consumed on use and securely erased.

## Testing Patterns

### Test Helpers

- `d/1` - decode lowercase hex to binary: `d("abcd")` → `<<0xAB, 0xCD>>`
- `e/1` - encode binary to lowercase hex: `e(<<0xAB>>)` → `"ab"`

### Running Tests

```bash
mix test test/secp256k1/ecdsa_test.exs:20  # run test at line 20
mix test test/secp256k1_test.exs --trace   # verbose output
```

### Vector-Driven Tests

Tests use compile-time generation from external vectors:

```elixir
@vectors Vectors.load_bip340()

for vector <- @vectors do
  test "BIP-340 ##{vector.index}: #{vector.comment}" do
    # Each vector becomes a separate test
  end
end
```

## C NIF Guidelines

### Structure

- Include `utils.h` for common helpers (`ctx`, `error_result`, `secure_erase`)
- Use `ErlNifBinary` for binary data
- Return `enif_make_badarg(env)` for invalid inputs
- Return `error_result(env, "message")` for operation failures
- Always `secure_erase` sensitive data before returning

### NIF Registration

```c
static ErlNifFunc nif_funcs[] = {
  {"function_name", arity, c_function_name}
};

ERL_NIF_INIT(Elixir.Secp256k1.Module, nif_funcs, &load, NULL, &upgrade, &unload)
```

### Resource Types (MuSig)

For sensitive data that must not be copied (like secret nonces):

```c
static ErlNifResourceType *secnonce_resource_type;

// In load():
secnonce_resource_type = enif_open_resource_type(
  env, NULL, "secnonce_resource", destruct_secnonce,
  ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL
);
```

## Anti-Patterns

- **AUX parameter functions**: `sign/3` and `sign32/3` accept custom AUX values - NOT RECOMMENDED. Use the 2-arg versions which generate random AUX.
- **Skipping guards**: Always validate inputs with guards before calling NIFs.
- **Copying secnonces**: MuSig secnonces are resources, not binaries - don't try to serialize them.

## BACKLOG WORKFLOW INSTRUCTIONS

This project uses Backlog.md MCP for all task and project management activities.

**CRITICAL GUIDANCE**

- If your client supports MCP resources, read `backlog://workflow/overview` to understand when and how to use Backlog for this project.
- If your client only supports tools or the above request fails, call `backlog.get_backlog_instructions()` to load the tool-oriented overview. Use the `instruction` selector when you need `task-creation`, `task-execution`, or `task-finalization`.

- **First time working here?** Read the overview resource IMMEDIATELY to learn the workflow
- **Already familiar?** You should have the overview cached ("## Backlog.md Overview (MCP)")
- **When to read it**: BEFORE creating tasks, or when you're unsure whether to track work

These guides cover:
- Decision framework for when to create tasks
- Search-first workflow to avoid duplicates
- Links to detailed guides for task creation, execution, and finalization
- MCP tools reference

You MUST read the overview resource to understand the complete workflow. The information is NOT summarized here.
