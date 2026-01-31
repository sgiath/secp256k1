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
  secp256k1.ex           # main public API module
  secp256k1/
    ecdsa.ex             # ECDSA signatures (NIF wrapper)
    schnorr.ex           # Schnorr signatures (NIF wrapper)
    extrakeys.ex         # x-only pubkey derivation (NIF wrapper)
    musig.ex             # MuSig2 multi-signatures (NIF wrapper)
    guards.ex            # custom guards (is_seckey, is_hash, etc.)
test/
  support/
    case.ex              # base test case template
    format.ex            # test helpers: d/1 (decode hex), e/1 (encode hex)
  secp256k1_test.exs     # main module tests
  secp256k1/
    ecdsa_test.exs       # ECDSA tests
    schnorr_test.exs     # Schnorr tests
    extrakeys_test.exs   # extrakeys tests
    musig_test.exs       # MuSig tests
c_src/
  *.c                    # NIF implementations
  *.h                    # shared utilities (random.h, utils.h)
  secp256k1/             # cloned bitcoin-core/secp256k1 (auto-fetched)
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

Available guards: `is_bin_size/2`, `is_hash/1`, `is_seckey/1`, `is_compressed_pubkey/1`, `is_uncompressed_pubkey/1`, `is_xonly_pubkey/1`, `is_pubkey/1`, `is_ecdsa_sig/1`, `is_schnorr_sig/1`

### NIF Error Handling

NIF stubs return error tuples; don't call without loading:

```elixir
def nif_func(_arg), do: :erlang.nif_error({:error, :not_loaded})
```

Return patterns from NIFs:

- Success: raw binary or `{:ok, result}` or `{:ok, a, b}`
- Failure: `{:error, reason}` or `enif_make_badarg(env)`

## Testing Patterns

### Test Helpers

- `d/1` - decode lowercase hex to binary: `d("abcd")` -> `<<0xAB, 0xCD>>`
- `e/1` - encode binary to lowercase hex: `e(<<0xAB>>) -> "ab"`

### Running Single Tests

```bash
mix test test/secp256k1/ecdsa_test.exs:20  # run test at line 20
mix test test/secp256k1_test.exs --trace   # verbose output
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
