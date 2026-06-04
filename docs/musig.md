# MuSig2 Multi-Signatures

MuSig2 (BIP-327) is a multi-signature scheme that allows multiple parties to aggregate their public keys into a single public key. A signature created by combining partial signatures from all parties looks exactly like a standard Schnorr signature to a verifier.

## Concepts

- **Key Aggregation**: Combining individual public keys into a single aggregated x-only public key.
- **Nonce Generation**: Each signer generates a secret and public nonce.
- **Nonce Aggregation**: Combining all public nonces into an aggregate nonce.
- **Partial Signing**: Each signer creates a partial signature using their secret key, secret nonce, and the aggregate nonce.
- **Signature Aggregation**: Combining partial signatures into the final valid Schnorr signature.

> #### Process-local state {: .info}
>
> `keyagg_cache`, `session`, and `secnonce` values returned by this library are
> process-local NIF resources. They are not serialized binaries, cannot be
> stored or sent to another BEAM instance, and must be recreated for each
> signing process. Public nonces, aggregate nonces, partial signatures, and
> final signatures are serialized binaries.

> #### Secret nonces are one-use {: .warning}
>
> Never reuse MuSig2 secret nonces. Call `nonce_gen/5` fresh for every signing
> attempt. Reusing a nonce with the same key can leak the secret key.

## Example: 3-of-3 Signing Session

In this example, 3 parties (Alice, Bob, and Carol) want to sign a message together. MuSig2 is an n-of-n scheme relative to the aggregated key, meaning all parties whose keys were aggregated must participate to produce a valid signature.

### 1. Setup Signers

We generate keys for our 3 participants.

```elixir
# Generate keys for 3 parties
participants = for i <- 1..3 do
  {seckey, pubkey} = Secp256k1.keypair(:compressed)
  %{id: i, seckey: seckey, pubkey: pubkey}
end

participant_pubkeys = Enum.map(participants, & &1.pubkey)
```

### 2. Key Aggregation

The participants aggregate their public keys to create the group public key.

```elixir
alias Secp256k1.MuSig

# Aggregate public keys
{:ok, agg_xonly_pubkey, keyagg_cache} = MuSig.pubkey_agg(participant_pubkeys)

# agg_xonly_pubkey is the 32-byte public key that verifies the final signature
# keyagg_cache is a process-local resource used by later MuSig calls
```

### 3. Nonce Generation & Exchange

Each participant generates a nonce pair (secret and public). They must exchange public nonces.

```elixir
message = :crypto.hash(:sha256, "Joint Account Authorization")

# Each participant generates a nonce
participants_with_nonces = Enum.map(participants, fn p ->
  {:ok, secnonce, pubnonce} = MuSig.nonce_gen(p.seckey, p.pubkey, message, keyagg_cache, nil)

  p
  |> Map.put(:secnonce, secnonce) # KEEP SECRET!
  |> Map.put(:pubnonce, pubnonce) # Share this
end)

# Collect all public nonces
pubnonces = Enum.map(participants_with_nonces, & &1.pubnonce)
```

### 4. Nonce Aggregation & Session Setup

Combine the public nonces to create a signing session.

```elixir
# Aggregate nonces
aggnonce = MuSig.nonce_agg(pubnonces)

# Create the signing session (processes the aggregate nonce)
session = MuSig.nonce_process(aggnonce, message, keyagg_cache)
# session is also a process-local resource
```

### 5. Partial Signing

Each participant creates their partial signature.

```elixir
participants_with_sigs = Enum.map(participants_with_nonces, fn p ->
  partial_sig = MuSig.partial_sign(p.secnonce, p.seckey, keyagg_cache, session)
  Map.put(p, :partial_sig, partial_sig)
end)

# Collect all partial signatures
partial_sigs = Enum.map(participants_with_sigs, & &1.partial_sig)
```

### 6. Signature Aggregation & Verification

Finally, aggregate the partial signatures into the final Schnorr signature.

```elixir
# Combine partial signatures
final_signature = MuSig.partial_sig_agg(session, partial_sigs)

# Verify the signature against the aggregated public key
is_valid = Secp256k1.schnorr_valid?(final_signature, message, agg_xonly_pubkey)
# => true
```

## Security Considerations

1. **Nonce Reuse**: never reuse nonces. The `nonce_gen` function uses
   randomness and the message to protect against this, but you must ensure that
   a fresh `nonce_gen` call is made for every signature attempt.
2. **Round Communication**: MuSig2 is a 2-round protocol.
   - Round 1: Exchange public nonces.
   - Round 2: Exchange partial signatures.
   - All public nonces must be received before signing begins.
