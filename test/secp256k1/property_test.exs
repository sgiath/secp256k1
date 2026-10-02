defmodule Secp256k1Test.Property do
  @moduledoc false
  use Secp256k1Test.Case, async: true
  use ExUnitProperties

  alias Secp256k1.ECDH
  alias Secp256k1.ECDSA
  alias Secp256k1.Extrakeys
  alias Secp256k1.Schnorr

  @curve_order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @dirty_message_threshold 65_536

  describe "secret keys" do
    test "accept 1 and n - 1 and reject 0, n, and 2^256 - 1" do
      msg_hash = :crypto.hash(:sha256, "scalar boundaries")

      for seckey <- [<<1::256>>, <<@curve_order - 1::256>>] do
        assert Secp256k1.valid_seckey?(seckey)
        sig = Secp256k1.ecdsa_sign(msg_hash, seckey)
        assert Secp256k1.ecdsa_valid?(sig, msg_hash, Secp256k1.pubkey(seckey, :compressed))
        sig = Secp256k1.schnorr_sign(msg_hash, seckey)
        assert Secp256k1.schnorr_valid?(sig, msg_hash, Secp256k1.pubkey(seckey, :xonly))
      end

      generator = Secp256k1.pubkey(<<1::256>>, :compressed)

      for seckey <- [<<0::256>>, <<@curve_order::256>>, :binary.copy(<<255>>, 32)] do
        refute Secp256k1.valid_seckey?(seckey)

        for type <- [:compressed, :uncompressed, :xonly] do
          assert_raise ArgumentError, fn -> Secp256k1.pubkey(seckey, type) end
        end

        assert_raise ArgumentError, fn -> Secp256k1.ecdsa_sign(msg_hash, seckey) end
        assert_raise ArgumentError, fn -> Secp256k1.schnorr_sign(msg_hash, seckey) end
        assert_raise ArgumentError, fn -> Secp256k1.ecdh(seckey, generator) end
      end
    end
  end

  describe "public-key encodings" do
    property "convert between formats without loss and all parse as valid" do
      check all seckey <- seckey() do
        compressed = ECDSA.compressed_pubkey(seckey)
        uncompressed = ECDSA.uncompressed_pubkey(seckey)
        xonly = Extrakeys.xonly_pubkey(seckey)

        assert ECDSA.decompress_pubkey(compressed) == uncompressed
        assert ECDSA.compress_pubkey(uncompressed) == compressed
        assert Secp256k1.convert_pubkey(compressed, :xonly) == xonly
        assert Enum.all?([compressed, uncompressed, xonly], &Secp256k1.valid_pubkey?/1)
      end
    end
  end

  describe "ECDSA" do
    property "signatures verify with both encodings and only for the signed hash" do
      check all seckey <- seckey(),
                msg_hash <- binary(length: 32),
                bit <- integer(0..255) do
        sig = ECDSA.sign(msg_hash, seckey)
        compressed = ECDSA.compressed_pubkey(seckey)

        assert ECDSA.valid?(sig, msg_hash, compressed)
        assert ECDSA.valid?(sig, msg_hash, ECDSA.uncompressed_pubkey(seckey))
        refute ECDSA.valid?(sig, flip_bit(msg_hash, bit), compressed)
      end
    end

    property "signatures are low-S and survive a DER round trip" do
      check all seckey <- seckey(), msg_hash <- binary(length: 32) do
        sig = ECDSA.sign(msg_hash, seckey)

        assert ECDSA.normalize(sig) == sig
        der = ECDSA.serialize_der(sig)
        assert ECDSA.parse_der(der) == sig
      end
    end

    property "the high-S twin is rejected until normalized back to the signature" do
      check all seckey <- seckey(), msg_hash <- binary(length: 32) do
        <<r::binary-size(32), s::256>> = sig = ECDSA.sign(msg_hash, seckey)
        high_s = <<r::binary, @curve_order - s::256>>
        pubkey = ECDSA.compressed_pubkey(seckey)

        refute ECDSA.valid?(high_s, msg_hash, pubkey)
        der = ECDSA.serialize_der(high_s)
        assert ECDSA.parse_der(der) == high_s
        normalized = ECDSA.normalize(high_s)
        assert normalized == sig
        assert ECDSA.valid?(normalized, msg_hash, pubkey)
      end
    end
  end

  describe "ECDH" do
    # The shared point a*B equals the public key of the scalar a*b mod n; libsecp256k1's
    # default hash is SHA256 over its compressed encoding.
    property "both parties derive SHA256 of the compressed shared point" do
      check all a <- seckey(), b <- seckey() do
        <<a_int::256>> = a
        <<b_int::256>> = b
        shared_point = ECDSA.compressed_pubkey(<<rem(a_int * b_int, @curve_order)::256>>)
        expected = :crypto.hash(:sha256, shared_point)

        assert ECDH.ecdh(a, ECDSA.compressed_pubkey(b)) == expected
        assert ECDH.ecdh(a, ECDSA.uncompressed_pubkey(b)) == expected
        assert ECDH.ecdh(b, ECDSA.compressed_pubkey(a)) == expected
        assert ECDH.ecdh(b, ECDSA.uncompressed_pubkey(a)) == expected
      end
    end
  end

  describe "key tweaks" do
    property "public-key tweak matches the public key of the tweaked secret key" do
      check all seckey <- seckey(), tweak <- tweak(seckey) do
        compressed = ECDSA.compressed_pubkey(seckey)
        uncompressed = ECDSA.uncompressed_pubkey(seckey)

        case Extrakeys.ec_seckey_tweak_add(seckey, tweak) do
          {:error, _reason} ->
            assert {:error, _reason} = Extrakeys.ec_pubkey_tweak_add(compressed, tweak)
            assert {:error, _reason} = Extrakeys.ec_pubkey_tweak_add(uncompressed, tweak)

          tweaked ->
            assert Extrakeys.ec_pubkey_tweak_add(compressed, tweak) ==
                     ECDSA.compressed_pubkey(tweaked)

            assert Extrakeys.ec_pubkey_tweak_add(uncompressed, tweak) ==
                     ECDSA.uncompressed_pubkey(tweaked)
        end
      end
    end

    property "x-only tweak matches the tweaked secret key and checks only with its parity" do
      check all seckey <- seckey(), tweak <- tweak(seckey) do
        internal = Extrakeys.xonly_pubkey(seckey)

        case Extrakeys.xonly_seckey_tweak_add(seckey, tweak) do
          {:error, _reason} ->
            assert {:error, _reason} = Extrakeys.xonly_pubkey_tweak_add(internal, tweak)

          tweaked ->
            assert {:ok, output, parity} = Extrakeys.xonly_pubkey_tweak_add(internal, tweak)
            assert ECDSA.compressed_pubkey(tweaked) == <<2 + parity, output::binary>>
            assert Extrakeys.xonly_pubkey_tweak_add_check(output, parity, internal, tweak)
            refute Extrakeys.xonly_pubkey_tweak_add_check(output, 1 - parity, internal, tweak)
        end
      end
    end
  end

  describe "Schnorr" do
    property "signatures verify for any message length below the dirty threshold" do
      check all seckey <- seckey(), message <- binary(max_length: 1024) do
        sig = Schnorr.sign(message, seckey)

        assert Schnorr.valid?(sig, message, Extrakeys.xonly_pubkey(seckey))
      end
    end

    property "a single flipped bit in the message or signature fails verification" do
      check all seckey <- seckey(),
                message <- binary(min_length: 1, max_length: 256),
                message_bit <- non_negative_integer(),
                sig_bit <- integer(0..511) do
        pubkey = Extrakeys.xonly_pubkey(seckey)
        sig = Schnorr.sign(message, seckey)
        flipped_message = flip_bit(message, rem(message_bit, bit_size(message)))
        flipped_sig = flip_bit(sig, sig_bit)

        refute Schnorr.valid?(sig, flipped_message, pubkey)
        refute Schnorr.valid?(flipped_sig, message, pubkey)
      end
    end

    property "signatures verify around and above the dirty threshold" do
      check all seckey <- seckey(),
                chunk <- binary(length: 64),
                size <- integer((@dirty_message_threshold - 2)..(@dirty_message_threshold + 64)),
                bit <- integer(0..(size * 8 - 1)),
                max_runs: 10 do
        message = binary_part(:binary.copy(chunk, div(size, 64) + 1), 0, size)
        pubkey = Extrakeys.xonly_pubkey(seckey)
        sig = Schnorr.sign(message, seckey)

        assert Schnorr.valid?(sig, message, pubkey)
        refute Schnorr.valid?(sig, flip_bit(message, bit), pubkey)
      end
    end
  end

  # Random valid scalars, with the boundary scalars 1 and n - 1 mixed in.
  defp seckey do
    frequency([
      {1, member_of([<<1::256>>, <<@curve_order - 1::256>>])},
      {8, filter(binary(length: 32), &Secp256k1.valid_seckey?/1)}
    ])
  end

  # Random tweaks, plus boundaries and tweaks that cancel `seckey` for either Y parity (`-k` for
  # plain and even-Y x-only tweaks, `k` for odd-Y x-only tweaks), so error results are generated.
  defp tweak(seckey) do
    <<k::256>> = seckey

    frequency([
      {8, binary(length: 32)},
      {1, member_of([<<0::256>>, <<1::256>>, <<@curve_order - 1::256>>, <<@curve_order::256>>])},
      {1, member_of([<<@curve_order - k::256>>, seckey])}
    ])
  end

  defp flip_bit(binary, index) do
    <<prefix::bitstring-size(^index), bit::1, rest::bitstring>> = binary
    <<prefix::bitstring, 1 - bit::1, rest::bitstring>>
  end
end
