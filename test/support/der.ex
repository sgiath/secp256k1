defmodule Secp256k1Test.DER do
  @moduledoc false

  def to_compact(der_hex) when is_binary(der_hex) do
    der = Base.decode16!(der_hex, case: :mixed)

    {sequence, _rest} = read_sequence(der)
    {r, rest} = read_integer(sequence)
    {s, rest} = read_integer(rest)

    if rest != <<>> do
      raise ArgumentError, "extra data after DER sequence"
    end

    normalize_integer(r) <> normalize_integer(s)
  end

  defp read_sequence(<<0x30, rest::binary>>) do
    {len, rest} = read_length(rest)
    <<seq::binary-size(^len), remaining::binary>> = rest
    {seq, remaining}
  end

  defp read_sequence(_), do: raise(ArgumentError, "invalid DER sequence")

  defp read_integer(<<0x02, rest::binary>>) do
    {len, rest} = read_length(rest)
    <<value::binary-size(^len), remaining::binary>> = rest
    validate_integer(value)
    {value, remaining}
  end

  defp read_integer(_), do: raise(ArgumentError, "invalid DER integer")

  defp read_length(<<len, rest::binary>>) when len <= 0x7F do
    {len, rest}
  end

  defp read_length(<<0x81, len, rest::binary>>) do
    {len, rest}
  end

  defp read_length(<<0x82, b1, b2, rest::binary>>) do
    {b1 * 256 + b2, rest}
  end

  defp read_length(_), do: raise(ArgumentError, "unsupported DER length")

  defp normalize_integer(value) do
    trimmed = trim_leading_zeros(value)
    padded = if trimmed == <<>>, do: <<0>>, else: trimmed

    case byte_size(padded) do
      size when size < 32 -> :binary.copy(<<0>>, 32 - size) <> padded
      32 -> padded
      _ -> raise ArgumentError, "DER integer is too large"
    end
  end

  defp trim_leading_zeros(<<0, rest::binary>>), do: trim_leading_zeros(rest)
  defp trim_leading_zeros(value), do: value

  defp validate_integer(<<>>), do: raise(ArgumentError, "invalid DER integer")

  defp validate_integer(<<0x00, next, _::binary>>) when next < 0x80 do
    raise ArgumentError, "non-minimal DER integer encoding"
  end

  defp validate_integer(<<first, _::binary>>) when first >= 0x80 do
    raise ArgumentError, "negative DER integer"
  end

  defp validate_integer(_value), do: :ok
end
