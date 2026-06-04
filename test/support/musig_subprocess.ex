defmodule Secp256k1Test.MuSigSubprocess do
  @moduledoc false

  def run(expression) when is_binary(expression) do
    ebin = Path.expand("../../_build/test/lib/lib_secp256k1/ebin", __DIR__)
    elixir = System.find_executable("elixir") || "elixir"

    code = """
    try do
      #{expression}
      IO.puts("MUSIG_SUBPROCESS_OK")
    rescue
      exception in ArgumentError ->
        IO.puts("MUSIG_SUBPROCESS_ARGUMENT_ERROR:" <> Exception.message(exception))

      exception ->
        IO.puts("MUSIG_SUBPROCESS_EXCEPTION:" <> inspect(exception))
        System.halt(2)
    catch
      kind, value ->
        IO.puts("MUSIG_SUBPROCESS_CATCH:" <> inspect({kind, value}))
        System.halt(2)
    end
    """

    System.cmd(elixir, ["-pa", ebin, "-e", code], stderr_to_stdout: true)
  end
end
