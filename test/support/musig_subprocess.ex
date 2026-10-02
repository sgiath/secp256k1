defmodule Secp256k1Test.MuSigSubprocess do
  @moduledoc false

  # A healthy child finishes in about a second; this bounds a hung one well below the ExUnit
  # test timeout.
  @deadline_ms 15_000

  @doc """
  Evaluates `expression` in a fresh BEAM that loads this build's code.

  Returns `{output, exit_status}`. A child still running after #{@deadline_ms} ms is killed
  and returns `{output, :timeout}`.
  """
  def run(expression) when is_binary(expression) do
    elixir = System.find_executable("elixir") || raise "elixir executable not found in PATH"

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

    port =
      Port.open({:spawn_executable, elixir}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        :hide,
        args: code_path_args() ++ ["-e", code]
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    deadline = System.monotonic_time(:millisecond) + @deadline_ms

    collect(port, os_pid, deadline, [])
  end

  # Every `ebin` directory of the running build: this library and its dependencies.
  defp code_path_args do
    Mix.Project.build_path()
    |> Path.join("lib/*/ebin")
    |> Path.wildcard()
    |> Enum.flat_map(&["-pa", &1])
  end

  defp collect(port, os_pid, deadline, output) do
    timeout = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        collect(port, os_pid, deadline, [output, data])

      {^port, {:exit_status, status}} ->
        {IO.iodata_to_binary(output), status}
    after
      timeout ->
        System.cmd("kill", ["-KILL", Integer.to_string(os_pid)])
        output = drain(port, output)

        {IO.iodata_to_binary([output, "\nMUSIG_SUBPROCESS_TIMEOUT after #{@deadline_ms} ms"]),
         :timeout}
    end
  end

  # Collects what the killed child wrote before it exited.
  defp drain(port, output) do
    receive do
      {^port, {:data, data}} -> drain(port, [output, data])
      {^port, {:exit_status, _status}} -> output
    after
      5_000 -> output
    end
  end
end
