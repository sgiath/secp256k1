defmodule Secp256k1Test.NativeFault do
  @moduledoc false
  use Secp256k1Test.Case, async: true

  alias Secp256k1.NIF
  alias Secp256k1Test.MuSigSubprocess

  @moduletag :fault_injection

  # Upper bound on fault points in one call; a call needing more is a harness bug.
  @max_fault_points 16

  test "every native operation honors the allocation and RNG failure contracts" do
    f = fixtures()

    for {name, args_fun, expected} <- operation_cases(f) do
      runs = fault_runs(name, args_fun)
      {faulted, [final]} = Enum.split(runs, -1)

      for run <- runs do
        assert run.net_allocs == 0,
               "#{name} failing fault point #{run.fail_at} leaked #{run.net_allocs} allocations"
      end

      for run <- faulted do
        assert run.result == failure_result(run.failed),
               "#{name} failing #{run.failed} (point #{run.fail_at}) returned " <>
                 inspect(run.result)
      end

      assert final.hits == length(faulted)
      assert_expected(name, final.result, expected)

      if !is_boolean(final.result) do
        assert faulted != [], "#{name} reached no fault point"
      end
    end
  end

  test "musig_nonce_gen reports an RNG failure as an operation error" do
    f = fixtures()

    assert {{:error, "RNG failed"}, %{net_allocs: 0, failed: :fill_random}} =
             fault_call(1, :musig_nonce_gen, [f.seckey, f.pubkey, f.msg, f.cache, nil])
  end

  test "musig_partial_sign consumes the nonce when its result cannot be allocated" do
    f = fixtures()
    {:ok, secnonce, _pubnonce} = NIF.musig_nonce_gen(f.seckey, f.pubkey, f.msg, f.cache, nil)
    args = [secnonce, f.seckey, f.cache, f.session]

    assert {{:error, :allocation_failed}, %{failed: :enif_alloc_binary, net_allocs: 0}} =
             fault_call(1, :musig_partial_sign, args)

    assert NIF.musig_partial_sign(secnonce, f.seckey, f.cache, f.session) ==
             {:error, "nonce already used"}
  end

  test "an illegal-argument callback raises ArgumentError over any result" do
    assert_raise ArgumentError, fn ->
      NIF.fault_call_with_callback(:illegal, :ecdsa_compressed_pubkey, [<<1::256>>])
    end

    assert_raise ArgumentError, fn ->
      NIF.fault_call_with_callback(:illegal, :ecdh, [<<1::256>>, <<2, 0::256>>])
    end

    assert_raise ArgumentError, fn ->
      NIF.fault_call_with_callback(:illegal, :valid_seckey?, [<<0::256>>])
    end
  end

  test "an internal-error callback replaces any result with the internal error" do
    for {name, args} <- [
          {:ecdsa_compressed_pubkey, [<<1::256>>]},
          {:ecdh, [<<1::256>>, <<2, 0::256>>]},
          {:valid_seckey?, [<<0::256>>]}
        ] do
      assert NIF.fault_call_with_callback(:internal, name, args) ==
               {:error, "libsecp256k1 internal error"}
    end
  end

  test "an exception raised by the NIF body wins over a callback" do
    for kind <- [:illegal, :internal] do
      assert_raise ArgumentError, fn ->
        NIF.fault_call_with_callback(kind, :ecdsa_compressed_pubkey, [<<0::256>>])
      end
    end
  end

  # Runs child BEAMs but is not tagged :expensive: `--include expensive` would override the
  # :fault_injection exclusion in builds without the harness.
  test "a load failing at any fault point fails cleanly without leaking" do
    failed_loads =
      Enum.reduce_while(1..@max_fault_points, 0, fn fail_at, failed_loads ->
        case child_load(fail_at) do
          :loaded -> {:halt, failed_loads}
          :failed -> {:cont, failed_loads + 1}
        end
      end)

    assert failed_loads in 1..(@max_fault_points - 1)
  end

  # The probe names the module only as data: compiling a remote call would load the NIF before
  # `setup` sets the fault point.
  defp child_load(fail_at) do
    setup = ~s|System.put_env("SECP256K1_NIF_FAULT_LOAD", "#{fail_at}")|

    probe = """
    module = Secp256k1.NIF

    case Code.ensure_loaded(module) do
      {:module, _} ->
        valid? = apply(module, :valid_seckey?, [<<1::256>>])
        IO.puts("FAULT_LOAD:loaded:" <> inspect(valid?))

      other ->
        IO.puts("FAULT_LOAD:" <> inspect(other))
    end
    """

    {output, status} = MuSigSubprocess.run(setup, probe)
    assert status == 0, output

    cond do
      output =~ "FAULT_LOAD:loaded:true" -> :loaded
      output =~ "FAULT_LOAD:{:error, :on_load_failure}" -> :failed
      true -> flunk("unexpected load outcome at fault point #{fail_at}:\n#{output}")
    end
  end

  # Calls NIF `name` failing fault point 1, 2, ... until a call hits no failing fault point.
  # Returns every run, the last one being the call without a fault.
  defp fault_runs(name, args_fun, fail_at \\ 1, runs \\ []) do
    assert fail_at <= @max_fault_points, "#{name} hit more than #{@max_fault_points} faults"
    {result, stats} = fault_call(fail_at, name, args_fun.())
    runs = [Map.merge(stats, %{fail_at: fail_at, result: result}) | runs]

    if stats.failed == nil do
      Enum.reverse(runs)
    else
      fault_runs(name, args_fun, fail_at + 1, runs)
    end
  end

  defp fault_call(fail_at, name, args) do
    result =
      try do
        NIF.fault_call(fail_at, name, args)
      rescue
        exception in ArgumentError -> {:raised, exception}
      end

    assert_receive {:secp256k1_fault, hits, net_allocs, failed}
    {result, %{hits: hits, net_allocs: net_allocs, failed: failed}}
  end

  defp failure_result(:fill_random), do: {:error, "RNG failed"}
  defp failure_result(_allocation), do: {:error, :allocation_failed}

  defp assert_expected(name, result, expected) when is_function(expected, 1) do
    assert expected.(result), "#{name} returned #{inspect(result)}"
  end

  defp assert_expected(name, result, expected) do
    assert result == expected, "#{name} returned #{inspect(result)}"
  end

  defp fixtures do
    seckey = <<1::256>>
    other_seckey = <<2::256>>
    pubkey = NIF.ecdsa_compressed_pubkey(seckey)
    other_pubkey = NIF.ecdsa_compressed_pubkey(other_seckey)
    msg = :crypto.hash(:sha256, "native fault injection")
    {:ok, _agg_pubkey, cache} = NIF.musig_pubkey_agg([pubkey, other_pubkey])
    {:ok, secnonce, pubnonce} = NIF.musig_nonce_gen(seckey, pubkey, msg, cache, nil)

    {:ok, other_secnonce, other_pubnonce} =
      NIF.musig_nonce_gen(other_seckey, other_pubkey, msg, cache, nil)

    aggnonce = NIF.musig_nonce_agg([pubnonce, other_pubnonce])
    session = NIF.musig_nonce_process(aggnonce, msg, cache)
    partial_sig = NIF.musig_partial_sign(secnonce, seckey, cache, session)
    other_partial_sig = NIF.musig_partial_sign(other_secnonce, other_seckey, cache, session)

    %{
      seckey: seckey,
      pubkey: pubkey,
      other_pubkey: other_pubkey,
      uncompressed_pubkey: NIF.ecdsa_uncompressed_pubkey(seckey),
      xonly_pubkey: NIF.xonly_pubkey(seckey),
      msg: msg,
      ecdsa_sig: NIF.ecdsa_sign(msg, seckey, nil),
      cache: cache,
      pubnonce: pubnonce,
      other_pubnonce: other_pubnonce,
      aggnonce: aggnonce,
      session: session,
      partial_sigs: [partial_sig, other_partial_sig]
    }
  end

  # {nif_name, args_fun, expected}: `expected` is the result of the call without a fault, or
  # a predicate on it. Deterministic cases compare against a plain NIF call.
  defp operation_cases(f) do
    deterministic_cases(f) ++ musig_cases(f) ++ operation_error_cases(f)
  end

  defp deterministic_cases(f) do
    tweak = <<7::256>>
    aux = <<9::256>>
    der = NIF.ecdsa_serialize_der(f.ecdsa_sig)
    schnorr_sig = NIF.schnorr_sign32(f.msg, f.seckey, aux)
    {:ok, tweaked_xonly, parity} = NIF.xonly_pubkey_tweak_add(f.xonly_pubkey, tweak)

    Enum.map(
      [
        {:ecdsa_compressed_pubkey, [f.seckey]},
        {:ecdsa_uncompressed_pubkey, [f.seckey]},
        {:ecdsa_compress_pubkey, [f.uncompressed_pubkey]},
        {:ecdsa_decompress_pubkey, [f.pubkey]},
        {:ecdsa_sign, [f.msg, f.seckey, nil]},
        {:ecdsa_sign, [f.msg, f.seckey, aux]},
        {:ecdsa_serialize_der, [f.ecdsa_sig]},
        {:ecdsa_parse_der, [der]},
        {:ecdsa_normalize, [f.ecdsa_sig]},
        {:ecdsa_valid?, [f.ecdsa_sig, f.msg, f.pubkey]},
        {:schnorr_sign32, [f.msg, f.seckey, aux]},
        {:schnorr_sign_custom, ["any length message", f.seckey, aux]},
        {:schnorr_sign_custom_dirty, ["any length message", f.seckey, aux]},
        {:schnorr_valid?, [schnorr_sig, f.msg, f.xonly_pubkey]},
        {:schnorr_valid_dirty?, [schnorr_sig, f.msg, f.xonly_pubkey]},
        {:ecdh, [f.seckey, f.other_pubkey]},
        {:valid_seckey?, [f.seckey]},
        {:valid_pubkey?, [f.pubkey]},
        {:xonly_pubkey, [f.seckey]},
        {:xonly_pubkey_from_pubkey, [f.pubkey]},
        {:ec_seckey_tweak_add, [f.seckey, tweak]},
        {:ec_pubkey_tweak_add, [f.pubkey, tweak]},
        {:xonly_seckey_tweak_add, [f.seckey, tweak]},
        {:xonly_pubkey_tweak_add, [f.xonly_pubkey, tweak]},
        {:xonly_pubkey_tweak_add_check, [tweaked_xonly, parity, f.xonly_pubkey, tweak]},
        {:musig_pubkey_get, [f.cache]},
        {:musig_nonce_agg, [[f.pubnonce, f.other_pubnonce]]},
        {:musig_partial_sig_agg, [f.session, f.partial_sigs]},
        {:musig_partial_sig_verify,
         [hd(f.partial_sigs), f.pubnonce, f.pubkey, f.cache, f.session]}
      ],
      fn {name, args} -> {name, fn -> args end, apply(NIF, name, args)} end
    )
  end

  defp musig_cases(f) do
    tweak = <<7::256>>
    agg_pubkey = elem(NIF.musig_pubkey_agg([f.pubkey, f.other_pubkey]), 1)

    [
      {:musig_pubkey_agg, fn -> [[f.pubkey, f.other_pubkey]] end,
       &match?({:ok, ^agg_pubkey, cache} when is_reference(cache), &1)},
      {:musig_pubkey_ec_tweak_add, fn -> [f.cache, tweak] end,
       &match?({:ok, <<_::264>>, cache} when is_reference(cache), &1)},
      {:musig_pubkey_xonly_tweak_add, fn -> [f.cache, tweak] end,
       &match?({:ok, <<_::264>>, cache} when is_reference(cache), &1)},
      {:musig_nonce_gen, fn -> [f.seckey, f.pubkey, f.msg, f.cache, <<3::256>>] end,
       &match?({:ok, secnonce, <<_::528>>} when is_reference(secnonce), &1)},
      {:musig_nonce_gen, fn -> [nil, f.pubkey, nil, nil, nil] end,
       &match?({:ok, secnonce, <<_::528>>} when is_reference(secnonce), &1)},
      {:musig_nonce_process, fn -> [f.aggnonce, f.msg, f.cache] end, &is_reference/1},
      {:musig_partial_sign, fn -> fresh_partial_sign_args(f) end, &match?(<<_::256>>, &1)}
    ]
  end

  # Operation failures build their reason binary, which is a fault point too.
  defp operation_error_cases(f) do
    invalid_pubkey = <<2, 0::256>>

    curve_order =
      Base.decode16!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

    [secnonce | _rest] = used_args = fresh_partial_sign_args(f)
    assert <<_::256>> = NIF.musig_partial_sign(secnonce, f.seckey, f.cache, f.session)

    [
      {:ecdh, fn -> [f.seckey, invalid_pubkey] end, {:error, "secp256k1_ec_pubkey_parse failed"}},
      {:ec_seckey_tweak_add, fn -> [f.seckey, curve_order] end,
       {:error, "secp256k1_ec_seckey_tweak_add failed"}},
      {:musig_partial_sign, fn -> used_args end, {:error, "nonce already used"}},
      {:musig_partial_sign, fn -> fresh_partial_sign_args(f, :crypto.hash(:sha256, "other")) end,
       {:error, "secnonce was generated for a different message"}}
    ]
  end

  defp fresh_partial_sign_args(f, nonce_msg \\ nil) do
    {:ok, secnonce, _pubnonce} =
      NIF.musig_nonce_gen(f.seckey, f.pubkey, nonce_msg || f.msg, f.cache, nil)

    [secnonce, f.seckey, f.cache, f.session]
  end
end

defmodule Secp256k1Test.NativeFaultResources do
  @moduledoc false
  # Not async: live resource counters are global to the NIF.
  use Secp256k1Test.Case, async: false

  alias Secp256k1.NIF

  @moduletag :fault_injection

  test "resources of an exited process, including failed constructions, are destroyed" do
    baseline = settled_live_resources()
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        create_resources()
        send(parent, {:created, self()})

        receive do
          :exit -> :ok
        end
      end)

    assert_receive {:created, ^pid}, 5_000

    assert NIF.fault_live_resources() == %{
             keyagg_cache: baseline.keyagg_cache + 1,
             secnonce: baseline.secnonce + 2,
             session: baseline.session + 1
           }

    send(pid, :exit)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5_000
    :erlang.garbage_collect()

    assert eventually(fn -> NIF.fault_live_resources() == baseline end),
           "live resources #{inspect(NIF.fault_live_resources())}, " <>
             "baseline #{inspect(baseline)}"
  end

  # One cache, two secnonces, and one session stay referenced by the caller. Every faulting
  # nonce_gen releases what it allocated, including a secnonce without a mutex.
  defp create_resources do
    seckey = <<1::256>>
    pubkey = NIF.ecdsa_compressed_pubkey(seckey)
    other_pubkey = NIF.ecdsa_compressed_pubkey(<<2::256>>)
    msg = :crypto.hash(:sha256, "resource reclamation")
    {:ok, _agg_pubkey, cache} = NIF.musig_pubkey_agg([pubkey, other_pubkey])

    for fail_at <- 1..4 do
      assert {:error, _reason} =
               NIF.fault_call(fail_at, :musig_nonce_gen, [seckey, pubkey, msg, cache, nil])
    end

    {:ok, secnonce, pubnonce} = NIF.musig_nonce_gen(seckey, pubkey, msg, cache, nil)

    {:ok, other_secnonce, other_pubnonce} =
      NIF.musig_nonce_gen(nil, other_pubkey, msg, cache, nil)

    aggnonce = NIF.musig_nonce_agg([pubnonce, other_pubnonce])
    session = NIF.musig_nonce_process(aggnonce, msg, cache)
    Process.put(:resources, [cache, secnonce, other_secnonce, session])
  end

  defp settled_live_resources do
    :erlang.garbage_collect()
    first = NIF.fault_live_resources()
    Process.sleep(50)

    case NIF.fault_live_resources() do
      ^first -> first
      _changed -> settled_live_resources()
    end
  end

  defp eventually(check, attempts \\ 100) do
    cond do
      check.() ->
        true

      attempts == 0 ->
        false

      true ->
        Process.sleep(20)
        eventually(check, attempts - 1)
    end
  end
end
