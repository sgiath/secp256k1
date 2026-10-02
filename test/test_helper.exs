# Fault-injection tests need a NIF built with SECP256K1_NIF_FAULT_INJECTION=1.
fault_injection_harness? =
  try do
    is_map(Secp256k1.NIF.fault_live_resources())
  rescue
    ErlangError -> false
  end

exclude = if fault_injection_harness?, do: [:expensive], else: [:expensive, :fault_injection]

ExUnit.start(exclude: exclude)
