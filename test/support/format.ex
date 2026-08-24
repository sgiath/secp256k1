defmodule Secp256k1Test.Format do
  @moduledoc false

  def d(data), do: Base.decode16!(data, case: :lower)
end
