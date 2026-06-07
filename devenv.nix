{ pkgs, inputs, ... }:

{
  dotenv.disableHint = true;

  packages = with pkgs; [
    git
    autoreconfHook
    inputs.backlog-md.packages.${pkgs.stdenv.hostPlatform.system}.default
  ];

  languages = {
    c.enable = true;
    elixir = {
      enable = true;
      package = pkgs.beam_minimal.packages.erlang_29.elixir_1_20;
    };
  };

  enterTest = ''
    mix test
  '';

  env = {
    MIX_OS_DEPS_COMPILE_PARTITION_COUNT = "16";
    ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
    ELIXIR_ERL_OPTIONS = "+sssdio 128";
  };

  git-hooks.hooks = {
    shellcheck.enable = true;
    nixfmt.enable = true;
    prettier = {
      enable = true;
      settings.print-width = 98;
    };
  };
}
