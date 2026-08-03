{ pkgs, inputs, ... }:

{
  packages = with pkgs; [
    git
    gnupg
    autoreconfHook
    prettier
  ];

  languages = {
    c.enable = true;
    elixir = {
      enable = true;
      package = pkgs.beamMinimal29Packages.elixir_1_20;
    };
  };

  dotenv.disableHint = true;
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
