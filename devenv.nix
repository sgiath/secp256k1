{ pkgs, inputs, ... }:
let
  beamPackages = pkgs.beamMinimal29Packages;
  expert = inputs.expert.packages.${pkgs.stdenv.system}.default.override {
    inherit beamPackages;
  };
in
{
  packages = with pkgs; [
    git
    gnupg
    autoreconfHook
    prettier
  ];

  languages = {
    c.enable = true;
    nix.enable = true;
    shell.enable = true;

    elixir = {
      enable = true;
      package = beamPackages.elixir_1_20;
      lsp = {
        enable = true;
        package = expert;
      };
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
