{
  description = "secp256k1 lib in Elixir";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    { parts, ... }@inputs:
    parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      perSystem =
        { pkgs, ... }:
        let
          beamPackages = pkgs.beam.packages.erlang_28;
          elixir = beamPackages.elixir_1_19;
        in
        {
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              elixir
              git
              autoreconfHook
              prettier
            ];

            env = {
              MIX_OS_DEPS_COMPILE_PARTITION_COUNT = "16";
              ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
              ELIXIR_ERL_OPTIONS = "+sssdio 128";
            };
          };
        };
    };
}
