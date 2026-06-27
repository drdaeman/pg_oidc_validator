{
  description = "Dev shell for pg_oidc_validator";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "pg_oidc_validator";

          nativeBuildInputs = with pkgs; [
            postgresql_18.stdenv.cc
            gnumake
            pkg-config
            postgresql_18
            postgresql_18.pg_config
            meson
            ninja

            # Test harness (test/spec, see test/README.md)
            ruby
            bundler
          ];

          buildInputs = with pkgs; [
            curl
            openssl
          ];
        };
      });
    };
}
