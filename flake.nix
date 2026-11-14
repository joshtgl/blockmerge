{
  description = "Retrieve, merge, and generate inbound and outbound IP blocklists";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        blockmerge = pkgs.callPackage ./nix/package.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.blockmerge;
      });

      overlays.default = final: _prev: {
        blockmerge = final.callPackage ./nix/package.nix { };
      };

      nixosModules.blockmerge = {
        imports = [ ./nix/module.nix ];
        nixpkgs.overlays = [ self.overlays.default ];
      };
      nixosModules.default = self.nixosModules.blockmerge;

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.blockmerge;
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
