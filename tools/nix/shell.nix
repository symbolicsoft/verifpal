# I'm basing the nix layout on the verifpal in nixpkgs and this blogpost
# https://christine.website/blog/i-was-wrong-about-nix-2020-02-10

# This shell is used to update deps, in root dir run:
# vgo2nix -outfile nix/deps.nix

# To update the sources for this shell you can run:
# niv update

let
  pkgs = import <nixpkgs> { };
  unstable = import (fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };
  sources = import ./tools/nix/sources.nix;
  vgo2nix = (import sources.vgo2nix { });
in
  pkgs.mkShell {
    buildInputs = [
      unstable.go
      pkgs.haskellPackages.niv
      vgo2nix
    ];
  }
