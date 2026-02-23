{ pkgs ? import <nixpkgs> {} }:

pkgs.rustPlatform.buildRustPackage rec {
  pname = "verifpal";
  version = "latest";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };
}
