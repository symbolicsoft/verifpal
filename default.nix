{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let unstable = import (fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };

in unstable.buildGoPackage rec {
  pname = "verifpal";
  version = "latest";

  goPackagePath = "verifpal.com";

  src = ./.;
  goDeps = ./tools/nix/deps.nix;

  nativeBuildInputs = [ pigeon ];

  postPatch = ''
    sed -e 's|/bin/echo |echo |g' -i Makefile
  '';

  buildPhase = ''
    make -C go/src/$goPackagePath parser linux
  '';

  installPhase = ''
    mkdir -p $bin/bin
    cp go/src/$goPackagePath/build/linux/verifpal $bin/bin/
  '';

}
