{ pkgs ? import (builtins.fetchTarball https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz) {} }:

let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  moz_pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };

  rustPlatform = pkgs.makeRustPlatform {
    inherit (moz_pkgs.latest.rustChannels.nightly) cargo;
    rustc = moz_pkgs.latest.rustChannels.nightly.rust;
  };

  gitlab-cert-auth = rustPlatform.buildRustPackage {
    name = "gitlab-cert-auth";
    version = "0.1.0";
    src = ./.;
    cargoSha256 = "1ikx2nhx1qr99yygg1zjx68wjdwamsja2yq0g4lyrwssf9f1lzjb";
  };

in gitlab-cert-auth
