with import <nixpkgs> {};

mkShell {
  name = "snipeit-cert-auth-dev-shell";
  buildInputs = [
    cargo rustc
    openssl
    pkg-config
  ];
}