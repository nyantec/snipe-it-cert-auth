{ openssl, pkg-config, rustPlatform }:

let
  snipe-it-cert-auth = rustPlatform.buildRustPackage {
    name = "snipe-it-cert-auth";
    version = "0.1.0";

    src = ./.;

    buildInputs = [ openssl ];
    nativeBuildInputs = [ pkg-config ];

    cargoLock = {
      lockFile = ./Cargo.lock;
    };
  };

in snipe-it-cert-auth
