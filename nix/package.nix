{
  lib,
  rustPlatform,
  cacert,
  cmake,
  perl,
  pkg-config,
}:

let
  manifest = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = manifest.package.name;
  inherit (manifest.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # aws-lc-sys (rustls backend used by reqwest) builds its C sources with cmake.
  nativeBuildInputs = [
    cmake
    perl
    pkg-config
  ];
  dontUseCmakeConfigure = true;

  # reqwest loads the platform trust store even for tests against local mock servers.
  nativeCheckInputs = [ cacert ];
  preCheck = ''
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
  '';

  meta = {
    inherit (manifest.package) description;
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "blockmerge";
    platforms = lib.platforms.linux;
  };
}
