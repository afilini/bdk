let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
  nightly_rust = (pkgs.rustChannelOf { date = "2022-07-25"; channel = "nightly"; });
in
pkgs.mkShell {
  buildInputs = with pkgs; [ nightly_rust.rust libbfd libunwind libopcodes lldb clang llvm ];

  CARGO_INSTALL_ROOT = "${builtins.toString ./nix-cargo}";
  RUSTFLAGS="-Znew-llvm-pass-manager=no";

  shellHook = ''
    export PATH="$CARGO_INSTALL_ROOT/bin:$PATH"
  '';
}

