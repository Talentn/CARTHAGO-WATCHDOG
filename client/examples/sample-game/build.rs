//! Compiles game.c with the C compiler cargo already uses and links it against
//! carthago_sentinel.dll through its import library, so the sample needs no CMake.
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=game.c");
    println!("cargo:rerun-if-changed=../../../sdk/native/include/carthago_sentinel.h");
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    cc::Build::new().file("game.c").include("../../../sdk/native/include").warnings(true).compile("carthago_sample_game_c");
    // OUT_DIR is under <target>/<profile>/build; the DLL and its import library are in
    // <target>/<profile> and <target>/<profile>/deps.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let profile = out.ancestors().find(|p| p.file_name().is_some_and(|n| n == "build")).and_then(|p| p.parent()).expect("OUT_DIR is not under a build directory");
    println!("cargo:rustc-link-search=native={}", profile.display());
    println!("cargo:rustc-link-search=native={}", profile.join("deps").display());
    println!("cargo:rustc-link-lib=dylib=carthago_sentinel.dll");
    println!("cargo:rustc-link-lib=dylib=user32");
}
