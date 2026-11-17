//! `carthago-sample-game.exe`: the game is `game.c`, plain C against the SDK's C header.
//! This file only hands the command line to it, so that `cargo build` is the whole build.

#[cfg(not(windows))]
fn main() {
    eprintln!("carthago-sample-game runs on Windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::ffi::{c_char, c_int, CString};
    extern "C" {
        fn game_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
    }
    let args: Vec<CString> = std::env::args().filter_map(|a| CString::new(a).ok()).collect();
    let mut argv: Vec<*mut c_char> = args.iter().map(|a| a.as_ptr() as *mut c_char).collect();
    argv.push(std::ptr::null_mut());
    std::process::exit(unsafe { game_main(args.len() as c_int, argv.as_mut_ptr()) });
}
