//! A marker file for the sample game's known-cheat test. It does nothing: no code runs
//! when it is loaded and its one function returns a constant. The test puts this file's
//! SHA-256 on the studio's list of known cheat files and has the sample game load it.

#[no_mangle]
pub extern "C" fn carthago_sample_marker() -> u32 {
    0x4341_5254
}
