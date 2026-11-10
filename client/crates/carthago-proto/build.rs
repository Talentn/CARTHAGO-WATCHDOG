use std::error::Error;
use std::path::PathBuf;

const FILES: [&str; 2] = ["carthago/v1/handshake.proto", "carthago/v1/gameserver.proto"];

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../../proto");
    // protox is a pure-Rust protobuf compiler, so builds need no protoc install.
    let fds = protox::compile(FILES, [&root])?;
    prost_build::Config::new().compile_fds(fds)?;
    println!("cargo:rerun-if-changed={}", root.join("carthago").display());
    Ok(())
}
