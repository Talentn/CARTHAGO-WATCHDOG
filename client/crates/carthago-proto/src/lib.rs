//! Protobuf types generated from the shared `proto/` tree (architecture plan §5.1).

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/carthago.v1.rs"));
}

pub use prost::Message;
