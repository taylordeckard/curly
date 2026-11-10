//! Compiles `examples/collection/proto/users.proto` with protox (no `protoc` needed) and
//! generates the tonic server plus a descriptor set for server reflection.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = std::path::Path::new("../collection/proto");
    println!("cargo:rerun-if-changed=../collection/proto/users.proto");
    let fds = protox::compile(["users.proto"], [proto_dir])?;
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(
        out.join("users_descriptor.bin"),
        prost::Message::encode_to_vec(&fds),
    )?;
    tonic_prost_build::configure()
        .build_client(false)
        .compile_fds(fds)?;
    Ok(())
}
