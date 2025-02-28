use std::env;

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=src/proto");
    println!("cargo::rerun-if-env-changed=DOCS_RS");

    // Check if this is a docs.rs build
    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:warning=Skipping protobuf code generation on docs.rs.");
        return Ok(());
    }
    let out_dir = env::var_os("OUT_DIR").context("failed to lookup `OUT_DIR`")?;

    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);

    let file_descriptors = protox::compile(["src/proto/workload.proto"], ["src/proto"])
        .context("failed to compile protocol buffer file set")?;

    tonic_build::configure()
        .build_client(true)
        .out_dir(&out_dir)
        .compile_fds_with_config(proto_config, file_descriptors)
        .context("failed to compile protocol buffers")?;

    Ok(())
}
