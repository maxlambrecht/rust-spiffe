use std::{env, fs};

fn main() -> Result<(), anyhow::Error> {
    // Check if this is a docs.rs build
    let is_docs_rs = env::var_os("DOCS_RS").is_some();

    if !is_docs_rs {
        let mut proto_config = prost_build::Config::new();
        proto_config.bytes(["."]);
        let file_descriptors = protox::compile(["src/proto/workload.proto"], ["src/proto"])?;
        tonic_build::configure()
            .build_client(true)
            .out_dir("src/proto")
            .compile_fds_with_config(proto_config, file_descriptors)?;

        fs::rename("src/proto/_.rs", "src/proto/workload.rs")?;
    } else {
        println!("cargo:warning=Skipping protobuf code generation on docs.rs.");
    }

    Ok(())
}
