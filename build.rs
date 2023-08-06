use std::fs;

fn main() -> Result<(), anyhow::Error> {
    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);
    tonic_build::configure()
        .build_client(true)
        .out_dir("src/proto")
        .compile_with_config(proto_config, &["src/proto/workload.proto"], &["src/proto"])?;

    fs::rename("src/proto/_.rs", "src/proto/workload.rs")?;

    Ok(())
}
