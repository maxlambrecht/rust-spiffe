// spiffe-rustls/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only generate code when grpc examples are enabled.
    if std::env::var("CARGO_FEATURE_GRPC_EXAMPLES").is_err() {
        return Ok(());
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/helloworld.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/helloworld.proto");
    Ok(())
}
