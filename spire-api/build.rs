fn main() -> Result<(), anyhow::Error> {
    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);
    tonic_build::configure()
        .build_client(true)
        .out_dir("src/proto")
        .compile_with_config(
            proto_config,
            &["spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto"],
            &["spire-api-sdk/proto"], 
        )?;

    Ok(())
}
