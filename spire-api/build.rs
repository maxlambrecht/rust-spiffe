use std::env;

fn main() -> Result<(), anyhow::Error> {
    // Check if this is a docs.rs build
    let is_docs_rs = env::var_os("DOCS_RS").is_some();

    if !is_docs_rs {
        let mut proto_config = prost_build::Config::new();
        proto_config.bytes(["."]);
        tonic_build::configure()
            .build_client(true)
            .out_dir("src/proto")
            .compile_protos_with_config(
                proto_config,
                &[
                    "spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.\
                     proto",
                ],
                &["spire-api-sdk/proto"],
            )?;
    } else {
        println!("cargo:warning=Skipping protobuf code generation on docs.rs.");
    }

    Ok(())
}
