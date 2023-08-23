use std::path::Path;
use std::process::Command;

const SPIRE_API_SDK_TAG: &str = "v1.7.2";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = Path::new("../spire-api-sdk");
    if !destination.exists() {
        let status = Command::new("git")
            .args(&[
                "clone",
                "https://github.com/spiffe/spire-api-sdk.git",
                destination.to_str().unwrap(),
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to clone repository".into());
        }

        // Checkout the specific tag
        let status = Command::new("git")
            .current_dir(destination)
            .args(&["checkout", SPIRE_API_SDK_TAG])
            .status()?;

        if !status.success() {
            return Err("Failed to checkout tag".into());
        }
    }

    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);
    tonic_build::configure()
        .build_client(true)
        .out_dir("src/proto")
        .compile_with_config(
            proto_config,
            &["../spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto"],
            &["../spire-api-sdk/proto"],
        )?;

    Ok(())
}
