//! Build script for compiling Protocol Buffer definitions with tonic.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = [
        "proto/argus/v1/common.proto",
        "proto/argus/v1/auth.proto",
        "proto/argus/v1/billing.proto",
        "proto/argus/v1/identity.proto",
    ];

    // Configure tonic-build
    tonic_build::configure()
        // Generate server code
        .build_server(true)
        // Generate client code
        .build_client(true)
        // Include file descriptors for reflection
        .file_descriptor_set_path(
            std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("argus_descriptor.bin"),
        )
        // Compile all proto files
        .compile(&proto_files, &["proto"])?;

    // Tell Cargo to rerun if protos change
    for proto in &proto_files {
        println!("cargo:rerun-if-changed={proto}");
    }

    Ok(())
}
