use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=X25519-Cortex-M4/x25519-cortex-m4-gcc.s");

    let target = env::var("TARGET")?;

    if target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main") {
        // Feature to see if we will run with Cortex-M DSP asm.
        println!("cargo:rustc-cfg=cortex_m4");

        // Build asm.
        cc::Build::new()
            .flag("-std=c11")
            .file("X25519-Cortex-M4/x25519-cortex-m4-gcc.s")
            .flag("-march=armv7e-m")
            .compile("x25519-cortex-m4-sys");
    }

    Ok(())
}
