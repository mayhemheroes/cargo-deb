use honggfuzz::fuzz;
use cargo_deb::*;
use cargo_deb::control::ControlArchiveBuilder;
use std::path::Path;
use std::fs;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

struct CliOptions {
    no_build: bool,
    strip_override: Option<bool>,
    separate_debug_symbols: bool,
    fast: bool,
    verbose: bool,
    quiet: bool,
    install: bool,
    selected_package_name: Option<String>,
    output_path: Option<String>,
    variant: Option<String>,
    target: Option<String>,
    manifest_path: Option<String>,
    cargo_build_cmd: String,
    cargo_build_flags: Vec<String>,
    deb_version: Option<String>,
    deb_revision: Option<String>,
    system_xz: bool,
    profile: Option<String>,
}

/*fn random_bool() -> bool {
    rand::thread_rng().gen_bool(0.5)
}*/

fn process(
    CliOptions {
        manifest_path,
        output_path,
        selected_package_name,
        variant,
        target,
        install,
        no_build,
        strip_override,
        separate_debug_symbols,
        quiet,
        fast,
        verbose,
        cargo_build_cmd,
        mut cargo_build_flags,
        deb_version,
        deb_revision,
        system_xz,
        profile,
    }: CliOptions,
) -> CDResult<()> {
    let target = target.as_deref();
    let variant = variant.as_deref();

    // `cargo deb` invocation passes the `deb` arg through.
    if cargo_build_flags.first().map_or(false, |arg| arg == "deb") {
        cargo_build_flags.remove(0);
    }

    // Listener conditionally prints warnings
    let listener_tmp1;
    let listener_tmp2;
    let listener: &dyn listener::Listener = if quiet {
        listener_tmp1 = listener::NoOpListener;
        &listener_tmp1
    } else {
        listener_tmp2 = listener::StdErrListener { verbose };
        &listener_tmp2
    };

    // The profile is selected based on the given ClI options and then passed to
    // cargo build accordingly. you could argue that the other way around is
    // more desirable. However for now we want all commands coming in via the
    // same `interface`
    let selected_profile = profile.as_deref().unwrap_or("release");
    if selected_profile == "dev" {
        listener.warning("dev profile is not supported and will be a hard error in the future. \
            cargo-deb is for making releases, and it doesn't make sense to use it with dev profiles.".into());
        listener.warning("To enable debug symbols set `[profile.release] debug = true` instead.".into());
    }
    cargo_build_flags.push(format!("--profile={selected_profile}"));

    let manifest_path = manifest_path.as_ref().map_or("Cargo.toml", |s| s.as_str());
    let mut options = Config::from_manifest(
        Path::new(manifest_path),
        selected_package_name.as_deref(),
        output_path,
        target,
        variant,
        deb_version,
        deb_revision,
        listener,
        selected_profile,
    )?;
    reset_deb_temp_directory(&options)?;

    options.extend_cargo_build_flags(&mut cargo_build_flags);

    if !no_build {
        cargo_build(&options, target, &cargo_build_cmd, &cargo_build_flags, verbose)?;
    }

    options.resolve_assets()?;

    crate::data::compress_assets(&mut options, listener)?;

    if strip_override.unwrap_or(separate_debug_symbols || !options.debug_enabled) {
        strip_binaries(&mut options, target, listener, separate_debug_symbols)?;
    } else {
        log::debug!("not stripping profile.release.debug={} strip-flag={:?}", options.debug_enabled, strip_override);
    }

    // Obtain the current time which will be used to stamp the generated files in the archives.
    let default_timestamp = options.default_timestamp;

    let options = &options;
    let (control_builder, data_result) = rayon::join(
        move || {
            // The control archive is the metadata for the package manager
            let mut control_builder = ControlArchiveBuilder::new(compress::xz_or_gz(fast, system_xz)?, default_timestamp, listener);
            control_builder.generate_archive(options)?;
            Ok::<_, CargoDebError>(control_builder)
        },
        move || {
            // Initialize the contents of the data archive (files that go into the filesystem).
            let (compressed, asset_hashes) = data::generate_archive(compress::xz_or_gz(fast, system_xz)?, &options, default_timestamp, listener)?;
            let original_data_size = compressed.uncompressed_size;
            Ok::<_, CargoDebError>((compressed.finish()?, original_data_size, asset_hashes))
        },
    );
    let mut control_builder = control_builder?;
    let (data_compressed, original_data_size, asset_hashes) = data_result?;
    control_builder.generate_md5sums(options, asset_hashes)?;
    let control_compressed = control_builder.finish()?.finish()?;

    let mut deb_contents = DebArchive::new(&options)?;
    deb_contents.add_data("debian-binary".into(), default_timestamp, b"2.0\n")?;

    // Order is important for Debian
    deb_contents.add_data(format!("control.tar.{}", control_compressed.extension()), default_timestamp, &control_compressed)?;
    drop(control_compressed);
    let compressed_data_size = data_compressed.len();
    listener.info(format!(
        "compressed/original ratio {compressed_data_size}/{original_data_size} ({}%)",
        compressed_data_size * 100 / original_data_size
    ));
    deb_contents.add_data(format!("data.tar.{}", data_compressed.extension()), default_timestamp, &data_compressed)?;
    drop(data_compressed);

    let generated = deb_contents.finish()?;
    if !quiet {
        println!("{}", generated.display());
    }

    remove_deb_temp_directory(options);

    if install {
        install_deb(&generated)?;
    }
    Ok(())
}

// Fuzzing

fn fuzz_input(input: &str, split_index: usize) {
    let (input_manifest, input_main_rs) = input.split_at(split_index);

    // Create a temporary directory for the fuzz input
    let temp_dir = tempfile::tempdir().unwrap();
    let manifest_path = temp_dir.path().join("Cargo.toml");

    // Write the fuzz input to the temporary Cargo.toml
    if fs::write(&manifest_path, input_manifest).is_err() {
        return;
    }

    // Create a temporary "src" directory with a "main.rs" file
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("main.rs"), input_main_rs).unwrap();

    // Make sure the temporary manifest_path exists
    if !manifest_path.exists() {
        return;
    }

    // Run cargo-deb with the temporary manifest_path and src_dir
    for i in 0..32 {
        let no_build = (i >> 0) % 2 == 1;
        let separate_debug_symbols = (i >> 1) % 2 == 1;
        let fast = (i >> 2) % 2 == 1;
        let system_xz = (i >> 3) % 2 == 1;
        
        for strip_override_index in 0..3 {
            let strip_override = match strip_override_index {
                0 => Some(true),
                1 => Some(false),
                _ => None,
            };
    
            let cli_options = CliOptions {
                no_build,
                strip_override,
                separate_debug_symbols,
                fast,
                verbose: false,
                quiet: true,
                install: false,
                selected_package_name: None,
                output_path: None,
                variant: None,
                target: None,
                manifest_path: Some(manifest_path.to_string_lossy().to_string()),
                cargo_build_cmd: "build".to_string(),
                cargo_build_flags: vec![],
                deb_version: None,
                deb_revision: None,
                system_xz,
                profile: None,
            };
    
            // Run the process function with the temporary manifest_path
            let _result = std::panic::catch_unwind(|| {
                process(cli_options)
            });
        }
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Convert the fuzz input data to a string
            if let Ok(input) = std::str::from_utf8(data) {
                if data.len() < 32 {
                    return;
                }
    
                // Create a seed for rng
                let mut seed = [0u8; 32];
                for (dst, src) in seed.iter_mut().zip(data.iter()) {
                    *dst = *src;
                }

                let mut rng = StdRng::from_seed(seed);

                // Fuzz the input at a random split index
                let split_index = rng.gen_range(0..=input.len());
                fuzz_input(input, split_index);
            }
        });
    }
}