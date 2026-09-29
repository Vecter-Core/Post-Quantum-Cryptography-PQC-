//! `vpqc` command-line tool.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use vpqc::{Error, Profile, encryption, keys, signing};
use vpqc_core::AlgorithmId;
use vpqc_format::{DetachedSignature, Sealed, dearmor};

#[derive(Parser)]
#[command(
    name = "vpqc",
    version,
    about = "Post-quantum cryptography with safe defaults (pre-release, unaudited)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Purpose {
    /// Encryption key pair (KEM).
    Encrypt,
    /// Signing key pair.
    Sign,
}

#[derive(Clone, Copy, ValueEnum)]
enum ScanFormat {
    /// Human-readable report.
    Text,
    /// Machine-readable report.
    Json,
    /// CycloneDX 1.6 cryptographic bill of materials.
    Cbom,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    /// Exit non-zero if any quantum-vulnerable finding exists.
    QuantumVulnerable,
    /// Exit non-zero on quantum-vulnerable or weak findings.
    Weak,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Standard,
    FastAuth,
    Cnsa2,
    High,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Standard => Profile::Standard,
            ProfileArg::FastAuth => Profile::FastAuth,
            ProfileArg::Cnsa2 => Profile::Cnsa2,
            ProfileArg::High => Profile::High,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// List profiles and the algorithms they select.
    Profiles,
    /// Generate a key pair: writes <OUT>.pub and <OUT>.vpqc-secret (mode 0600).
    Keygen {
        /// What the key is for.
        #[arg(long, value_enum)]
        purpose: Purpose,
        /// Profile.
        #[arg(long, value_enum, default_value = "standard")]
        profile: ProfileArg,
        /// Output path prefix.
        #[arg(long)]
        out: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a file or stream of any size (constant memory). Recommended for files.
    Encrypt {
        /// Recipient public key file.
        #[arg(long)]
        to: PathBuf,
        /// Authenticated context; must be given again to decrypt.
        #[arg(long, default_value = "")]
        aad: String,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Decrypt a stream produced by `encrypt`. With `-o FILE`, the file appears only if the
    /// whole stream verifies; to stdout, output must be discarded if the exit code is non-zero.
    Decrypt {
        /// Secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Authenticated context used when encrypting.
        #[arg(long, default_value = "")]
        aad: String,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Encrypt a message that fits in memory (sealed box). Use `-` for stdin/stdout.
    Seal {
        /// Recipient public key file.
        #[arg(long)]
        to: PathBuf,
        /// Authenticated context; must be given again to open.
        #[arg(long, default_value = "")]
        aad: String,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Decrypt a sealed file with a secret key.
    Open {
        /// Secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Authenticated context used when sealing.
        #[arg(long, default_value = "")]
        aad: String,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Sign a file (detached signature).
    Sign {
        /// Secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Domain-separation context, e.g. "my-app/release-v1" (at most 255 bytes).
        #[arg(long)]
        context: String,
        /// Signature output file.
        #[arg(short, long)]
        output: PathBuf,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Verify a detached signature.
    Verify {
        /// Public key file.
        #[arg(long)]
        key: PathBuf,
        /// Domain-separation context used when signing.
        #[arg(long)]
        context: String,
        /// Signature file.
        #[arg(long)]
        sig: PathBuf,
        /// Input file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Inventory cryptography in a directory: quantum-vulnerable algorithms in code, configs,
    /// certificates and key files (pattern-based for code; certificates are parsed exactly).
    Scan {
        /// File or directory to scan.
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ScanFormat,
        /// Include informational findings (strong symmetric algorithms) in text output.
        #[arg(long)]
        all: bool,
        /// Also scan documentation files (.md, .txt, ...).
        #[arg(long)]
        include_docs: bool,
        /// Also report mentions inside comment lines.
        #[arg(long)]
        include_comments: bool,
        /// Skip paths containing this text (repeatable).
        #[arg(long)]
        exclude: Vec<String>,
        /// Exit with status 2 if findings of this severity (or worse) exist. For CI gating.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Write the report to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Describe a key, sealed file or signature.
    Inspect {
        /// File to inspect.
        file: PathBuf,
    },
}

type CliResult = Result<(), String>;

fn err(e: Error) -> String {
    e.to_string()
}

fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) if p != Path::new("-") => fs::read(p).map_err(|e| format!("{}: {e}", p.display())),
        _ => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            Ok(buf)
        }
    }
}

fn write_output(path: &Option<PathBuf>, data: &[u8]) -> CliResult {
    match path {
        Some(p) if p != Path::new("-") => {
            fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))
        }
        _ => std::io::stdout().write_all(data).map_err(|e| e.to_string()),
    }
}

/// Read a key file that is either armored text or binary.
fn read_key_bytes(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let raw = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    match std::str::from_utf8(&raw) {
        Ok(text) if text.trim_start().starts_with("-----BEGIN") => {
            dearmor(label, text).map_err(err)
        }
        _ => Ok(raw),
    }
}

fn write_new(path: &Path, data: &[u8], secret: bool, force: bool) -> CliResult {
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let _ = secret;
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e} (use --force to overwrite)", path.display()))?;
    f.write_all(data).map_err(|e| e.to_string())
}

fn describe_alg(alg: AlgorithmId) -> String {
    let pq = match alg {
        AlgorithmId::Kem(k) if k.is_hybrid() => "hybrid classical + post-quantum",
        AlgorithmId::Kem(_) => "post-quantum",
        AlgorithmId::Sig(s) if s.is_post_quantum() => "post-quantum (or composite with it)",
        AlgorithmId::Sig(_) => "CLASSICAL ONLY: not quantum-resistant",
    };
    format!("{} [{pq}]", alg.name())
}

fn run(cli: Cli) -> CliResult {
    match cli.command {
        Command::Profiles => {
            println!("{:<10} {:<32} SIGNATURES", "PROFILE", "ENCRYPTION");
            for p in Profile::ALL {
                println!(
                    "{:<10} {:<32} {}",
                    p.name(),
                    p.kem().name(),
                    p.signature().name()
                );
            }
            Ok(())
        }
        Command::Keygen {
            purpose,
            profile,
            out,
            force,
        } => {
            let profile: Profile = profile.into();
            let pair = match purpose {
                Purpose::Encrypt => encryption::generate(profile),
                Purpose::Sign => signing::generate(profile),
            }
            .map_err(err)?;
            let mut pub_path = out.clone().into_os_string();
            pub_path.push(".pub");
            let mut sec_path = out.into_os_string();
            sec_path.push(".vpqc-secret");
            write_new(
                Path::new(&pub_path),
                keys::public_to_text(&pair.public).as_bytes(),
                false,
                force,
            )?;
            write_new(
                Path::new(&sec_path),
                keys::secret_to_text(&pair.secret).as_bytes(),
                true,
                force,
            )?;
            eprintln!("algorithm : {}", describe_alg(pair.public.algorithm()));
            eprintln!("public    : {}", Path::new(&pub_path).display());
            eprintln!(
                "secret    : {}  (unencrypted; keep it private)",
                Path::new(&sec_path).display()
            );
            Ok(())
        }
        Command::Encrypt {
            to,
            aad,
            output,
            force,
            input,
        } => {
            let pk =
                keys::public_from_bytes(&read_key_bytes(&to, "VPQC PUBLIC KEY")?).map_err(err)?;
            run_stream(
                true,
                &input,
                &output,
                force,
                |r, w| vpqc::stream::seal_stream(&pk, aad.as_bytes(), r, w),
                |r, o| vpqc::stream::encrypt_to_file(&pk, aad.as_bytes(), r, o),
            )
        }
        Command::Decrypt {
            key,
            aad,
            output,
            force,
            input,
        } => {
            let sk =
                keys::secret_from_bytes(&read_key_bytes(&key, "VPQC SECRET KEY")?).map_err(err)?;
            run_stream(
                false,
                &input,
                &output,
                force,
                |r, w| vpqc::stream::open_stream(&sk, aad.as_bytes(), r, w),
                |r, o| vpqc::stream::decrypt_to_file(&sk, aad.as_bytes(), r, o),
            )
        }
        Command::Seal {
            to,
            aad,
            output,
            input,
        } => {
            let pk =
                keys::public_from_bytes(&read_key_bytes(&to, "VPQC PUBLIC KEY")?).map_err(err)?;
            let data = read_input(&input)?;
            let sealed = encryption::seal(&pk, &data, aad.as_bytes()).map_err(err)?;
            write_output(&output, &sealed)
        }
        Command::Open {
            key,
            aad,
            output,
            input,
        } => {
            let sk =
                keys::secret_from_bytes(&read_key_bytes(&key, "VPQC SECRET KEY")?).map_err(err)?;
            let data = read_input(&input)?;
            let plain = encryption::open(&sk, &data, aad.as_bytes()).map_err(err)?;
            write_output(&output, &plain)
        }
        Command::Sign {
            key,
            context,
            output,
            input,
        } => {
            let sk =
                keys::secret_from_bytes(&read_key_bytes(&key, "VPQC SECRET KEY")?).map_err(err)?;
            let data = read_input(&input)?;
            let sig = signing::sign(&sk, &data, context.as_bytes()).map_err(err)?;
            write_output(&Some(output), &sig)
        }
        Command::Verify {
            key,
            context,
            sig,
            input,
        } => {
            let pk =
                keys::public_from_bytes(&read_key_bytes(&key, "VPQC PUBLIC KEY")?).map_err(err)?;
            let sig = fs::read(&sig).map_err(|e| format!("{}: {e}", sig.display()))?;
            let data = read_input(&input)?;
            signing::verify(&pk, &data, context.as_bytes(), &sig).map_err(err)?;
            eprintln!("signature OK ({})", describe_alg(pk.algorithm()));
            Ok(())
        }
        Command::Scan {
            path,
            format,
            all,
            include_docs,
            include_comments,
            exclude,
            fail_on,
            output,
        } => {
            let options = vpqc_scan::Options {
                include_docs,
                include_comments,
                exclude,
                ..Default::default()
            };
            let report = vpqc_scan::scan_path(&path, &options)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let text = match format {
                ScanFormat::Text => vpqc_scan::to_text(&report, all),
                ScanFormat::Json => vpqc_scan::to_json(&report),
                ScanFormat::Cbom => vpqc_scan::to_cbom(&report),
            };
            write_output(&output, text.as_bytes())?;
            let bad = match fail_on {
                Some(FailOn::QuantumVulnerable) => {
                    report.count(vpqc_scan::Risk::QuantumVulnerable) > 0
                }
                Some(FailOn::Weak) => {
                    report.count(vpqc_scan::Risk::QuantumVulnerable)
                        + report.count(vpqc_scan::Risk::Weak)
                        > 0
                }
                None => false,
            };
            if bad {
                eprintln!("vpqc scan: policy failed (--fail-on)");
                std::process::exit(2);
            }
            Ok(())
        }
        Command::Inspect { file } => inspect(&file),
    }
}

fn is_stdio(p: &Option<PathBuf>) -> bool {
    p.as_deref().is_none_or(|p| p == Path::new("-"))
}

fn open_reader(input: &Option<PathBuf>) -> Result<Box<dyn Read>, String> {
    Ok(match input.as_deref().filter(|_| !is_stdio(input)) {
        Some(p) => Box::new(std::io::BufReader::with_capacity(
            1 << 16,
            fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?,
        )),
        None => Box::new(std::io::stdin().lock()),
    })
}

fn stream_error(e: &std::io::Error) -> String {
    match vpqc::stream::crypto_error(e) {
        Some(c) => c.to_string(),
        None => e.to_string(),
    }
}

/// Run a streaming operation. File-to-file uses the atomic file API; anything involving
/// stdin/stdout streams through buffers. For decryption to stdout, a failure is reported on
/// stderr with a non-zero exit code after partial output may already have been written.
fn run_stream(
    encrypting: bool,
    input: &Option<PathBuf>,
    output: &Option<PathBuf>,
    force: bool,
    streaming: impl FnOnce(&mut dyn Read, &mut dyn Write) -> std::io::Result<u64>,
    to_file: impl FnOnce(&mut dyn Read, &Path) -> std::io::Result<u64>,
) -> CliResult {
    if let Some(out) = output.as_deref().filter(|_| !is_stdio(output)) {
        if out.exists() && !force {
            return Err(format!(
                "{}: already exists (use --force to overwrite)",
                out.display()
            ));
        }
        // Any input -> file: written through a temporary file, renamed only on success.
        let mut reader = open_reader(input)?;
        to_file(&mut reader, out).map_err(|e| stream_error(&e))?;
        return Ok(());
    }
    let mut reader = open_reader(input)?;
    let mut stdout = std::io::BufWriter::with_capacity(1 << 16, std::io::stdout().lock());
    match streaming(&mut reader, &mut stdout) {
        Ok(_) => Ok(()),
        Err(e) if !encrypting => Err(format!(
            "{} (discard any output already written)",
            stream_error(&e)
        )),
        Err(e) => Err(stream_error(&e)),
    }
}

fn inspect(path: &Path) -> CliResult {
    // Streams can be huge: identify them from their header without reading the whole file.
    let size = fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    let mut prefix = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(1 << 16).read_to_end(&mut prefix))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if let Ok(h) = vpqc_format::StreamHeader::decode_prefix(&prefix) {
        let header_len = 12 + h.kem_ciphertext.len() as u64;
        let cs = h.chunk_size() as u64;
        let body = size.saturating_sub(header_len);
        let chunks = body.div_ceil(cs + 16).max(1);
        println!(
            "stream     : KEM {}, AEAD ChaCha20-Poly1305, {} KiB chunks\nsize       : {size} bytes, about {} bytes of plaintext in {chunks} chunk(s)",
            describe_alg(AlgorithmId::Kem(h.kem)),
            cs / 1024,
            body.saturating_sub(16 * chunks),
        );
        return Ok(());
    }
    let raw = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes = match std::str::from_utf8(&raw) {
        Ok(t) if t.trim_start().starts_with("-----BEGIN VPQC") => {
            let label = if t.contains("PUBLIC KEY") {
                "VPQC PUBLIC KEY"
            } else {
                "VPQC SECRET KEY"
            };
            dearmor(label, t).map_err(err)?
        }
        _ => raw,
    };
    if let Ok(pk) = keys::public_from_bytes(&bytes) {
        println!(
            "public key : {}\nsize       : {} bytes",
            describe_alg(pk.algorithm()),
            pk.as_bytes().len()
        );
    } else if let Ok(sk) = keys::secret_from_bytes(&bytes) {
        println!(
            "secret key : {}\nsize       : {} bytes (seed)",
            describe_alg(sk.algorithm()),
            sk.expose_bytes().len()
        );
    } else if let Ok(s) = Sealed::decode(&bytes) {
        println!(
            "sealed box : KEM {} ({} byte ciphertext), AEAD ChaCha20-Poly1305, body {} bytes",
            describe_alg(AlgorithmId::Kem(s.kem)),
            s.kem_ciphertext.len(),
            s.body.len()
        );
    } else if let Ok(s) = DetachedSignature::decode(&bytes) {
        println!(
            "signature  : {}\nsize       : {} bytes",
            describe_alg(AlgorithmId::Sig(s.algorithm)),
            s.bytes.len()
        );
    } else {
        return Err("not a recognised vpqc object".into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vpqc: {e}");
            ExitCode::FAILURE
        }
    }
}
