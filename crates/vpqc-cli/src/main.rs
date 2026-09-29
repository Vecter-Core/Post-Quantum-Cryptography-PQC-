//! `vpqc` command-line tool.

mod cose;
mod jose;
mod ssh;
mod x509;

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
    /// Repeat --to for several recipients (up to 32, e.g. a user key and a recovery key):
    /// each can decrypt with their own secret key.
    Encrypt {
        /// Recipient public key file (repeatable).
        #[arg(long, required = true)]
        to: Vec<PathBuf>,
        /// Use the envelope (multi-recipient) format even for one recipient, so that the
        /// recipients can later be changed with `vpqc rewrap` (e.g. key rotation).
        #[arg(long)]
        envelope: bool,
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
    /// Change the recipients of an envelope (a file encrypted with several --to, or with
    /// --envelope) without re-encrypting its data. You must be a current recipient. Removing a
    /// recipient does not revoke data they already decrypted or the file key they know.
    Rewrap {
        /// Your secret key (a current recipient).
        #[arg(long)]
        key: PathBuf,
        /// New recipient public key file (repeatable); the complete new list.
        #[arg(long, required = true)]
        to: Vec<PathBuf>,
        /// Authenticated context used when encrypting.
        #[arg(long, default_value = "")]
        aad: String,
        /// Output file.
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
        /// Input file.
        input: PathBuf,
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
    /// Post-quantum JWKs (`AKP`, ML-DSA) for JOSE.
    Jwk {
        #[command(subcommand)]
        command: jose::JwkCommand,
    },
    /// Compact JWS signed with ML-DSA.
    Jws {
        #[command(subcommand)]
        command: jose::JwsCommand,
    },
    /// JSON Web Tokens signed with ML-DSA.
    Jwt {
        #[command(subcommand)]
        command: jose::JwtCommand,
    },
    /// COSE_Sign1 with ML-DSA (binary counterpart of JWS, for IoT and attestation).
    Cose {
        #[command(subcommand)]
        command: cose::CoseCommand,
    },
    /// CBOR Web Tokens signed with ML-DSA.
    Cwt {
        #[command(subcommand)]
        command: cose::CwtCommand,
    },
    /// SSH: check whether a server offers a post-quantum key exchange.
    Ssh {
        #[command(subcommand)]
        command: ssh::SshCommand,
    },
    /// Post-quantum X.509: ML-DSA keys, certificates, chain verification.
    X509 {
        #[command(subcommand)]
        command: x509::X509Command,
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
            envelope,
            aad,
            output,
            force,
            input,
        } => {
            let pks = read_public_keys(&to)?;
            let refs: Vec<_> = pks.iter().collect();
            let aad = aad.as_bytes();
            if let ([pk], false) = (&refs[..], envelope) {
                // One recipient: the single-recipient format (ADR-0007).
                run_stream(
                    true,
                    &input,
                    &output,
                    force,
                    |r, w| vpqc::stream::seal_stream(pk, aad, r, w),
                    |r, o| vpqc::stream::encrypt_to_file(pk, aad, r, o),
                )
            } else {
                run_stream(
                    true,
                    &input,
                    &output,
                    force,
                    |r, w| vpqc::stream::seal_stream_multi(&refs, aad, r, w),
                    |r, o| vpqc::stream::encrypt_to_file_multi(&refs, aad, r, o),
                )
            }
        }
        Command::Rewrap {
            key,
            to,
            aad,
            output,
            force,
            input,
        } => {
            let sk =
                keys::secret_from_bytes(&read_key_bytes(&key, "VPQC SECRET KEY")?).map_err(err)?;
            let pks = read_public_keys(&to)?;
            let refs: Vec<_> = pks.iter().collect();
            if output.exists() && !force {
                return Err(format!(
                    "{}: already exists (use --force to overwrite)",
                    output.display()
                ));
            }
            vpqc::stream::rewrap_file(&sk, aad.as_bytes(), &refs, &input, &output)
                .map(|_| ())
                .map_err(|e| stream_error(&e))
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
        Command::Jwk { command } => jose::jwk(command),
        Command::Jws { command } => jose::jws(command),
        Command::Jwt { command } => jose::jwt(command),
        Command::X509 { command } => x509::run(command),
        Command::Ssh { command } => ssh::run(command),
        Command::Cose { command } => cose::cose(command),
        Command::Cwt { command } => cose::cwt(command),
    }
}

fn read_public_keys(paths: &[PathBuf]) -> Result<Vec<vpqc::PublicKey>, String> {
    paths
        .iter()
        .map(|p| {
            keys::public_from_bytes(&read_key_bytes(p, "VPQC PUBLIC KEY")?)
                .map_err(|e| format!("{}: {e}", p.display()))
        })
        .collect()
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
    if let Ok(h) = vpqc_format::AnyStreamHeader::decode_prefix(&prefix) {
        let (header_len, kems) = match &h {
            vpqc_format::AnyStreamHeader::Single(s) => {
                (12 + s.kem_ciphertext.len() as u64, vec![s.kem])
            }
            vpqc_format::AnyStreamHeader::Multi(m) => (
                m.encode().map(|e| e.len() as u64).unwrap_or(0),
                m.recipients.iter().map(|r| r.kem).collect(),
            ),
        };
        let cs = h.chunk_size() as u64;
        let body = size.saturating_sub(header_len);
        let chunks = body.div_ceil(cs + 16).max(1);
        if let [kem] = kems[..] {
            println!(
                "stream     : KEM {}, AEAD ChaCha20-Poly1305, {} KiB chunks",
                describe_alg(AlgorithmId::Kem(kem)),
                cs / 1024
            );
        } else {
            println!(
                "stream     : {} recipients, AEAD ChaCha20-Poly1305, {} KiB chunks",
                kems.len(),
                cs / 1024
            );
            for (i, kem) in kems.iter().enumerate() {
                println!(
                    "recipient {i:<2}: KEM {}",
                    describe_alg(AlgorithmId::Kem(*kem))
                );
            }
        }
        println!(
            "size       : {size} bytes, about {} bytes of plaintext in {chunks} chunk(s)",
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
