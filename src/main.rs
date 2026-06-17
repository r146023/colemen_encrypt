use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, ValueEnum};
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MAGIC: &[u8; 8] = b"CLENC001";
const FORMAT_VERSION: u32 = 1;
const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ARGON2_ITERATIONS: u32 = 3;
const DEFAULT_ARGON2_PARALLELISM: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const DATA_NONCE_PREFIX_LEN: usize = 4;
const METADATA_NONCE_PREFIX: [u8; DATA_NONCE_PREFIX_LEN] = *b"META";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CollisionMode {
    Skip,
    Rename,
    Overwrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VerifyMode {
    Full,
    Hash,
    Auth,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeleteStrategy {
    Unlink,
    #[value(name = "best_effort_overwrite", alias = "best-effort-overwrite")]
    BestEffortOverwrite,
    None,
}

#[derive(Parser, Debug)]
#[command(name = "colemen_encrypt")]
#[command(author, version, about)]
#[command(arg_required_else_help = true)]
struct Cli {
    /// Mode: encrypt or decrypt.
    #[arg(value_enum)]
    mode: Mode,

    /// A single file or directory to process.
    #[arg(long = "target")]
    target: Option<PathBuf>,

    /// A text file containing paths to files/directories, one per line.
    #[arg(long = "target_list", alias = "target-list")]
    target_list: Option<PathBuf>,

    /// Password used for encryption/decryption. Prefer --password_env when possible.
    #[arg(long = "password")]
    password: Option<String>,

    /// Name of an environment variable containing the password.
    #[arg(long = "password_env", alias = "password-env")]
    password_env: Option<String>,

    /// Optional output directory.
    #[arg(long = "output_dir", alias = "output-dir")]
    output_dir: Option<PathBuf>,

    /// Keep relative path structure inside output_dir.
    #[arg(long = "keep_relative_path", alias = "keep-relative-path", default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    keep_relative_path: bool,

    /// Keep original files after successful encryption/decryption.
    #[arg(long = "keep_original", alias = "keep-original", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    keep_original: bool,

    /// Number of worker threads.
    #[arg(long = "thread_count", alias = "thread-count", default_value_t = 4)]
    thread_count: usize,

    /// Process directories recursively.
    #[arg(long = "recursive", default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    recursive: bool,

    /// Preserve timestamps and permissions where supported.
    #[arg(long = "preserve_metadata", alias = "preserve-metadata", default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    preserve_metadata: bool,

    /// Simulate the operation without writing/deleting files.
    #[arg(long = "dry_run", alias = "dry-run", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    dry_run: bool,

    /// Print detailed human-readable logs.
    #[arg(long = "verbose", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    verbose: bool,

    /// Prefix applied to encrypted filenames. During decrypt, removed only if provided.
    #[arg(long = "prefix", default_value = "")]
    prefix: String,

    /// Suffix applied to encrypted filename stems. During decrypt, removed only if provided.
    #[arg(long = "suffix", default_value = "")]
    suffix: String,

    /// Output JSON Lines events instead of human-readable logs.
    #[arg(long = "machine_responses", alias = "machine-responses", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    machine_responses: bool,

    /// Encrypted file extension.
    #[arg(long = "extension", default_value = ".enc")]
    extension: String,

    /// Collision handling strategy.
    #[arg(long = "collision", value_enum, default_value = "skip")]
    collision: CollisionMode,

    /// Verification strategy.
    #[arg(long = "verify", value_enum, default_value = "full")]
    verify: VerifyMode,

    /// Original deletion strategy after successful verification.
    #[arg(long = "delete_strategy", alias = "delete-strategy", value_enum, default_value = "unlink")]
    delete_strategy: DeleteStrategy,

    /// Randomize encrypted output filenames and store original names only in encrypted metadata.
    #[arg(long = "private_names", alias = "private-names", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    private_names: bool,

    /// Encrypt files that already end with the encrypted extension.
    #[arg(long = "allow_double_encrypt", alias = "allow-double-encrypt", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    allow_double_encrypt: bool,

    /// Chunk size in bytes.
    #[arg(long = "chunk_size", alias = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: u64,

    /// Argon2id memory cost in KiB.
    #[arg(long = "argon2_memory_kib", alias = "argon2-memory-kib", default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    argon2_memory_kib: u32,

    /// Argon2id iteration count.
    #[arg(long = "argon2_iterations", alias = "argon2-iterations", default_value_t = DEFAULT_ARGON2_ITERATIONS)]
    argon2_iterations: u32,

    /// Argon2id parallelism.
    #[arg(long = "argon2_parallelism", alias = "argon2-parallelism", default_value_t = DEFAULT_ARGON2_PARALLELISM)]
    argon2_parallelism: u32,

    /// Stop after the first file-level failure.
    #[arg(long = "fail_fast", alias = "fail-fast", default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool)]
    fail_fast: bool,
}

fn parse_bool(s: &str) -> std::result::Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        other => Err(format!("expected true/false, got {other:?}")),
    }
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    mode: Mode,
    target: Option<PathBuf>,
    target_list: Option<PathBuf>,
    password: String,
    output_dir: Option<PathBuf>,
    keep_relative_path: bool,
    keep_original: bool,
    thread_count: usize,
    recursive: bool,
    preserve_metadata: bool,
    dry_run: bool,
    verbose: bool,
    prefix: String,
    suffix: String,
    machine_responses: bool,
    extension: String,
    collision: CollisionMode,
    verify: VerifyMode,
    delete_strategy: DeleteStrategy,
    private_names: bool,
    allow_double_encrypt: bool,
    chunk_size: u64,
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    argon2_parallelism: u32,
    fail_fast: bool,
}

impl RuntimeConfig {
    fn from_cli(cli: Cli) -> Result<Self> {
        if cli.target.is_some() == cli.target_list.is_some() {
            bail!("provide exactly one of --target or --target_list");
        }

        if cli.password.is_some() == cli.password_env.is_some() {
            bail!("provide exactly one of --password or --password_env");
        }

        if cli.thread_count == 0 {
            bail!("--thread_count must be greater than 0");
        }

        if cli.chunk_size == 0 || cli.chunk_size > (u32::MAX as u64 - 32) {
            bail!("--chunk_size must be between 1 and {} bytes", u32::MAX - 32);
        }

        if cli.argon2_memory_kib < 8 * 1024 {
            bail!("--argon2_memory_kib should be at least 8192 KiB");
        }

        if cli.argon2_iterations == 0 || cli.argon2_parallelism == 0 {
            bail!("Argon2 iterations and parallelism must be greater than 0");
        }

        let password = match (cli.password, cli.password_env) {
            (Some(p), None) => p,
            (None, Some(var)) => env::var(&var)
                .with_context(|| format!("failed to read password from environment variable {var:?}"))?,
            _ => unreachable!(),
        };

        if password.is_empty() {
            bail!("password cannot be empty");
        }

        Ok(Self {
            mode: cli.mode,
            target: cli.target,
            target_list: cli.target_list,
            password,
            output_dir: cli.output_dir,
            keep_relative_path: cli.keep_relative_path,
            keep_original: cli.keep_original,
            thread_count: cli.thread_count,
            recursive: cli.recursive,
            preserve_metadata: cli.preserve_metadata,
            dry_run: cli.dry_run,
            verbose: cli.verbose,
            prefix: cli.prefix,
            suffix: cli.suffix,
            machine_responses: cli.machine_responses,
            extension: normalize_extension(&cli.extension),
            collision: cli.collision,
            verify: cli.verify,
            delete_strategy: cli.delete_strategy,
            private_names: cli.private_names,
            allow_double_encrypt: cli.allow_double_encrypt,
            chunk_size: cli.chunk_size,
            argon2_memory_kib: cli.argon2_memory_kib,
            argon2_iterations: cli.argon2_iterations,
            argon2_parallelism: cli.argon2_parallelism,
            fail_fast: cli.fail_fast,
        })
    }
}

#[derive(Debug, Clone)]
struct WorkItem {
    source: PathBuf,
    relative_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfHeader {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicHeader {
    format: String,
    format_version: u32,
    cipher: String,
    kdf: KdfHeader,
    chunk_size: u64,
    data_nonce_prefix_hex: String,
    filename_mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredMetadata {
    original_file_name: String,
    original_size: u64,
    chunk_size: u64,
    chunk_count: u64,
    plaintext_sha256: Option<String>,
    readonly: bool,
    modified_unix_ms: Option<i128>,
    accessed_unix_ms: Option<i128>,
    created_unix_ms: Option<i128>,
    #[cfg(unix)]
    unix_mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct MachineEventStart {
    #[serde(rename = "type")]
    event_type: &'static str,
    mode: Mode,
    dry_run: bool,
    thread_count: usize,
    item_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MachineEventSummary {
    #[serde(rename = "type")]
    event_type: &'static str,
    mode: Mode,
    files_total: usize,
    files_success: usize,
    files_failed: usize,
    files_skipped: usize,
    warnings: usize,
    duration_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct FileReport {
    #[serde(rename = "type")]
    event_type: String,
    mode: Mode,
    source: String,
    destination: Option<String>,
    status: String,
    bytes_read: u64,
    bytes_written: u64,
    duration_ms: u128,
    original_deleted: bool,
    deletion_strategy: DeleteStrategy,
    deletion_assurance: String,
    warnings: Vec<String>,
    error: Option<String>,
}

impl FileReport {
    fn warning(mode: Mode, source: &Path, warning: impl Into<String>) -> Self {
        Self {
            event_type: "file_warning".to_string(),
            mode,
            source: path_to_string(source),
            destination: None,
            status: "skipped".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms: 0,
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: vec![warning.into()],
            error: None,
        }
    }

    fn error(mode: Mode, source: &Path, destination: Option<&Path>, error: impl Into<String>, duration_ms: u128) -> Self {
        Self {
            event_type: "file_error".to_string(),
            mode,
            source: path_to_string(source),
            destination: destination.map(path_to_string),
            status: "failed".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms,
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: Vec::new(),
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone)]
struct PathPlan {
    destination: PathBuf,
    skipped: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct EncryptStats {
    bytes_read: u64,
    bytes_written: u64,
}

#[derive(Debug)]
struct DecryptStats {
    bytes_read: u64,
    bytes_written: u64,
    metadata: StoredMetadata,
}

fn main() {
    let exit_code = match real_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ERROR: {err:#}");
            2
        }
    };
    process::exit(exit_code);
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let mut config = RuntimeConfig::from_cli(cli)?;
    let started = Instant::now();

    if !config.machine_responses {
        print_banner(&config);
    }

    let mut discovery_reports = Vec::new();
    let work_items = collect_work_items(&config, &mut discovery_reports)?;

    if config.machine_responses {
        print_json_line(&MachineEventStart {
            event_type: "start",
            mode: config.mode,
            dry_run: config.dry_run,
            thread_count: config.thread_count,
            item_count: work_items.len(),
        })?;
    } else {
        println!("Discovered {} file(s).", work_items.len());
        if config.dry_run {
            println!("DRY RUN: no files will be written or deleted.");
        }
        println!("SSD deletion note: file-level deletion is best-effort only; permanent SSD sanitization is not guaranteed.");
        println!();
    }

    let mut reports = discovery_reports;

    if config.fail_fast {
        for item in &work_items {
            let report = process_item(&config, item);
            let failed = report.status == "failed";
            reports.push(report);
            if failed {
                break;
            }
        }
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.thread_count)
            .build()
            .context("failed to initialize worker thread pool")?;

        let mut file_reports = pool.install(|| {
            work_items
                .par_iter()
                .map(|item| process_item(&config, item))
                .collect::<Vec<_>>()
        });
        reports.append(&mut file_reports);
    }

    reports.sort_by(|a, b| a.source.cmp(&b.source));

    for report in &reports {
        if config.machine_responses {
            print_json_line(report)?;
        } else {
            print_human_file_report(report, config.verbose);
        }
    }

    let summary = summarize(config.mode, &reports, started.elapsed());

    if config.machine_responses {
        print_json_line(&summary)?;
    } else {
        print_human_summary(&summary);
    }

    config.password.zeroize();

    if summary.files_failed > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn print_banner(config: &RuntimeConfig) {
    println!("colemen_encrypt {:?}", config.mode);
    println!("verify={:?}, collision={:?}, delete_strategy={:?}", config.verify, config.collision, config.delete_strategy);
    println!();
}

fn collect_work_items(config: &RuntimeConfig, reports: &mut Vec<FileReport>) -> Result<Vec<WorkItem>> {
    let mut items = Vec::new();

    if let Some(target) = &config.target {
        collect_path(config, target, reports, &mut items)?;
    }

    if let Some(target_list) = &config.target_list {
        let content = fs::read_to_string(target_list)
            .with_context(|| format!("failed to read target_list {}", target_list.display()))?;

        for (line_no, raw_line) in content.lines().enumerate() {
            let trimmed = trim_list_line(raw_line);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let path = PathBuf::from(trimmed);
            if !path.exists() {
                reports.push(FileReport::warning(
                    config.mode,
                    &path,
                    format!("target_list line {} does not exist; skipped", line_no + 1),
                ));
                continue;
            }
            collect_path(config, &path, reports, &mut items)?;
        }
    }

    dedupe_work_items(&mut items);
    Ok(items)
}

fn collect_path(
    config: &RuntimeConfig,
    path: &Path,
    reports: &mut Vec<FileReport>,
    items: &mut Vec<WorkItem>,
) -> Result<()> {
    if !path.exists() {
        reports.push(FileReport::warning(config.mode, path, "source path does not exist; skipped"));
        return Ok(());
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            reports.push(FileReport::warning(
                config.mode,
                path,
                format!("failed to read metadata: {err}"),
            ));
            return Ok(());
        }
    };

    if meta.is_file() {
        maybe_add_file(config, path, file_name_path(path), reports, items);
        return Ok(());
    }

    if meta.is_dir() {
        if config.recursive {
            for entry in WalkDir::new(path).follow_links(false).into_iter() {
                match entry {
                    Ok(entry) => {
                        if entry.file_type().is_file() {
                            let rel = entry
                                .path()
                                .strip_prefix(path)
                                .map(Path::to_path_buf)
                                .unwrap_or_else(|_| PathBuf::from(entry.file_name()));
                            maybe_add_file(config, entry.path(), rel, reports, items);
                        }
                    }
                    Err(err) => reports.push(FileReport::warning(
                        config.mode,
                        path,
                        format!("directory traversal warning: {err}"),
                    )),
                }
            }
        } else {
            for entry in fs::read_dir(path).with_context(|| format!("failed to read directory {}", path.display()))? {
                match entry {
                    Ok(entry) => {
                        let entry_path = entry.path();
                        match entry.file_type() {
                            Ok(ft) if ft.is_file() => maybe_add_file(
                                config,
                                &entry_path,
                                file_name_path(&entry_path),
                                reports,
                                items,
                            ),
                            Ok(_) => {}
                            Err(err) => reports.push(FileReport::warning(
                                config.mode,
                                &entry_path,
                                format!("failed to inspect directory entry: {err}"),
                            )),
                        }
                    }
                    Err(err) => reports.push(FileReport::warning(
                        config.mode,
                        path,
                        format!("failed to read directory entry: {err}"),
                    )),
                }
            }
        }
        return Ok(());
    }

    reports.push(FileReport::warning(config.mode, path, "not a regular file or directory; skipped"));
    Ok(())
}

fn maybe_add_file(
    config: &RuntimeConfig,
    source: &Path,
    relative_path: PathBuf,
    reports: &mut Vec<FileReport>,
    items: &mut Vec<WorkItem>,
) {
    match config.mode {
        Mode::Encrypt => {
            if !config.allow_double_encrypt && path_ends_with_extension(source, &config.extension) {
                reports.push(FileReport::warning(
                    config.mode,
                    source,
                    format!("already ends with {}; skipped to avoid double encryption", config.extension),
                ));
                return;
            }
        }
        Mode::Decrypt => {
            if !path_ends_with_extension(source, &config.extension) {
                reports.push(FileReport::warning(
                    config.mode,
                    source,
                    format!("does not end with {}; skipped", config.extension),
                ));
                return;
            }
        }
    }

    items.push(WorkItem {
        source: source.to_path_buf(),
        relative_path,
    });
}

fn dedupe_work_items(items: &mut Vec<WorkItem>) {
    items.sort_by(|a, b| a.source.cmp(&b.source));
    items.dedup_by(|a, b| a.source == b.source);
}

fn process_item(config: &RuntimeConfig, item: &WorkItem) -> FileReport {
    let started = Instant::now();
    match config.mode {
        Mode::Encrypt => process_encrypt_item(config, item, started),
        Mode::Decrypt => process_decrypt_item(config, item, started),
    }
}

fn process_encrypt_item(config: &RuntimeConfig, item: &WorkItem, started: Instant) -> FileReport {
    let source = &item.source;

    let plan = match plan_encrypt_destination(config, item) {
        Ok(plan) => plan,
        Err(err) => return FileReport::error(config.mode, source, None, err.to_string(), started.elapsed().as_millis()),
    };

    if plan.skipped {
        return FileReport {
            event_type: "file_skipped".to_string(),
            mode: config.mode,
            source: path_to_string(source),
            destination: Some(path_to_string(&plan.destination)),
            status: "skipped".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms: started.elapsed().as_millis(),
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: vec![plan.warning.unwrap_or_else(|| "skipped".to_string())],
            error: None,
        };
    }

    if config.dry_run {
        return FileReport {
            event_type: "would_process".to_string(),
            mode: config.mode,
            source: path_to_string(source),
            destination: Some(path_to_string(&plan.destination)),
            status: "would_process".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms: started.elapsed().as_millis(),
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: plan.warning.into_iter().collect(),
            error: None,
        };
    }

    match encrypt_file_transaction(config, source, &plan.destination) {
        Ok(stats) => {
            let (deleted, delete_strategy, deletion_assurance, mut warnings) =
                handle_original_after_success(config, source);
            if let Some(w) = plan.warning {
                warnings.push(w);
            }

            FileReport {
                event_type: "file_success".to_string(),
                mode: config.mode,
                source: path_to_string(source),
                destination: Some(path_to_string(&plan.destination)),
                status: "success".to_string(),
                bytes_read: stats.bytes_read,
                bytes_written: stats.bytes_written,
                duration_ms: started.elapsed().as_millis(),
                original_deleted: deleted,
                deletion_strategy: delete_strategy,
                deletion_assurance,
                warnings,
                error: None,
            }
        }
        Err(err) => FileReport::error(
            config.mode,
            source,
            Some(&plan.destination),
            format!("{err:#}"),
            started.elapsed().as_millis(),
        ),
    }
}

fn process_decrypt_item(config: &RuntimeConfig, item: &WorkItem, started: Instant) -> FileReport {
    let source = &item.source;

    if config.dry_run {
        let plan = plan_decrypt_destination_without_metadata(config, item);
        return FileReport {
            event_type: "would_process".to_string(),
            mode: config.mode,
            source: path_to_string(source),
            destination: plan.ok().map(|p| path_to_string(&p.destination)),
            status: "would_process".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms: started.elapsed().as_millis(),
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: vec!["dry-run decrypt does not authenticate password or inspect encrypted metadata".to_string()],
            error: None,
        };
    }

    let destination_plan = match plan_decrypt_destination_authenticated(config, item) {
        Ok(plan) => plan,
        Err(err) => {
            return FileReport::error(
                config.mode,
                source,
                None,
                format!("{err:#}"),
                started.elapsed().as_millis(),
            )
        }
    };

    if destination_plan.skipped {
        return FileReport {
            event_type: "file_skipped".to_string(),
            mode: config.mode,
            source: path_to_string(source),
            destination: Some(path_to_string(&destination_plan.destination)),
            status: "skipped".to_string(),
            bytes_read: 0,
            bytes_written: 0,
            duration_ms: started.elapsed().as_millis(),
            original_deleted: false,
            deletion_strategy: DeleteStrategy::None,
            deletion_assurance: "none".to_string(),
            warnings: destination_plan.warning.into_iter().collect(),
            error: None,
        };
    }

    match decrypt_file_transaction(config, item, &destination_plan.destination) {
        Ok(stats) => {
            let (deleted, delete_strategy, deletion_assurance, mut warnings) =
                handle_original_after_success(config, source);
            if let Some(w) = destination_plan.warning {
                warnings.push(w);
            }

            FileReport {
                event_type: "file_success".to_string(),
                mode: config.mode,
                source: path_to_string(source),
                destination: Some(path_to_string(&destination_plan.destination)),
                status: "success".to_string(),
                bytes_read: stats.bytes_read,
                bytes_written: stats.bytes_written,
                duration_ms: started.elapsed().as_millis(),
                original_deleted: deleted,
                deletion_strategy: delete_strategy,
                deletion_assurance,
                warnings,
                error: None,
            }
        }
        Err(err) => FileReport::error(
            config.mode,
            source,
            Some(&destination_plan.destination),
            format!("{err:#}"),
            started.elapsed().as_millis(),
        ),
    }
}

fn encrypt_file_transaction(config: &RuntimeConfig, source: &Path, destination: &Path) -> Result<EncryptStats> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent directory"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create destination directory {}", parent.display()))?;

    let temp_path = make_temp_path(parent, destination)?;

    let result = (|| {
        let stats = encrypt_file_to_path(config, source, &temp_path)
            .with_context(|| format!("failed to encrypt {}", source.display()))?;

        if config.verify != VerifyMode::None {
            verify_encrypted_file(config, &temp_path)
                .with_context(|| format!("verification failed for {}", temp_path.display()))?;
        }

        finalize_temp_file(&temp_path, destination, config.collision)
            .with_context(|| format!("failed to finalize {}", destination.display()))?;

        sync_parent_dir(parent);

        Ok(stats)
    })();

    if result.is_err() {
        make_file_writable(&temp_path).ok();
        let _ = fs::remove_file(&temp_path);
    }

    result
}

fn decrypt_file_transaction(config: &RuntimeConfig, item: &WorkItem, final_destination: &Path) -> Result<DecryptStats> {
    let source = &item.source;

    let parent = final_destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent directory"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create destination directory {}", parent.display()))?;

    let temp_path = make_temp_path(parent, final_destination)?;

    let result = (|| {
        let stats = decrypt_file_to_path(config, source, &temp_path)
            .with_context(|| format!("failed to decrypt {}", source.display()))?;

        if matches!(config.verify, VerifyMode::Full | VerifyMode::Hash) {
            verify_decrypted_plaintext(&temp_path, &stats.metadata)
                .with_context(|| format!("decrypted output verification failed for {}", temp_path.display()))?;
        }

        if config.preserve_metadata {
            apply_stored_metadata(&temp_path, &stats.metadata)
                .with_context(|| format!("failed to apply metadata to {}", temp_path.display()))?;
        }

        finalize_temp_file(&temp_path, final_destination, config.collision)
            .with_context(|| format!("failed to finalize {}", final_destination.display()))?;

        sync_parent_dir(parent);
        Ok(stats)
    })();

    if result.is_err() {
        make_file_writable(&temp_path).ok();
        let _ = fs::remove_file(&temp_path);
    }

    result
}

fn encrypt_file_to_path(config: &RuntimeConfig, source: &Path, output: &Path) -> Result<EncryptStats> {
    let source_meta = fs::metadata(source)
        .with_context(|| format!("failed to read source metadata {}", source.display()))?;
    let source_size = source_meta.len();
    let chunk_count = chunk_count(source_size, config.chunk_size);

    let plaintext_hash = if matches!(config.verify, VerifyMode::Full | VerifyMode::Hash) {
        Some(hash_file(source)?.1)
    } else {
        None
    };

    let mut salt = [0u8; SALT_LEN];
    let mut data_nonce_prefix = [0u8; DATA_NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut data_nonce_prefix);

    let header = PublicHeader {
        format: "colemen_encrypt".to_string(),
        format_version: FORMAT_VERSION,
        cipher: "AES-256-GCM-SIV".to_string(),
        kdf: KdfHeader {
            algorithm: "Argon2id".to_string(),
            version: 0x13,
            memory_kib: config.argon2_memory_kib,
            iterations: config.argon2_iterations,
            parallelism: config.argon2_parallelism,
            salt_hex: hex::encode(salt),
        },
        chunk_size: config.chunk_size,
        data_nonce_prefix_hex: hex::encode(data_nonce_prefix),
        filename_mode: if config.private_names { "private" } else { "visible" }.to_string(),
    };

    let header_bytes = serde_json::to_vec(&header)?;
    if header_bytes.len() > u32::MAX as usize {
        bail!("public header is too large");
    }

    let mut key = derive_key(config.password.as_bytes(), &salt, &header.kdf)?;
    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| anyhow!("invalid AES key length"))?;

    let stored_metadata = build_stored_metadata(source, &source_meta, config.chunk_size, chunk_count, plaintext_hash)?;
    let metadata_json = serde_json::to_vec(&stored_metadata)?;
    let metadata_nonce = make_nonce(&METADATA_NONCE_PREFIX, u64::MAX);
    let metadata_ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&metadata_nonce),
            Payload {
                msg: &metadata_json,
                aad: &header_bytes,
            },
        )
        .map_err(|_| anyhow!("metadata encryption failed"))?;

    let mut bytes_written = 0u64;
    let mut bytes_read = 0u64;

    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .with_context(|| format!("failed to create temp output {}", output.display()))?,
    );

    writer.write_all(MAGIC)?;
    bytes_written += MAGIC.len() as u64;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    bytes_written += 4;
    writer.write_all(&header_bytes)?;
    bytes_written += header_bytes.len() as u64;
    writer.write_all(&(metadata_ciphertext.len() as u64).to_le_bytes())?;
    bytes_written += 8;
    writer.write_all(&metadata_ciphertext)?;
    bytes_written += metadata_ciphertext.len() as u64;

    let mut reader = BufReader::new(File::open(source)?);
    let mut buffer = vec![0u8; config.chunk_size as usize];

    for index in 0..chunk_count {
        let remaining = source_size - bytes_read;
        let to_read = remaining.min(config.chunk_size) as usize;
        reader.read_exact(&mut buffer[..to_read])?;
        bytes_read += to_read as u64;

        let nonce = make_nonce(&data_nonce_prefix, index);
        let aad = data_chunk_aad(&header_bytes, index);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &buffer[..to_read],
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("data chunk encryption failed at chunk {index}"))?;

        if ciphertext.len() > u32::MAX as usize {
            bail!("ciphertext chunk is too large");
        }

        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;
        bytes_written += 4 + ciphertext.len() as u64;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    if config.preserve_metadata {
        preserve_basic_filesystem_metadata(source, output)?;
    }

    key.zeroize();

    Ok(EncryptStats {
        bytes_read,
        bytes_written,
    })
}

fn decrypt_file_to_path(config: &RuntimeConfig, source: &Path, output: &Path) -> Result<DecryptStats> {
    let mut reader = BufReader::new(File::open(source)?);
    let parsed = read_and_decrypt_metadata(config, &mut reader)?;

    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .with_context(|| format!("failed to create temp output {}", output.display()))?,
    );

    let mut hasher = Sha256::new();
    let mut bytes_written = 0u64;
    let data_nonce_prefix = decode_fixed_prefix(&parsed.header.data_nonce_prefix_hex)?;

    for index in 0..parsed.metadata.chunk_count {
        let ciphertext = read_chunk(&mut reader)
            .with_context(|| format!("failed to read encrypted chunk {index}"))?;
        let nonce = make_nonce(&data_nonce_prefix, index);
        let aad = data_chunk_aad(&parsed.header_bytes, index);
        let plaintext = parsed
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("authentication/decryption failed at chunk {index}"))?;

        hasher.update(&plaintext);
        writer.write_all(&plaintext)?;
        bytes_written += plaintext.len() as u64;
    }

    ensure_no_trailing_data(&mut reader)?;

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    if let Some(expected_hash) = &parsed.metadata.plaintext_sha256 {
        let actual_hash = hex::encode(hasher.finalize());
        if !constant_time_eq_hex(&actual_hash, expected_hash) {
            bail!("plaintext hash mismatch after decryption");
        }
    }

    if bytes_written != parsed.metadata.original_size {
        bail!(
            "decrypted size mismatch: expected {}, got {}",
            parsed.metadata.original_size,
            bytes_written
        );
    }

    Ok(DecryptStats {
        bytes_read: fs::metadata(source).map(|m| m.len()).unwrap_or(0),
        bytes_written,
        metadata: parsed.metadata,
    })
}

struct ParsedEncryptedFile {
    header_bytes: Vec<u8>,
    header: PublicHeader,
    metadata: StoredMetadata,
    cipher: Aes256GcmSiv,
}

fn inspect_encrypted_file(config: &RuntimeConfig, source: &Path) -> Result<ParsedEncryptedFile> {
    let mut reader = BufReader::new(File::open(source)?);
    read_and_decrypt_metadata(config, &mut reader)
}

fn read_and_decrypt_metadata<R: Read>(config: &RuntimeConfig, reader: &mut R) -> Result<ParsedEncryptedFile> {
    let (header_bytes, header) = read_public_header(reader)?;
    validate_public_header(&header)?;

    let salt = decode_fixed::<SALT_LEN>(&header.kdf.salt_hex, "salt")?;
    let mut key = derive_key(config.password.as_bytes(), &salt, &header.kdf)?;
    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| anyhow!("invalid AES key length"))?;

    let metadata_ciphertext_len = read_u64(reader)?;
    if metadata_ciphertext_len > 16 * 1024 * 1024 {
        bail!("encrypted metadata block is too large");
    }
    let mut metadata_ciphertext = vec![0u8; metadata_ciphertext_len as usize];
    reader.read_exact(&mut metadata_ciphertext)?;

    let metadata_nonce = make_nonce(&METADATA_NONCE_PREFIX, u64::MAX);
    let metadata_json = cipher
        .decrypt(
            Nonce::from_slice(&metadata_nonce),
            Payload {
                msg: &metadata_ciphertext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt metadata; password may be wrong or file may be corrupted"))?;

    let metadata: StoredMetadata = serde_json::from_slice(&metadata_json)
        .context("failed to parse encrypted metadata")?;

    if metadata.chunk_size != header.chunk_size {
        bail!("metadata/header chunk size mismatch");
    }
    if metadata.chunk_count != chunk_count(metadata.original_size, metadata.chunk_size) {
        bail!("metadata chunk count does not match original size");
    }

    key.zeroize();

    Ok(ParsedEncryptedFile {
        header_bytes,
        header,
        metadata,
        cipher,
    })
}

fn verify_encrypted_file(config: &RuntimeConfig, encrypted_path: &Path) -> Result<()> {
    if config.verify == VerifyMode::None {
        return Ok(());
    }

    let mut reader = BufReader::new(File::open(encrypted_path)?);
    let parsed = read_and_decrypt_metadata(config, &mut reader)?;
    let data_nonce_prefix = decode_fixed_prefix(&parsed.header.data_nonce_prefix_hex)?;
    let mut hasher = Sha256::new();
    let mut total_plaintext = 0u64;

    for index in 0..parsed.metadata.chunk_count {
        let ciphertext = read_chunk(&mut reader)
            .with_context(|| format!("failed to read encrypted chunk {index}"))?;
        let nonce = make_nonce(&data_nonce_prefix, index);
        let aad = data_chunk_aad(&parsed.header_bytes, index);
        let plaintext = parsed
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("authentication/decryption failed during verification at chunk {index}"))?;

        total_plaintext += plaintext.len() as u64;
        if matches!(config.verify, VerifyMode::Full | VerifyMode::Hash) {
            hasher.update(&plaintext);
        }
    }

    ensure_no_trailing_data(&mut reader)?;

    if total_plaintext != parsed.metadata.original_size {
        bail!(
            "verification size mismatch: expected {}, got {}",
            parsed.metadata.original_size,
            total_plaintext
        );
    }

    if matches!(config.verify, VerifyMode::Full | VerifyMode::Hash) {
        let expected = parsed
            .metadata
            .plaintext_sha256
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted file does not contain plaintext hash for hash verification"))?;
        let actual = hex::encode(hasher.finalize());
        if !constant_time_eq_hex(&actual, expected) {
            bail!("verification plaintext hash mismatch");
        }
    }

    Ok(())
}

fn verify_decrypted_plaintext(path: &Path, metadata: &StoredMetadata) -> Result<()> {
    let Some(expected) = &metadata.plaintext_sha256 else {
        return Ok(());
    };
    let (size, actual) = hash_file(path)?;
    if size != metadata.original_size {
        bail!("output size mismatch: expected {}, got {}", metadata.original_size, size);
    }
    if !constant_time_eq_hex(&actual, expected) {
        bail!("output hash mismatch");
    }
    Ok(())
}

fn plan_encrypt_destination(config: &RuntimeConfig, item: &WorkItem) -> Result<PathPlan> {
    let output_name = if config.private_names {
        random_private_filename(&config.extension)
    } else {
        encrypted_file_name(&item.source, config)?
    };

    let destination = destination_from_relative(config, item, &output_name);
    resolve_collision(&destination, config.collision)
}

fn plan_decrypt_destination_without_metadata(config: &RuntimeConfig, item: &WorkItem) -> Result<PathPlan> {
    let output_name = decrypted_visible_file_name(&item.source, config)?;
    let destination = destination_from_relative(config, item, &output_name);
    resolve_collision(&destination, config.collision)
}

fn plan_decrypt_destination_authenticated(config: &RuntimeConfig, item: &WorkItem) -> Result<PathPlan> {
    let inspect = inspect_encrypted_file(config, &item.source)
        .with_context(|| format!("failed to inspect encrypted file {}", item.source.display()))?;
    let destination = plan_decrypt_destination_with_metadata(config, item, &inspect.header, &inspect.metadata)?;
    resolve_collision(&destination, config.collision)
}

fn plan_decrypt_destination_with_metadata(
    config: &RuntimeConfig,
    item: &WorkItem,
    header: &PublicHeader,
    metadata: &StoredMetadata,
) -> Result<PathBuf> {
    let output_name = if header.filename_mode == "private" {
        metadata.original_file_name.clone()
    } else {
        decrypted_visible_file_name(&item.source, config)?
    };

    let destination = destination_from_relative(config, item, &output_name);
    Ok(destination)
}

fn destination_from_relative(config: &RuntimeConfig, item: &WorkItem, output_name: &str) -> PathBuf {
    if let Some(output_dir) = &config.output_dir {
        if config.keep_relative_path {
            let mut rel = item.relative_path.clone();
            rel.set_file_name(output_name);
            output_dir.join(rel)
        } else {
            output_dir.join(output_name)
        }
    } else {
        item.source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(output_name)
    }
}

fn resolve_collision(destination: &Path, mode: CollisionMode) -> Result<PathPlan> {
    if !destination.exists() {
        return Ok(PathPlan {
            destination: destination.to_path_buf(),
            skipped: false,
            warning: None,
        });
    }

    match mode {
        CollisionMode::Skip => Ok(PathPlan {
            destination: destination.to_path_buf(),
            skipped: true,
            warning: Some(format!("destination already exists; skipped: {}", destination.display())),
        }),
        CollisionMode::Rename => {
            let renamed = next_available_path(destination)?;
            Ok(PathPlan {
                destination: renamed.clone(),
                skipped: false,
                warning: Some(format!(
                    "destination existed; renamed output to {}",
                    renamed.display()
                )),
            })
        }
        CollisionMode::Overwrite => Ok(PathPlan {
            destination: destination.to_path_buf(),
            skipped: false,
            warning: Some(format!("destination exists and will be overwritten: {}", destination.display())),
        }),
    }
}

fn encrypted_file_name(source: &Path, config: &RuntimeConfig) -> Result<String> {
    let filename = source
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("source has no valid UTF-8 file name"))?;

    let path = Path::new(filename);
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or(filename);
    let ext = path.extension().and_then(OsStr::to_str);

    let mut name = String::new();
    name.push_str(&config.prefix);
    name.push_str(stem);
    name.push_str(&config.suffix);
    if let Some(ext) = ext {
        name.push('.');
        name.push_str(ext);
    }
    name.push_str(&config.extension);
    Ok(name)
}

fn decrypted_visible_file_name(source: &Path, config: &RuntimeConfig) -> Result<String> {
    let filename = source
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("source has no valid UTF-8 file name"))?;

    if !filename.ends_with(&config.extension) {
        bail!("source file does not end with {}", config.extension);
    }

    let without_enc = &filename[..filename.len() - config.extension.len()];
    let path = Path::new(without_enc);
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or(without_enc);
    let ext = path.extension().and_then(OsStr::to_str);

    let mut clean_stem = stem.to_string();
    if !config.prefix.is_empty() && clean_stem.starts_with(&config.prefix) {
        clean_stem = clean_stem[config.prefix.len()..].to_string();
    }
    if !config.suffix.is_empty() && clean_stem.ends_with(&config.suffix) {
        clean_stem.truncate(clean_stem.len() - config.suffix.len());
    }

    let mut name = clean_stem;
    if let Some(ext) = ext {
        name.push('.');
        name.push_str(ext);
    }
    Ok(name)
}

fn random_private_filename(extension: &str) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{}{}", hex::encode(bytes), extension)
}

fn build_stored_metadata(
    source: &Path,
    source_meta: &fs::Metadata,
    chunk_size: u64,
    chunk_count: u64,
    plaintext_hash: Option<String>,
) -> Result<StoredMetadata> {
    Ok(StoredMetadata {
        original_file_name: source
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("source has no valid UTF-8 file name"))?
            .to_string(),
        original_size: source_meta.len(),
        chunk_size,
        chunk_count,
        plaintext_sha256: plaintext_hash,
        readonly: source_meta.permissions().readonly(),
        modified_unix_ms: source_meta.modified().ok().and_then(system_time_to_unix_ms),
        accessed_unix_ms: source_meta.accessed().ok().and_then(system_time_to_unix_ms),
        created_unix_ms: source_meta.created().ok().and_then(system_time_to_unix_ms),
        #[cfg(unix)]
        unix_mode: Some(source_meta.permissions().mode()),
    })
}

fn preserve_basic_filesystem_metadata(source: &Path, dest: &Path) -> Result<()> {
    let meta = fs::metadata(source)?;

    if let (Ok(atime), Ok(mtime)) = (meta.accessed(), meta.modified()) {
        let atime = filetime::FileTime::from_system_time(atime);
        let mtime = filetime::FileTime::from_system_time(mtime);
        filetime::set_file_times(dest, atime, mtime)?;
    }

    let perms = meta.permissions();
    fs::set_permissions(dest, perms)?;
    Ok(())
}

fn apply_stored_metadata(dest: &Path, metadata: &StoredMetadata) -> Result<()> {
    if let (Some(accessed), Some(modified)) = (metadata.accessed_unix_ms, metadata.modified_unix_ms) {
        let atime = filetime_from_unix_ms(accessed);
        let mtime = filetime_from_unix_ms(modified);
        filetime::set_file_times(dest, atime, mtime)?;
    }

    let mut perms = fs::metadata(dest)?.permissions();
    perms.set_readonly(metadata.readonly);
    #[cfg(unix)]
    if let Some(mode) = metadata.unix_mode {
        perms.set_mode(mode);
    }
    fs::set_permissions(dest, perms)?;

    Ok(())
}

fn handle_original_after_success(config: &RuntimeConfig, source: &Path) -> (bool, DeleteStrategy, String, Vec<String>) {
    let mut warnings = Vec::new();

    if config.keep_original || config.delete_strategy == DeleteStrategy::None {
        return (false, DeleteStrategy::None, "none".to_string(), warnings);
    }

    let result = match config.delete_strategy {
        DeleteStrategy::Unlink => remove_file_best_effort(source),
        DeleteStrategy::BestEffortOverwrite => best_effort_overwrite_then_remove(source),
        DeleteStrategy::None => Ok(()),
    };

    match result {
        Ok(()) => (
            true,
            config.delete_strategy,
            "best_effort_file_level".to_string(),
            warnings,
        ),
        Err(err) => {
            warnings.push(format!("failed to remove original after verified output: {err:#}"));
            (
                false,
                config.delete_strategy,
                "deletion_failed".to_string(),
                warnings,
            )
        }
    }
}

fn remove_file_best_effort(path: &Path) -> Result<()> {
    make_file_writable(path).ok();
    fs::remove_file(path).with_context(|| format!("failed to remove file {}", path.display()))
}

fn best_effort_overwrite_then_remove(path: &Path) -> Result<()> {
    make_file_writable(path).ok();
    let size = fs::metadata(path)?.len();
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open file for overwrite {}", path.display()))?;

    let zero_block = vec![0u8; 1024 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(zero_block.len() as u64) as usize;
        file.write_all(&zero_block[..n])?;
        remaining -= n as u64;
    }
    file.flush()?;
    file.sync_all()?;
    drop(file);

    fs::remove_file(path).with_context(|| format!("failed to remove overwritten file {}", path.display()))
}

fn make_file_writable(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();

    #[cfg(unix)]
    {
        let mode = perms.mode() | 0o200;
        perms.set_mode(mode);
    }

    #[cfg(not(unix))]
    {
        perms.set_readonly(false);
    }

    fs::set_permissions(path, perms)?;
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8], kdf: &KdfHeader) -> Result<[u8; KEY_LEN]> {
    if kdf.algorithm != "Argon2id" {
        bail!("unsupported KDF: {}", kdf.algorithm);
    }
    if kdf.version != 0x13 {
        bail!("unsupported Argon2 version: {}", kdf.version);
    }

    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| anyhow!("invalid Argon2 parameters: {err}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|err| anyhow!("Argon2 key derivation failed: {err}"))?;
    Ok(key)
}

fn read_public_header<R: Read>(reader: &mut R) -> Result<(Vec<u8>, PublicHeader)> {
    let mut magic = [0u8; MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("not a colemen_encrypt file or unsupported magic header");
    }

    let header_len = read_u32(reader)? as usize;
    if header_len == 0 || header_len > 1024 * 1024 {
        bail!("invalid public header length");
    }

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header: PublicHeader = serde_json::from_slice(&header_bytes)?;
    Ok((header_bytes, header))
}

fn validate_public_header(header: &PublicHeader) -> Result<()> {
    if header.format != "colemen_encrypt" {
        bail!("unsupported format: {}", header.format);
    }
    if header.format_version != FORMAT_VERSION {
        bail!("unsupported format version: {}", header.format_version);
    }
    if header.cipher != "AES-256-GCM-SIV" {
        bail!("unsupported cipher: {}", header.cipher);
    }
    if header.chunk_size == 0 || header.chunk_size > (u32::MAX as u64 - 32) {
        bail!("invalid chunk size in header");
    }
    let _ = decode_fixed_prefix(&header.data_nonce_prefix_hex)?;
    Ok(())
}

fn read_chunk<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = read_u32(reader)? as usize;
    if len == 0 || len > (u32::MAX as usize) {
        bail!("invalid chunk length");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn ensure_no_trailing_data<R: Read>(reader: &mut R) -> Result<()> {
    let mut one = [0u8; 1];
    match reader.read(&mut one)? {
        0 => Ok(()),
        _ => bail!("encrypted file contains trailing unexpected data"),
    }
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn make_nonce(prefix: &[u8; DATA_NONCE_PREFIX_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..DATA_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[DATA_NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn data_chunk_aad(header_bytes: &[u8], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_bytes.len() + 16);
    aad.extend_from_slice(b"colemen_encrypt:data:");
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(header_bytes);
    aad
}

fn decode_fixed<const N: usize>(hex_value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex_value).with_context(|| format!("invalid hex for {label}"))?;
    if bytes.len() != N {
        bail!("invalid {label} length: expected {N}, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_fixed_prefix(hex_value: &str) -> Result<[u8; DATA_NONCE_PREFIX_LEN]> {
    decode_fixed::<DATA_NONCE_PREFIX_LEN>(hex_value, "data nonce prefix")
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }

    Ok((total, hex::encode(hasher.finalize())))
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn make_temp_path(parent: &Path, destination: &Path) -> Result<PathBuf> {
    let filename = destination
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("colemen_encrypt_output");

    for _ in 0..10_000 {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let candidate = parent.join(format!(".{filename}.{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("failed to create a unique temporary path in {}", parent.display())
}

fn finalize_temp_file(temp_path: &Path, destination: &Path, collision: CollisionMode) -> Result<()> {
    if destination.exists() {
        match collision {
            CollisionMode::Skip => bail!("destination already exists: {}", destination.display()),
            CollisionMode::Rename => bail!("internal error: rename collision should have been resolved earlier"),
            CollisionMode::Overwrite => {
                make_file_writable(destination).ok();
                fs::remove_file(destination).with_context(|| {
                    format!("failed to remove existing destination {}", destination.display())
                })?;
            }
        }
    }

    fs::rename(temp_path, destination)
        .with_context(|| format!("failed to rename temp file into place: {}", destination.display()))?;
    Ok(())
}

fn next_available_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("invalid destination filename"))?;
    let p = Path::new(file_name);
    let stem = p.file_stem().and_then(OsStr::to_str).unwrap_or(file_name);
    let ext = p.extension().and_then(OsStr::to_str);

    for i in 1..100_000u32 {
        let candidate_name = match ext {
            Some(ext) => format!("{stem}.{i}.{ext}"),
            None => format!("{stem}.{i}"),
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("failed to find available destination filename for {}", path.display())
}

fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Ok(dir) = File::open(path) {
            let _ = dir.sync_all();
        }
    }
}

fn normalize_extension(ext: &str) -> String {
    let trimmed = ext.trim();
    if trimmed.is_empty() {
        ".enc".to_string()
    } else if trimmed.starts_with('.') {
        trimmed.to_string()
    } else {
        format!(".{trimmed}")
    }
}

fn path_ends_with_extension(path: &Path, extension: &str) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(|name| name.ends_with(extension))
        .unwrap_or(false)
}

fn file_name_path(path: &Path) -> PathBuf {
    path.file_name().map(PathBuf::from).unwrap_or_else(|| path.to_path_buf())
}

fn trim_list_line(line: &str) -> &str {
    let trimmed = line.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn chunk_count(size: u64, chunk_size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        ((size - 1) / chunk_size) + 1
    }
}

fn system_time_to_unix_ms(time: SystemTime) -> Option<i128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| duration_to_ms(d) as i128)
}

fn duration_to_ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn filetime_from_unix_ms(ms: i128) -> filetime::FileTime {
    let secs = ms.div_euclid(1000) as i64;
    let millis = ms.rem_euclid(1000) as u32;
    filetime::FileTime::from_unix_time(secs, millis * 1_000_000)
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn print_json_line<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

fn print_human_file_report(report: &FileReport, verbose: bool) {
    match report.status.as_str() {
        "success" => {
            println!("SUCCESS  {}", report.source);
            if let Some(dest) = &report.destination {
                println!("         -> {dest}");
            }
            if verbose {
                println!(
                    "         bytes_read={}, bytes_written={}, duration_ms={}, original_deleted={}",
                    report.bytes_read, report.bytes_written, report.duration_ms, report.original_deleted
                );
            }
        }
        "failed" => {
            println!("FAILED   {}", report.source);
            if let Some(dest) = &report.destination {
                println!("         -> {dest}");
            }
            if let Some(err) = &report.error {
                println!("         error: {err}");
            }
        }
        "skipped" => {
            println!("SKIPPED  {}", report.source);
            for warning in &report.warnings {
                println!("         warning: {warning}");
            }
        }
        "would_process" => {
            println!("WOULD    {}", report.source);
            if let Some(dest) = &report.destination {
                println!("         -> {dest}");
            }
            for warning in &report.warnings {
                println!("         note: {warning}");
            }
        }
        _ => println!("{} {}", report.status.to_uppercase(), report.source),
    }

    for warning in &report.warnings {
        if report.status != "skipped" && report.status != "would_process" {
            println!("         warning: {warning}");
        }
    }
}

fn summarize(mode: Mode, reports: &[FileReport], elapsed: Duration) -> MachineEventSummary {
    MachineEventSummary {
        event_type: "summary",
        mode,
        files_total: reports.len(),
        files_success: reports.iter().filter(|r| r.status == "success").count(),
        files_failed: reports.iter().filter(|r| r.status == "failed").count(),
        files_skipped: reports.iter().filter(|r| r.status == "skipped").count(),
        warnings: reports.iter().map(|r| r.warnings.len()).sum(),
        duration_ms: elapsed.as_millis(),
    }
}

fn print_human_summary(summary: &MachineEventSummary) {
    println!();
    println!("Summary");
    println!("-------");
    println!("mode:          {:?}", summary.mode);
    println!("total:         {}", summary.files_total);
    println!("success:       {}", summary.files_success);
    println!("failed:        {}", summary.files_failed);
    println!("skipped:       {}", summary.files_skipped);
    println!("warnings:      {}", summary.warnings);
    println!("duration_ms:   {}", summary.duration_ms);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_extension_adds_dot() {
        assert_eq!(normalize_extension("enc"), ".enc");
        assert_eq!(normalize_extension(".cenc"), ".cenc");
    }

    #[test]
    fn chunk_count_handles_empty_and_partial() {
        assert_eq!(chunk_count(0, 10), 0);
        assert_eq!(chunk_count(1, 10), 1);
        assert_eq!(chunk_count(10, 10), 1);
        assert_eq!(chunk_count(11, 10), 2);
    }
}
