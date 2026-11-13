//! Vigilyx-owned process sandbox worker contract and lifecycle controller.
//!
//! This is deliberately smaller than a kernel sandbox.  It owns the worker
//! protocol, environment sanitisation, process-group lifecycle, bounded I/O,
//! timeout, and failure semantics.  A configured launcher (for example a
//! reviewed bubblewrap/nsjail profile) supplies the namespace/seccomp/cgroup
//! boundary.  Without that launcher, configuration is rejected rather than
//! treating an ordinary child process as isolated.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const PROTOCOL_VERSION: &str = "vigilyx.process-sandbox.v1";
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_STDERR_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_CPU_SECS: u64 = 15;
const MAX_TIMEOUT_SECS: u64 = 120;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CPU_SECS: u64 = 120;
const MAX_OBSERVATIONS: usize = 64;
const MAX_OBSERVATION_FIELD_BYTES: usize = 4096;

/// Input sent to one disposable worker process.
///
/// The URL is metadata for the broker/renderer contract.  The worker profile
/// is expected to be offline by default; it must not interpret this field as
/// permission to perform arbitrary network access.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSandboxRequest {
    pub schema_version: &'static str,
    pub job_id: String,
    pub target_url: String,
    pub profile: String,
    pub network_mode: &'static str,
}

impl ProcessSandboxRequest {
    pub fn offline(job_id: impl Into<String>, target_url: impl Into<String>) -> Self {
        Self {
            schema_version: PROTOCOL_VERSION,
            job_id: job_id.into(),
            target_url: target_url.into(),
            profile: "offline_snapshot_v1".to_string(),
            network_mode: "none",
        }
    }
}

/// Worker output.  The coordinator accepts only completed or partial output;
/// process failures and lifecycle failures stay in [`ProcessSandboxError`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSandboxResponse {
    pub schema_version: String,
    pub status: WorkerResponseStatus,
    #[serde(default)]
    pub observations: Vec<WorkerObservation>,
    #[serde(default)]
    pub effective_url: Option<String>,
    #[serde(default)]
    pub redirect_chain: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerResponseStatus {
    Completed,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerObservation {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub confidence: Option<f32>,
}

impl ProcessSandboxResponse {
    fn validate(&self) -> Result<(), ProcessSandboxError> {
        if self.schema_version != PROTOCOL_VERSION {
            return Err(ProcessSandboxError::Protocol(format!(
                "unsupported schema version: {}",
                self.schema_version
            )));
        }
        if self.observations.len() > MAX_OBSERVATIONS {
            return Err(ProcessSandboxError::Protocol(format!(
                "too many observations: {} (max {})",
                self.observations.len(),
                MAX_OBSERVATIONS
            )));
        }
        for observation in &self.observations {
            if observation.kind.is_empty()
                || observation.kind.len() > MAX_OBSERVATION_FIELD_BYTES
                || observation.value.len() > MAX_OBSERVATION_FIELD_BYTES
            {
                return Err(ProcessSandboxError::Protocol(
                    "observation field is empty or exceeds the bounded size".to_string(),
                ));
            }
            if observation
                .confidence
                .is_some_and(|confidence| !(0.0..=1.0).contains(&confidence))
            {
                return Err(ProcessSandboxError::Protocol(
                    "observation confidence must be between 0 and 1".to_string(),
                ));
            }
        }
        if self.redirect_chain.len() > 8 {
            return Err(ProcessSandboxError::Protocol(
                "redirect chain exceeds the worker contract limit".to_string(),
            ));
        }
        if self
            .redirect_chain
            .iter()
            .any(|url| url.len() > MAX_OBSERVATION_FIELD_BYTES)
        {
            return Err(ProcessSandboxError::Protocol(
                "redirect-chain URL exceeds the worker contract limit".to_string(),
            ));
        }
        if self
            .effective_url
            .as_ref()
            .is_some_and(|url| url.len() > MAX_OBSERVATION_FIELD_BYTES)
        {
            return Err(ProcessSandboxError::Protocol(
                "effective URL exceeds the worker contract limit".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessSandboxConfig {
    /// Reviewed launcher that supplies namespaces/seccomp/cgroup isolation.
    pub launcher: PathBuf,
    /// Fixed arguments for the launcher.  They are passed as argv entries;
    /// no shell parsing or interpolation is performed.
    pub launcher_args: Vec<String>,
    /// Worker executable appended after launcher_args.
    pub worker: PathBuf,
    pub profile: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub max_stderr_bytes: usize,
    /// Hard address-space limit inherited by the launcher and worker.
    pub max_memory_bytes: u64,
    /// Hard CPU-time limit inherited by the launcher and worker.
    pub max_cpu_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessSandboxConfigError {
    Missing(&'static str),
    Invalid(String),
}

impl fmt::Display for ProcessSandboxConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "missing required configuration: {name}"),
            Self::Invalid(message) => write!(f, "invalid process sandbox configuration: {message}"),
        }
    }
}

impl std::error::Error for ProcessSandboxConfigError {}

impl ProcessSandboxConfig {
    /// Read an explicitly enabled configuration.
    ///
    /// `Ok(None)` means the feature is disabled.  `Err` means the operator
    /// attempted to enable it but the boundary is not complete; callers must
    /// expose this as unavailable coverage rather than silently falling back
    /// to an ordinary process.
    pub fn from_env() -> Result<Option<Self>, ProcessSandboxConfigError> {
        if !env_enabled("PROCESS_SANDBOX_ENABLED") {
            return Ok(None);
        }

        let launcher = required_executable("PROCESS_SANDBOX_LAUNCHER")?;
        let worker = required_executable("PROCESS_SANDBOX_WORKER")?;
        let profile = std::env::var("PROCESS_SANDBOX_PROFILE")
            .unwrap_or_else(|_| "offline_snapshot_v1".to_string());
        validate_profile(&profile)?;

        let launcher_args = match std::env::var("PROCESS_SANDBOX_LAUNCHER_ARGS") {
            Ok(raw) if !raw.trim().is_empty() => serde_json::from_str::<Vec<String>>(&raw)
                .map_err(|error| {
                    ProcessSandboxConfigError::Invalid(format!(
                        "PROCESS_SANDBOX_LAUNCHER_ARGS must be a JSON array: {error}"
                    ))
                })?,
            _ => Vec::new(),
        };
        validate_launcher_profile(&launcher, &launcher_args)?;

        let timeout_secs = bounded_env_u64(
            "PROCESS_SANDBOX_TIMEOUT_SECS",
            DEFAULT_TIMEOUT_SECS,
            1,
            MAX_TIMEOUT_SECS,
        )?;
        let max_output_bytes = bounded_env_usize(
            "PROCESS_SANDBOX_MAX_OUTPUT_BYTES",
            DEFAULT_MAX_OUTPUT_BYTES,
            1024,
            MAX_OUTPUT_BYTES,
        )?;
        let max_stderr_bytes = bounded_env_usize(
            "PROCESS_SANDBOX_MAX_STDERR_BYTES",
            DEFAULT_MAX_STDERR_BYTES,
            1024,
            MAX_STDERR_BYTES,
        )?;
        let max_memory_bytes = bounded_env_u64(
            "PROCESS_SANDBOX_MAX_MEMORY_BYTES",
            DEFAULT_MAX_MEMORY_BYTES,
            64 * 1024 * 1024,
            MAX_MEMORY_BYTES,
        )?;
        let max_cpu_secs = bounded_env_u64(
            "PROCESS_SANDBOX_MAX_CPU_SECS",
            DEFAULT_MAX_CPU_SECS,
            1,
            MAX_CPU_SECS,
        )?;

        Ok(Some(Self {
            launcher,
            launcher_args,
            worker,
            profile,
            timeout: Duration::from_secs(timeout_secs),
            max_output_bytes,
            max_stderr_bytes,
            max_memory_bytes,
            max_cpu_secs,
        }))
    }
}

fn validate_profile(profile: &str) -> Result<(), ProcessSandboxConfigError> {
    if profile != "offline_snapshot_v1" {
        return Err(ProcessSandboxConfigError::Invalid(format!(
            "unsupported profile {profile:?}; only offline_snapshot_v1 is implemented"
        )));
    }
    Ok(())
}

fn validate_launcher_profile(
    launcher: &Path,
    args: &[String],
) -> Result<(), ProcessSandboxConfigError> {
    let name = launcher
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !matches!(name, "bwrap" | "bubblewrap") {
        return Err(ProcessSandboxConfigError::Invalid(
            "only the reviewed bubblewrap launcher profile is supported".to_string(),
        ));
    }
    const REQUIRED_FLAGS: &[&str] = &[
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
        "--proc",
        "--dev",
        "--tmpfs",
        "--ro-bind",
        "--",
    ];
    for required in REQUIRED_FLAGS {
        if !args.iter().any(|arg| arg == required) {
            return Err(ProcessSandboxConfigError::Invalid(format!(
                "bubblewrap profile is missing required flag {required}"
            )));
        }
    }
    const FORBIDDEN_FLAGS: &[&str] = &[
        "--share-net",
        "--bind",
        "--bind-try",
        "--dev-bind",
        "--dev-bind-try",
        "--ro-bind-try",
        "--host-os",
    ];
    if let Some(forbidden) = args
        .iter()
        .find(|arg| FORBIDDEN_FLAGS.contains(&arg.as_str()))
    {
        return Err(ProcessSandboxConfigError::Invalid(format!(
            "bubblewrap profile contains forbidden flag {forbidden}"
        )));
    }
    if args.last().map(String::as_str) != Some("--") {
        return Err(ProcessSandboxConfigError::Invalid(
            "bubblewrap launcher arguments must end with -- before the worker path".to_string(),
        ));
    }
    Ok(())
}

fn env_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn required_executable(name: &'static str) -> Result<PathBuf, ProcessSandboxConfigError> {
    let raw = std::env::var(name).map_err(|_| ProcessSandboxConfigError::Missing(name))?;
    let path = PathBuf::from(raw.trim());
    validate_executable(name, &path)
}

fn validate_executable(name: &str, path: &Path) -> Result<PathBuf, ProcessSandboxConfigError> {
    if !path.is_absolute() {
        return Err(ProcessSandboxConfigError::Invalid(format!(
            "{name} must be an absolute path"
        )));
    }
    let canonical = path.canonicalize().map_err(|error| {
        ProcessSandboxConfigError::Invalid(format!("{name} cannot be resolved: {error}"))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        ProcessSandboxConfigError::Invalid(format!("{name} metadata unavailable: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(ProcessSandboxConfigError::Invalid(format!(
            "{name} is not a regular file"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ProcessSandboxConfigError::Invalid(format!(
                "{name} is not executable"
            )));
        }
    }
    Ok(canonical)
}

fn bounded_env_u64(
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ProcessSandboxConfigError> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|_| ProcessSandboxConfigError::Invalid(format!("{name} must be an integer")))
            .and_then(|value| {
                if (min..=max).contains(&value) {
                    Ok(value)
                } else {
                    Err(ProcessSandboxConfigError::Invalid(format!(
                        "{name} must be between {min} and {max}"
                    )))
                }
            }),
        Err(_) => Ok(default),
    }
}

fn bounded_env_usize(
    name: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, ProcessSandboxConfigError> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .map_err(|_| ProcessSandboxConfigError::Invalid(format!("{name} must be an integer")))
            .and_then(|value| {
                if (min..=max).contains(&value) {
                    Ok(value)
                } else {
                    Err(ProcessSandboxConfigError::Invalid(format!(
                        "{name} must be between {min} and {max}"
                    )))
                }
            }),
        Err(_) => Ok(default),
    }
}

#[derive(Debug)]
pub enum ProcessSandboxError {
    Unavailable(String),
    InvalidRequest(String),
    Spawn(String),
    Input(String),
    Timeout,
    OutputLimit {
        stream: &'static str,
        max_bytes: usize,
    },
    WorkerExited {
        code: Option<i32>,
        stderr: String,
    },
    Protocol(String),
}

impl fmt::Display for ProcessSandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "process sandbox unavailable: {message}"),
            Self::InvalidRequest(message) => {
                write!(f, "invalid process sandbox request: {message}")
            }
            Self::Spawn(message) => write!(f, "process sandbox worker spawn failed: {message}"),
            Self::Input(message) => write!(f, "process sandbox worker input failed: {message}"),
            Self::Timeout => write!(f, "process sandbox worker timed out"),
            Self::OutputLimit { stream, max_bytes } => {
                write!(f, "process sandbox {stream} exceeded {max_bytes} bytes")
            }
            Self::WorkerExited { code, stderr } => {
                write!(f, "process sandbox worker exited with {code:?}: {stderr}")
            }
            Self::Protocol(message) => write!(f, "process sandbox protocol error: {message}"),
        }
    }
}

impl std::error::Error for ProcessSandboxError {}

#[derive(Clone)]
pub struct ProcessSandbox {
    config: ProcessSandboxConfig,
}

impl ProcessSandbox {
    pub fn new(config: ProcessSandboxConfig) -> Self {
        Self { config }
    }

    pub fn from_env() -> Result<Option<Self>, ProcessSandboxConfigError> {
        ProcessSandboxConfig::from_env().map(|config| config.map(Self::new))
    }

    pub fn profile(&self) -> &str {
        &self.config.profile
    }

    pub async fn run(
        &self,
        request: &ProcessSandboxRequest,
    ) -> Result<ProcessSandboxResponse, ProcessSandboxError> {
        validate_request(request)?;
        let payload = serde_json::to_vec(request)
            .map_err(|error| ProcessSandboxError::Input(error.to_string()))?;
        if payload.len() > 16 * 1024 {
            return Err(ProcessSandboxError::InvalidRequest(
                "serialized request exceeds 16 KiB".to_string(),
            ));
        }

        let mut command = Command::new(&self.config.launcher);
        command
            .args(&self.config.launcher_args)
            .arg(&self.config.worker)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("HOME", "/nonexistent")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        #[cfg(unix)]
        {
            // Every job owns a fresh process group so timeout cleanup also
            // reaches a browser child spawned by the configured launcher.
            command.process_group(0);
        }

        #[cfg(target_os = "linux")]
        {
            let max_memory_bytes = self.config.max_memory_bytes;
            let max_cpu_secs = self.config.max_cpu_secs;
            // Apply limits before the launcher starts.  This is an additional
            // containment layer; it does not replace the reviewed namespace,
            // seccomp, and capability-drop profile.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    set_process_limit(libc::RLIMIT_AS, max_memory_bytes)?;
                    set_process_limit(libc::RLIMIT_CPU, max_cpu_secs)?;
                    Ok(())
                });
            }
        }

        let mut child = command
            .spawn()
            .map_err(|error| ProcessSandboxError::Spawn(error.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            let input_result = tokio::time::timeout(self.config.timeout, async {
                stdin
                    .write_all(&payload)
                    .await
                    .map_err(|error| ProcessSandboxError::Input(error.to_string()))?;
                stdin
                    .shutdown()
                    .await
                    .map_err(|error| ProcessSandboxError::Input(error.to_string()))
            })
            .await;
            match input_result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    terminate_child_group(&mut child).await;
                    return Err(error);
                }
                Err(_) => {
                    terminate_child_group(&mut child).await;
                    return Err(ProcessSandboxError::Timeout);
                }
            }
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProcessSandboxError::Spawn("stdout pipe missing".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ProcessSandboxError::Spawn("stderr pipe missing".to_string()))?;

        let (stream_tx, mut stream_rx) = mpsc::channel(2);
        let stdout_handle = tokio::spawn(forward_stream(
            stdout,
            self.config.max_output_bytes,
            StreamKind::Stdout,
            stream_tx.clone(),
        ));
        let stderr_handle = tokio::spawn(forward_stream(
            stderr,
            self.config.max_stderr_bytes,
            StreamKind::Stderr,
            stream_tx,
        ));

        let mut wait_tick = tokio::time::interval(Duration::from_millis(10));
        let deadline = tokio::time::sleep(self.config.timeout);
        tokio::pin!(deadline);
        let mut exit_status = None;
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;

        while exit_status.is_none() || stdout_bytes.is_none() || stderr_bytes.is_none() {
            tokio::select! {
                _ = wait_tick.tick(), if exit_status.is_none() => {
                    match child.try_wait() {
                        Ok(Some(status)) => exit_status = Some(status),
                        Ok(None) => {}
                        Err(error) => {
                            terminate_child_group(&mut child).await;
                            stdout_handle.abort();
                            stderr_handle.abort();
                            return Err(ProcessSandboxError::Spawn(error.to_string()));
                        }
                    }
                }
                event = stream_rx.recv(), if stdout_bytes.is_none() || stderr_bytes.is_none() => {
                    match event {
                        Some(StreamEvent { kind: StreamKind::Stdout, result }) => {
                            match result {
                                Ok(bytes) => stdout_bytes = Some(bytes),
                                Err(()) => {
                                    terminate_child_group(&mut child).await;
                                    stdout_handle.abort();
                                    stderr_handle.abort();
                                    return Err(ProcessSandboxError::OutputLimit {
                                        stream: "stdout",
                                        max_bytes: self.config.max_output_bytes,
                                    });
                                }
                            }
                        }
                        Some(StreamEvent { kind: StreamKind::Stderr, result }) => {
                            match result {
                                Ok(bytes) => stderr_bytes = Some(bytes),
                                Err(()) => {
                                    terminate_child_group(&mut child).await;
                                    stdout_handle.abort();
                                    stderr_handle.abort();
                                    return Err(ProcessSandboxError::OutputLimit {
                                        stream: "stderr",
                                        max_bytes: self.config.max_stderr_bytes,
                                    });
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = &mut deadline => {
                    terminate_child_group(&mut child).await;
                    stdout_handle.abort();
                    stderr_handle.abort();
                    return Err(ProcessSandboxError::Timeout);
                }
            }
        }

        let _ = stdout_handle.await;
        let _ = stderr_handle.await;

        let status = exit_status.ok_or_else(|| {
            ProcessSandboxError::Spawn("worker exited without a process status".to_string())
        })?;
        let stderr_text = bounded_display(stderr_bytes.as_deref().unwrap_or_default());
        if !status.success() {
            return Err(ProcessSandboxError::WorkerExited {
                code: status.code(),
                stderr: stderr_text,
            });
        }

        let output = stdout_bytes.ok_or_else(|| {
            ProcessSandboxError::Protocol("worker produced no stdout response".to_string())
        })?;
        let response: ProcessSandboxResponse = serde_json::from_slice(&output)
            .map_err(|error| ProcessSandboxError::Protocol(format!("invalid JSON: {error}")))?;
        response.validate()?;
        Ok(response)
    }
}

#[cfg(target_os = "linux")]
fn set_process_limit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` is a valid pointer for the duration of this call and
    // the resource/value pair was bounded during configuration parsing.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn validate_request(request: &ProcessSandboxRequest) -> Result<(), ProcessSandboxError> {
    if request.schema_version != PROTOCOL_VERSION {
        return Err(ProcessSandboxError::InvalidRequest(
            "unsupported request schema version".to_string(),
        ));
    }
    if request.job_id.is_empty() || request.job_id.len() > 256 {
        return Err(ProcessSandboxError::InvalidRequest(
            "job_id must contain 1-256 bytes".to_string(),
        ));
    }
    let parsed = url::Url::parse(&request.target_url)
        .map_err(|error| ProcessSandboxError::InvalidRequest(error.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ProcessSandboxError::InvalidRequest(
            "target_url must be an HTTP(S) URL without userinfo".to_string(),
        ));
    }
    if request.profile != "offline_snapshot_v1" || request.network_mode != "none" {
        return Err(ProcessSandboxError::InvalidRequest(
            "worker requests must use the offline_snapshot_v1/no-network profile".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct StreamEvent {
    kind: StreamKind,
    result: Result<Vec<u8>, ()>,
}

async fn forward_stream<R>(
    reader: R,
    max_bytes: usize,
    kind: StreamKind,
    sender: mpsc::Sender<StreamEvent>,
) where
    R: AsyncRead + Unpin,
{
    let result = read_bounded(reader, max_bytes).await.map_err(|_| ());
    let _ = sender.send(StreamEvent { kind, result }).await;
}

async fn read_bounded<R>(mut reader: R, max_bytes: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(max_bytes.min(8192));
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream exceeds configured limit",
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn bounded_display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(1024).collect()
}

async fn terminate_child_group(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: process_group(0) created a group owned by this worker child.
        // The negative PID targets that group, not the parent engine.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn worker_script(body: &str) -> tempfile::TempPath {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "#!/bin/sh").unwrap();
        // Test workers must honor the same request/response protocol as real
        // workers. Consuming stdin also prevents the child from exiting while
        // the coordinator is still writing its request (an intermittent EPIPE).
        writeln!(file, "cat >/dev/null").unwrap();
        write!(file, "{body}").unwrap();
        let mut permissions = file.as_file().metadata().unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(file.path(), permissions).unwrap();
        file.into_temp_path()
    }

    fn config(file: &tempfile::TempPath) -> ProcessSandboxConfig {
        ProcessSandboxConfig {
            // Use a stable interpreter as the test launcher.  Executing the
            // freshly-created script directly can race with the temporary
            // file handle on some remote filesystems and surface ETXTBSY;
            // the production launcher is still validated separately.
            launcher: PathBuf::from("/bin/sh"),
            launcher_args: Vec::new(),
            worker: file.to_path_buf(),
            profile: "offline_snapshot_v1".to_string(),
            timeout: Duration::from_millis(500),
            max_output_bytes: 1024,
            max_stderr_bytes: 1024,
            max_memory_bytes: 256 * 1024 * 1024,
            max_cpu_secs: 1,
        }
    }

    #[tokio::test]
    async fn accepts_one_bounded_worker_response() {
        let worker = worker_script(
            "printf '%s' '{\"schema_version\":\"vigilyx.process-sandbox.v1\",\"status\":\"completed\",\"observations\":[]}'\n",
        );
        let sandbox = ProcessSandbox::new(config(&worker));
        let response = sandbox
            .run(&ProcessSandboxRequest::offline(
                "job-1",
                "https://example.com/",
            ))
            .await
            .unwrap();
        assert_eq!(response.status, WorkerResponseStatus::Completed);
    }

    #[tokio::test]
    async fn rejects_malformed_worker_json() {
        let worker = worker_script("printf '%s' 'not-json'\n");
        let error = ProcessSandbox::new(config(&worker))
            .run(&ProcessSandboxRequest::offline(
                "job-2",
                "https://example.com/",
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, ProcessSandboxError::Protocol(_)));
    }

    #[tokio::test]
    async fn enforces_stdout_limit() {
        let worker = worker_script("head -c 2048 /dev/zero\n");
        let error = ProcessSandbox::new(config(&worker))
            .run(&ProcessSandboxRequest::offline(
                "job-3",
                "https://example.com/",
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ProcessSandboxError::OutputLimit {
                stream: "stdout",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn kills_timed_out_worker() {
        let worker = worker_script("sleep 5\n");
        let error = ProcessSandbox::new(config(&worker))
            .run(&ProcessSandboxRequest::offline(
                "job-4",
                "https://example.com/",
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProcessSandboxError::Timeout),
            "expected timeout, got {error:?}"
        );
    }

    #[tokio::test]
    async fn reports_nonzero_worker_exit() {
        let worker = worker_script("printf '%s' 'failed' >&2\nexit 7\n");
        let error = ProcessSandbox::new(config(&worker))
            .run(&ProcessSandboxRequest::offline(
                "job-5",
                "https://example.com/",
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ProcessSandboxError::WorkerExited { code: Some(7), .. }
        ));
    }

    #[test]
    fn rejects_non_absolute_executable_configuration() {
        let error = validate_executable("worker", Path::new("worker")).unwrap_err();
        assert!(error.to_string().contains("absolute path"));
    }

    #[test]
    fn rejects_unreviewed_launcher_profile() {
        let error = validate_launcher_profile(Path::new("/usr/bin/sh"), &[]).unwrap_err();
        assert!(error.to_string().contains("bubblewrap"));
    }

    #[test]
    fn rejects_bubblewrap_profile_that_keeps_network() {
        let args = vec!["--share-net".to_string(), "--".to_string()];
        let error = validate_launcher_profile(Path::new("/usr/bin/bwrap"), &args).unwrap_err();
        assert!(
            error.to_string().contains("missing required flag")
                || error.to_string().contains("forbidden flag")
        );
    }

    #[test]
    fn request_cannot_enable_network_or_userinfo() {
        let mut request = ProcessSandboxRequest::offline("job-6", "https://user@example.com/");
        assert!(validate_request(&request).is_err());
        request = ProcessSandboxRequest::offline("job-7", "https://example.com/");
        request.network_mode = "internet";
        assert!(validate_request(&request).is_err());
    }
}
