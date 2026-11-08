// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Per-job RPC bridge. The operator socket and node credentials never enter a workload.
use super::*;
use crate::{
    delegation::{DelegationLease, DelegationProvider},
    wire::JobState,
};
use std::sync::{Weak, atomic::AtomicBool};

pub(super) struct Provider {
    pub host: Weak<Host>,
    pub runtime: tokio::runtime::Handle,
}
impl DelegationProvider for Provider {
    fn prepare(&self, parent: &str, job_dir: &Path) -> Result<DelegationLease> {
        if !wire::valid_ulid(parent) {
            return Err("invalid delegation parent".into());
        }
        let host = self.host.upgrade().ok_or("delegation host stopped")?;
        let executor = host
            .executor
            .as_ref()
            .ok_or("delegation executor unavailable")?;
        let configured = host
            .config
            .executor
            .as_ref()
            .ok_or("delegation executor unavailable")?;
        if job_dir != configured.state_dir.join("jobs").join(parent) {
            return Err("delegation directory differs from admitted parent".into());
        }
        if !matches!(
            executor.status(parent)?.state,
            JobState::Starting | JobState::Running
        ) {
            return Err("delegation parent is not active".into());
        }
        let directory = job_dir.join("runtime-delegation");
        private_dir(&directory)?;
        let mut result_trust = host.config.result_trust.clone();
        if let Some(signing) = &configured.provenance {
            let key = crate::provenance::TrustedSigningKey {
                public_key: signing.public_key.clone(),
            };
            key.validate()?;
            if result_trust
                .get(&host.config.node_id)
                .is_some_and(|existing| existing != &key)
            {
                return Err("delegation local signing trust differs from executor".into());
            }
            result_trust.insert(host.config.node_id.clone(), key);
        }
        let config = NodeConfig {
            node_id: host.config.node_id.clone(),
            workspace: host.config.workspace.clone(),
            state_dir: PathBuf::from(format!("/tmp/lockyard-delegated-{parent}")),
            listen: None,
            certificate: "/run/lockyard-delegation/no-certificate".into(),
            private_key: "/run/lockyard-delegation/no-private-key".into(),
            trust_anchors: vec![],
            peers: vec![],
            relay: None,
            executor: None,
            metadata_notifications: false,
            result_trust,
            project_retention: BTreeMap::new(),
            workflow: None,
            delegation_socket: Some("/run/lockyard-delegation/control.sock".into()),
            revocations: None,
            rpc_timeout_seconds: host.config.rpc_timeout_seconds,
        };
        config.validate()?;
        store_data(
            &directory,
            "node.toml",
            toml::to_string(&config)?.as_bytes(),
        )?;
        let socket = directory.join("control.sock");
        let listener = bind_socket(&directory, &socket, &self.runtime)?;
        lockyard_core::fsio::sync_path(&directory)?;
        let active = Arc::new(AtomicBool::new(true));
        let active_task = active.clone();
        let weak = self.host.clone();
        let discovery = Arc::new(super::workflow_adapter::Driver::new(self.host.clone()));
        let parent = parent.to_owned();
        let task=self.runtime.spawn(async move {
            let permits=Arc::new(Semaphore::new(8));
            let submissions=Arc::new(std::sync::Mutex::new(BTreeSet::<String>::new()));
            let mut tasks=tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=> {
                        let Ok((stream,_))=accepted else {break;};
                        let Ok(permit)=permits.clone().try_acquire_owned() else {drop(stream);continue;};
                        let Some(host)=weak.upgrade() else {break;};
                        let Ok(global_permit)=host.delegation_connections.clone().try_acquire_owned() else {drop(stream);continue;};
                        if !active_task.load(Ordering::Acquire){break;}
                        let active=active_task.clone();let parent=parent.clone();let submissions=submissions.clone();let discovery=discovery.clone();
                        tasks.spawn(async move {let _permit=permit;let _global_permit=global_permit;let _=connection(host,stream,&parent,&active,&submissions,discovery.as_ref()).await;});
                    },
                    _=tasks.join_next(),if !tasks.is_empty()=>{},
                }
            }
            // Dropping JoinSet aborts incomplete requests. Already accepted remote jobs
            // retain their own immutable job identity and continue independently.
        });
        let cleanup_socket = socket.clone();
        Ok(DelegationLease::new(directory, move || {
            active.store(false, Ordering::Release);
            task.abort();
            let _ = fs::remove_file(cleanup_socket);
        }))
    }
}

#[cfg(unix)]
fn bind_socket(
    directory: &Path,
    socket: &Path,
    runtime: &tokio::runtime::Handle,
) -> Result<UnixListener> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };
    if let Ok(metadata) = fs::symlink_metadata(socket) {
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("unsafe delegation socket path".into());
        }
        fs::remove_file(socket)?;
    }
    // Linux's sockaddr_un limit applies to the spelling used at bind, not the
    // inode's eventual mount path. A directory FD also handles long state roots.
    let directory_file = File::open(directory)?;
    let short = PathBuf::from(format!(
        "/proc/self/fd/{}/control.sock",
        directory_file.as_raw_fd()
    ));
    let bind_path = if socket.as_os_str().len() < 100 {
        socket
    } else {
        short.as_path()
    };
    let listener = std::os::unix::net::UnixListener::bind(bind_path)?;
    listener.set_nonblocking(true)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let _entered = runtime.enter();
    Ok(UnixListener::from_std(listener)?)
}

async fn connection(
    host: Arc<Host>,
    mut stream: UnixStream,
    parent: &str,
    active: &AtomicBool,
    submissions: &std::sync::Mutex<BTreeSet<String>>,
    discovery: &super::workflow_adapter::Driver,
) -> Result<()> {
    #[cfg(unix)]
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Err("delegation peer denied".into());
    }
    let request: Control =
        serde_json::from_slice(&read_packet(&mut stream, Duration::from_secs(5)).await?)
            .map_err(|_| "invalid delegation request")?;
    let result: Result<Value> = async {
        if !active.load(Ordering::Acquire) {
            return Err("delegation lease has ended".into());
        }
        let executor = host
            .executor
            .as_ref()
            .ok_or("delegation executor unavailable")?;
        if !matches!(
            executor.status(parent)?.state,
            JobState::Starting | JobState::Running | JobState::InterruptedUnknown
        ) {
            return Err("delegation parent is not active".into());
        }
        let Control::Rpc {
            target,
            operation,
            payload,
        } = request
        else {
            return Err("workload bridge permits scoped RPC operations only".into());
        };
        if operation == Operation::JobResolveUnknown {
            return Err("workload bridge cannot resolve unknown execution".into());
        }
        if operation == Operation::NodePing
            && target == host.config.node_id
            && payload.get("discover").and_then(Value::as_bool) == Some(true)
        {
            let nodes = crate::workflow::WorkflowDriver::describe_nodes(discovery).await?;
            return Ok(serde_json::to_value(RpcReply::success(
                json!({"source":"delegation","nodes":nodes}),
            ))?);
        }
        if operation == Operation::JobSubmit {
            let id = payload
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| wire::valid_ulid(id))
                .ok_or("delegated submit requires stable job ID")?;
            let mut ids = submissions
                .lock()
                .map_err(|_| "delegation capacity unavailable")?;
            if !ids.contains(id) && ids.len() >= 256 {
                return Err("delegation child admission capacity reached".into());
            }
            ids.insert(id.into());
        }
        let reply = host
            .rpc_bound(
                &target,
                operation,
                payload,
                None,
                crate::incarnation::DispatchOrigin::Job(parent.into()),
            )
            .await?;
        Ok(serde_json::to_value(reply)?)
    }
    .await;
    let response = match result {
        Ok(value) => ControlReply {
            value: Some(value),
            error: None,
        },
        Err(_) => ControlReply {
            value: None,
            error: Some("scoped node RPC failed; query the same child job ID".into()),
        },
    };
    write_packet(&mut stream, &serde_json::to_vec(&response)?).await
}

#[cfg(windows)]
fn bind_socket(
    directory: &Path,
    socket: &Path,
    runtime: &tokio::runtime::Handle,
) -> Result<UnixListener> {
    let _entered = runtime.enter();
    let _ = directory;
    Ok(UnixListener::bind(socket)?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::executor::regression_tests::{retained_fixture_record, retention_fixture};
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_private_socket_allows_rpc_but_denies_operator_controls_and_ends_with_lease() {
        // Synthetic parent journal only. This proves the actual Unix capability
        // boundary; it does not run or claim a resource-enforced container.
        let (_host_root, mut host) = super::super::tests::fixture();
        let (_executor_root, mut config, executor) = retention_fixture();
        drop(executor);
        // Exercise the ordinary Unix socket here independently of TMPDIR length.
        // The long-path directory-FD fallback has its own Linux-specific test below.
        let socket_root = tempfile::Builder::new()
            .prefix("ly")
            .tempdir_in("/tmp")
            .unwrap();
        config.state_dir = socket_root.path().canonicalize().unwrap().join("executor");
        let executor = crate::executor::Executor::new(config.clone()).unwrap();
        let parent =
            retained_fixture_record(&executor, JobState::Starting, wall_ms().unwrap() + 60_000);
        assert!(
            config
                .state_dir
                .join("jobs")
                .join(&parent.spec.id)
                .join("runtime-delegation/control.sock")
                .as_os_str()
                .len()
                < 100
        );
        host.config.executor = Some(config.clone());
        host.executor = Some(executor.clone());
        let host = Arc::new(host);
        let provider = Provider {
            host: Arc::downgrade(&host),
            runtime: tokio::runtime::Handle::current(),
        };
        let lease = provider
            .prepare(
                &parent.spec.id,
                &config.state_dir.join("jobs").join(&parent.spec.id),
            )
            .unwrap();
        let socket = lease.directory.join("control.sock");
        let config_bytes = fs::read_to_string(lease.directory.join("node.toml")).unwrap();
        let client: NodeConfig = toml::from_str(&config_bytes).unwrap();
        client.validate().unwrap();
        assert!(client.delegation_socket.is_some());
        assert!(
            client.executor.is_none()
                && client.relay.is_none()
                && client.private_key.to_string_lossy().starts_with("/run/")
        );
        let ping = call_control(
            &socket,
            Control::Rpc {
                target: host.config.node_id.clone(),
                operation: Operation::NodePing,
                payload: Value::Null,
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(ping["ok"], true);
        assert_eq!(ping["result"]["node_id"], host.config.node_id);
        for control in [
            Control::Status,
            Control::Drain { enabled: true },
            Control::DrainStatus,
            Control::Dispatch {
                expected_local_certificate_sha256: host.certificate_sha256.clone(),
                request: crate::incarnation::DispatchControl::List {
                    offset: 0,
                    limit: 100,
                },
            },
            Control::Workflow {
                request: crate::workflow::WorkflowControl::List {
                    offset: 0,
                    limit: 100,
                },
            },
            Control::Rpc {
                target: host.config.node_id.clone(),
                operation: Operation::JobResolveUnknown,
                payload: json!({"job_id":parent.spec.id}),
            },
        ] {
            assert!(
                call_control(&socket, control, Duration::from_secs(5))
                    .await
                    .is_err()
            );
        }
        // A caller cannot smuggle an authority origin into strict Control JSON.
        assert!(
            serde_json::from_value::<Control>(
                json!({"command":"rpc","target":"worker","operation":"node.ping",
            "payload":null,"origin":{"kind":"operator"}})
            )
            .is_err()
        );
        drop(lease);
        assert!(UnixStream::connect(socket).await.is_err());
    }
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn long_state_paths_bind_with_directory_fd_and_are_reachable_by_their_mount_inode() {
        let root = tempfile::tempdir().unwrap();
        let directory=root.path().join("long-directory-component-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        private_dir(&directory).unwrap();
        let socket = directory.join("control.sock");
        assert!(socket.as_os_str().len() >= 100);
        let listener =
            bind_socket(&directory, &socket, &tokio::runtime::Handle::current()).unwrap();
        let client = UnixStream::connect(&socket);
        // Connecting with the host's long name hits sockaddr_un limits as expected;
        // the workload uses the short /run/lockyard-delegation mount path.
        assert!(client.await.is_err());
        use std::os::fd::AsRawFd;
        let directory_file = File::open(&directory).unwrap();
        let short = PathBuf::from(format!(
            "/proc/self/fd/{}/control.sock",
            directory_file.as_raw_fd()
        ));
        let stream = UnixStream::connect(short).await.unwrap();
        listener.accept().await.unwrap();
        drop(stream);
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn long_state_paths_without_linux_fd_paths_refuse_without_publishing_a_socket() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("long-directory-component-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        private_dir(&directory).unwrap();
        let socket = directory.join("control.sock");
        assert!(socket.as_os_str().len() >= 100);
        let error = bind_socket(&directory, &socket, &tokio::runtime::Handle::current())
            .expect_err("a Linux /proc/self/fd socket alias must not bind on this platform");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!socket.exists());
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    }
}
