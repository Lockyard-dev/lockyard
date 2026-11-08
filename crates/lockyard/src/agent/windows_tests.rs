// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
// Included inside daemon::tests so the cross-platform authority fixtures stay shared.
struct ClaimAuthority {
    fake: FakeServer,
    store: Mutex<lockyard_core::Store>,
}
impl Transport for ClaimAuthority {
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        if call.method == "POST" && call.path == "/api/v1/zones/claims" {
            let request = lockyard_core::proto::ClaimRequest {
                paths: vec!["src/shared.rs".into()],
                note: "Windows IPC arbitration".into(),
                ttl_minutes: 60,
                ..Default::default()
            };
            assert_eq!(call.body.as_ref().unwrap()["paths"], json!(request.paths));
            return match Backend::claim(
                &mut *self.store.lock().unwrap(),
                &call.session,
                &request,
                crate::now_ms(),
            ) {
                Ok(claim) => Ok(json!({"claim":claim})),
                Err(Error::Conflict(conflicts)) => {
                    Err(ClientError::Conflict(lockyard_cloud_client::ApiError {
                        status: 409,
                        code: "zone_conflict".into(),
                        details: json!({"conflicts":conflicts}),
                        ..Default::default()
                    }))
                }
                Err(error) => panic!("authority failed: {error}"),
            };
        }
        self.fake.call(call)
    }
}
#[test]
fn windows_two_sessions_one_claim_named_pipe() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("authority")).unwrap();
    let authority = Arc::new(ClaimAuthority {
        fake: FakeServer::default(),
        store: Mutex::new(lockyard_core::Store::init(&directory.path().join("authority")).unwrap()),
    });
    let mut settings = config(directory.path(), timing());
    settings.socket =
        lockyard_core::windows::pipe_path(&directory.path().to_string_lossy()).unwrap();
    let daemon = Daemon::start(settings.clone(), authority.clone()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut peers = Vec::new();
    for session in ["alice", "bob"] {
        let socket = AgentSocket::connect_in_state(
            &settings.socket,
            &settings.url,
            &settings.workspace,
            Duration::from_secs(5),
            &settings.state_root,
        )
        .unwrap();
        let barrier = barrier.clone();
        peers.push(thread::spawn(move || {
            barrier.wait();
            socket.ask(&Request::Call { call:Call::write(session,"POST","/api/v1/zones/claims".into(),json!({"paths":["src/shared.rs"],"note":"Windows IPC arbitration","ttl_minutes":60})) }).unwrap()
        }));
    }
    barrier.wait();
    let replies: Vec<_> = peers.into_iter().map(|peer| peer.join().unwrap()).collect();
    assert_eq!(
        replies.iter().filter(|reply| reply.error.is_none()).count(),
        1
    );
    assert_eq!(
        replies
            .iter()
            .filter(|reply| matches!(reply.error, Some(ClientError::Conflict(_))))
            .count(),
        1
    );
    let claims = Backend::claims(
        &*authority.store.lock().unwrap(),
        &ClaimQuery::default(),
        crate::now_ms(),
    )
    .unwrap();
    assert_eq!(claims.len(), 1);
    assert!(matches!(claims[0].session.as_str(), "alice" | "bob"));
    drop(daemon);
}
#[test]
fn windows_agent_restarts_while_an_idle_client_stays_open() {
    let directory = tempfile::tempdir().unwrap();
    let settings = config(directory.path(), timing());
    let daemon = Daemon::start(settings.clone(), Arc::new(FakeServer::default())).unwrap();
    let _idle = UnixStream::connect(&settings.socket).unwrap();
    drop(daemon);
    let replacement = Daemon::start(settings, Arc::new(FakeServer::default())).unwrap();
    drop(replacement);
}

#[test]
fn windows_workspaces_do_not_share_durable_agent_state() {
    let root = tempfile::tempdir().unwrap();
    let first = config(root.path(), timing());
    let mut second = first.clone();
    second.workspace = "other-workspace".into();
    assert_ne!(state_folder(&first), state_folder(&second));
}
