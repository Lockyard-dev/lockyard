// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Real, private key storage per unit-test thread. Never mutate XDG_CONFIG_HOME: even
//! readers with in-memory keys consult disk, and unrelated threads can read the environment.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;

thread_local! {
    static KEY_HOME: RefCell<tempfile::TempDir> = RefCell::new(tempfile::tempdir().unwrap());
}

pub(crate) fn key_config_home() -> PathBuf {
    // Key storage rejects symlinked parents; macOS spells its temporary root via /var.
    KEY_HOME.with(|home| home.borrow().path().canonicalize().unwrap())
}

pub(crate) struct KeyEnv {
    previous: Option<tempfile::TempDir>,
    // Restoration belongs to the thread on which the guard was created.
    _same_thread: PhantomData<Rc<()>>,
}

impl KeyEnv {
    pub(crate) fn new() -> Self {
        let next = tempfile::tempdir().unwrap();
        let previous = KEY_HOME.with(|home| home.replace(next));
        Self {
            previous: Some(previous),
            _same_thread: PhantomData,
        }
    }
}

impl Drop for KeyEnv {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            KEY_HOME.with(|home| home.replace(previous));
        }
    }
}

#[test]
fn key_homes_isolate_the_same_workspace_and_restore_after_unwind() {
    use crate::WorkspaceKey;
    let original = key_config_home();
    let key = WorkspaceKey::from_entropy([11; 32]);
    key.store_for_workspace("same-workspace").unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert_ne!(key_config_home(), original);
                assert!(
                    WorkspaceKey::load_for_workspace("same-workspace")
                        .unwrap()
                        .is_none()
                );
                WorkspaceKey::from_entropy([22; 32])
                    .store_for_workspace("same-workspace")
                    .unwrap();
            })
            .join()
            .unwrap();
    });
    let nested = std::panic::catch_unwind(|| {
        let _env = KeyEnv::new();
        assert_ne!(key_config_home(), original);
        assert!(
            WorkspaceKey::load_for_workspace("same-workspace")
                .unwrap()
                .is_none()
        );
        panic!("exercise guard restoration");
    });
    assert!(nested.is_err());
    assert_eq!(key_config_home(), original);
    assert_eq!(
        WorkspaceKey::load_for_workspace("same-workspace")
            .unwrap()
            .unwrap()
            .key_id(),
        key.key_id()
    );
}
