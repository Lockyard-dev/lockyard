// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_db(command: DbCommand, cwd: &Path) -> Result<Output> {
    match command {
        DbCommand::Backup { path } => {
            let destination = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            let store = Store::discover(cwd)?;
            store.backup(&destination)?;
            let path = destination.display().to_string();
            output(
                &json!({ "path": path }),
                format!("Database backup at {path}"),
            )
        }
    }
}
