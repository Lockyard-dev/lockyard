// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn serialized_log_guard_rejects_unsafe_marker_and_shared_stream_boundary() {
    for (raw, secrets) in [
        (b"REDACTED".to_vec(), vec![b"REDACTED".to_vec()]),
        (
            b"asecretb".to_vec(),
            vec![b"secret".to_vec(), b"a[REDACTED]b".to_vec()],
        ),
    ] {
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 4096,
            error: None,
            credential_tail: Vec::new(),
        }));
        assert!(
            drain(
                std::io::Cursor::new(raw),
                spool.clone(),
                secrets.clone(),
                Arc::new(AtomicBool::new(false))
            )
            .is_err()
        );
        let spool = spool.lock().unwrap();
        assert_eq!(spool.error, Some("serialized_log_contains_credential"));
        for secret in secrets {
            assert!(
                !spool
                    .file
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
    }
    // stdout and stderr append into one shared spool; their joint output must be safe too.
    let secrets = vec![b"abc".to_vec()];
    let mut spool = Spool {
        file: Vec::new(),
        bytes: 0,
        truncated: false,
        limit: 4096,
        error: None,
        credential_tail: Vec::new(),
    };
    let matcher = CredentialMatcher::new(&secrets).unwrap();
    spool.append(b"ab", &matcher).unwrap();
    assert!(spool.append(b"c", &matcher).is_err());
    assert_eq!(spool.file, b"ab");
    assert_eq!(spool.error, Some("serialized_log_contains_credential"));
}
#[test]
fn overlapping_credentials_redact_longest_match_without_leaving_a_suffix() {
    let spool = Arc::new(Mutex::new(Spool {
        file: Vec::new(),
        bytes: 0,
        truncated: false,
        limit: 4096,
        error: None,
        credential_tail: Vec::new(),
    }));
    drain(
        std::io::Cursor::new(b"ABCDE"),
        spool.clone(),
        vec![b"ABC".to_vec(), b"ABCDE".to_vec()],
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(spool.lock().unwrap().file, b"[REDACTED]");
}
#[test]
fn overlapping_redaction_handles_arbitrary_read_boundaries() {
    struct Chunked<'a> {
        bytes: &'a [u8],
        chunk: usize,
    }
    impl Read for Chunked<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = self.bytes.len().min(self.chunk).min(out.len());
            out[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }
    let secrets = vec![
        b"abc".to_vec(),
        b"abcde".to_vec(),
        b"bcd".to_vec(),
        b"zab".to_vec(),
    ];
    let input = b"zabcdeabcxzababcde";
    let mut expected = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        if let Some(pattern) = secrets
            .iter()
            .filter(|pattern| input[pos..].starts_with(pattern))
            .max_by_key(|pattern| pattern.len())
        {
            expected.extend_from_slice(b"[REDACTED]");
            pos += pattern.len();
        } else {
            expected.push(input[pos]);
            pos += 1;
        }
    }
    for chunk in 1..=input.len() {
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 4096,
            error: None,
            credential_tail: Vec::new(),
        }));
        drain(
            Chunked {
                bytes: input,
                chunk,
            },
            spool.clone(),
            secrets.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(spool.lock().unwrap().file, expected, "chunk size {chunk}");
    }
}
#[test]
fn long_overlapping_credentials_are_screened_without_quadratic_work() {
    let secrets: Vec<Vec<u8>> = (0..64)
        .map(|index| {
            let mut secret = vec![b'A'; 16384];
            secret[16382] = 64 + index;
            secret[16383] = b'B';
            secret
        })
        .collect();
    let mut data = vec![b'A'; 64 * 1024];
    data.push(b'B');
    let spool = Arc::new(Mutex::new(Spool {
        file: Vec::new(),
        bytes: 0,
        truncated: false,
        limit: 2 * 1024 * 1024,
        error: None,
        credential_tail: Vec::new(),
    }));
    drain(
        std::io::Cursor::new(&data),
        spool.clone(),
        secrets.clone(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let output = &spool.lock().unwrap().file;
    assert_eq!(output.len(), 64 * 1024 - 16383 + b"[REDACTED]".len());
    assert!(output.ends_with(b"[REDACTED]"));
    assert_eq!(
        scan_credential_stream(std::io::Cursor::new(&data), &secrets, 2 * 1024 * 1024)
            .unwrap_err()
            .0,
        "patch_contains_forwarded_credential"
    );
}
