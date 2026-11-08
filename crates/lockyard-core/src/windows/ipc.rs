// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Authenticated byte-stream named pipes; framing is owned by callers on every platform.
use super::{Security, checked, denied, pipe_path, require_private_handle, token_user};
use std::{
    cell::Cell,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    runtime::Runtime,
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_BUSY, HANDLE},
    Security::{
        Authorization::SE_KERNEL_OBJECT, EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::{
        Pipes::GetNamedPipeClientProcessId,
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

// Inspect the connected peer's process token, independently of the pipe object's ACL.
// No impersonation is entered, so a failed check cannot leave a worker under client identity.
fn require_client_user(pipe: HANDLE, owner: &[usize]) -> io::Result<()> {
    let mut process_id = 0;
    checked(unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) })?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = std::ptr::null_mut();
    checked(unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) })?;
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
    }
    if size < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::last_os_error());
    }
    let mut peer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            peer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    })?;
    let expected = unsafe { (*owner.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let actual = unsafe { (*peer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if unsafe { EqualSid(expected, actual) } == 0 {
        return Err(denied());
    }
    Ok(())
}
fn endpoint(path: &Path) -> io::Result<PathBuf> {
    if path.to_string_lossy().starts_with(r"\\.\pipe\lockyard-") {
        Ok(path.to_path_buf())
    } else {
        pipe_path(&path.to_string_lossy())
    }
}
fn server(path: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let security = Security::new()?;
    let mut attributes = security.attributes();
    // The owner-only descriptor exists at creation. The next instance is opened while
    // the current one still exists, so another user cannot occupy the name between accepts.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                path,
                (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
            )
    }
}
enum Pipe {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}
pub struct AsyncStream {
    pipe: Pipe,
    pending_operation: bool,
}
impl Drop for AsyncStream {
    fn drop(&mut self) {
        // A timed-out future can leave Mio owning an overlapped write. Cancel
        // that operation before the wrapper releases its last visible handle.
        if self.pending_operation {
            let handle = match &self.pipe {
                Pipe::Client(pipe) => pipe.as_raw_handle(),
                Pipe::Server(pipe) => pipe.as_raw_handle(),
            };
            unsafe {
                windows_sys::Win32::System::IO::CancelIoEx(handle, std::ptr::null());
            }
        }
    }
}
impl AsyncStream {
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::connect_timeout(path.as_ref(), Duration::from_secs(1)).await
    }
    pub async fn connect_timeout(path: &Path, timeout: Duration) -> io::Result<Self> {
        let path = endpoint(path)?;
        tokio::time::timeout(timeout, async {
            loop {
                match ClientOptions::new().open(&path) {
                    Ok(pipe) => {
                        // Tokio requests SECURITY_IDENTIFICATION; the server cannot act as this caller.
                        require_private_handle(pipe.as_raw_handle(), SE_KERNEL_OBJECT)?;
                        return Ok(Self {
                            pipe: Pipe::Client(pipe),
                            pending_operation: false,
                        });
                    }
                    Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                        tokio::time::sleep(Duration::from_millis(2)).await
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await?
    }
}
impl AsyncRead for AsyncStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().pipe {
            Pipe::Client(pipe) => Pin::new(pipe).poll_read(cx, buf),
            Pipe::Server(pipe) => Pin::new(pipe).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for AsyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        let result = match &mut stream.pipe {
            Pipe::Client(pipe) => Pin::new(pipe).poll_write(cx, buf),
            Pipe::Server(pipe) => Pin::new(pipe).poll_write(cx, buf),
        };
        stream.pending_operation = result.is_pending();
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        // A zero-byte write waits for the previous Mio overlapped write; Tokio's
        // own named-pipe flush is a no-op. No caller bytes are added here.
        let result = match &mut stream.pipe {
            Pipe::Client(pipe) => Pin::new(pipe).poll_write(cx, &[]).map_ok(|_| ()),
            Pipe::Server(pipe) => Pin::new(pipe).poll_write(cx, &[]).map_ok(|_| ()),
        };
        stream.pending_operation = result.is_pending();
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

pub struct AsyncListener {
    path: PathBuf,
    owner: Vec<usize>,
    pending: tokio::sync::Mutex<NamedPipeServer>,
}
impl AsyncListener {
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = endpoint(path.as_ref())?;
        let owner = token_user()?;
        let pending = server(&path, true)?;
        Ok(Self {
            path,
            owner,
            pending: tokio::sync::Mutex::new(pending),
        })
    }
    pub async fn accept(&self) -> io::Result<(AsyncStream, ())> {
        let mut pending = self.pending.lock().await;
        pending.connect().await?;
        // A disconnected pipe is not a fresh listening instance: clients get
        // ERROR_PIPE_BUSY until ConnectNamedPipe is issued again. Rotate even
        // rejected connections, keeping the namespace occupied throughout.
        // This also avoids reusing Mio's buffered I/O state after disconnect.
        let next = match server(&self.path, false) {
            Ok(next) => next,
            Err(error) => {
                let _ = pending.disconnect();
                return Err(error);
            }
        };
        let connected = std::mem::replace(&mut *pending, next);
        if let Err(error) = (|| {
            require_private_handle(connected.as_raw_handle(), SE_KERNEL_OBJECT)?;
            require_client_user(connected.as_raw_handle(), &self.owner)
        })() {
            let _ = connected.disconnect();
            return Err(error);
        }
        Ok((
            AsyncStream {
                pipe: Pipe::Server(connected),
                pending_operation: false,
            },
            (),
        ))
    }
}
/// Synchronous adapter for the threaded agent and short-lived hook. All frames remain shared.
struct Connection {
    pipe: Mutex<Option<AsyncStream>>,
    cancelled: std::sync::atomic::AtomicBool,
    incomplete_write: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}
impl Connection {
    fn close(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake.notify_one();
        if let Ok(mut pipe) = self.pipe.lock() {
            match pipe.as_ref().map(|stream| &stream.pipe) {
                Some(Pipe::Server(server)) => {
                    unsafe {
                        windows_sys::Win32::System::IO::CancelIoEx(
                            server.as_raw_handle(),
                            std::ptr::null(),
                        );
                    }
                    let _ = server.disconnect();
                }
                Some(Pipe::Client(client)) => unsafe {
                    windows_sys::Win32::System::IO::CancelIoEx(
                        client.as_raw_handle(),
                        std::ptr::null(),
                    );
                },
                None => {}
            }
            pipe.take();
        }
    }
    async fn cancelled(&self) {
        if !self.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            self.wake.notified().await;
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        // Aborted writes must not retain a hidden Mio server instance after the
        // last worker exits. A successful write is drained before returning;
        // leave its unread reply intact when closing the last server handle.
        if self
            .incomplete_write
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.close();
        }
    }
}
pub struct LocalStream {
    connection: Arc<Connection>,
    runtime: Arc<Runtime>,
    read_timeout: Cell<Option<Duration>>,
    write_timeout: Cell<Option<Duration>>,
}
fn runtime() -> io::Result<Arc<Runtime>> {
    // Keep the IOCP driver alive while deferred cancellation completions own
    // native handles, including after a short-lived client wrapper is dropped.
    static RUNTIME: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);
    let mut runtime = RUNTIME
        .lock()
        .map_err(|_| io::Error::other("pipe runtime poisoned"))?;
    if runtime.is_none() {
        *runtime = Some(Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()?,
        ));
    }
    Ok(runtime.as_ref().unwrap().clone())
}
impl LocalStream {
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::connect_timeout(path.as_ref(), Duration::from_secs(1))
    }
    pub fn connect_timeout(path: &Path, timeout: Duration) -> io::Result<Self> {
        let runtime = runtime()?;
        let pipe = runtime.block_on(AsyncStream::connect_timeout(path, timeout))?;
        Ok(Self::new(runtime, pipe))
    }
    fn new(runtime: Arc<Runtime>, pipe: AsyncStream) -> Self {
        Self {
            runtime,
            connection: Arc::new(Connection {
                pipe: Mutex::new(Some(pipe)),
                cancelled: std::sync::atomic::AtomicBool::new(false),
                incomplete_write: std::sync::atomic::AtomicBool::new(false),
                wake: tokio::sync::Notify::new(),
            }),
            read_timeout: Cell::new(None),
            write_timeout: Cell::new(None),
        }
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            runtime: self.runtime.clone(),
            connection: self.connection.clone(),
            read_timeout: Cell::new(self.read_timeout.get()),
            write_timeout: Cell::new(self.write_timeout.get()),
        })
    }
    pub fn set_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.read_timeout.set(value);
        Ok(())
    }
    pub fn set_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.write_timeout.set(value);
        Ok(())
    }
    fn lock(
        &self,
        limit: Option<Duration>,
    ) -> io::Result<(
        std::sync::MutexGuard<'_, Option<AsyncStream>>,
        Option<Duration>,
    )> {
        let start = std::time::Instant::now();
        loop {
            match self.connection.pipe.try_lock() {
                Ok(guard) => {
                    return Ok((
                        guard,
                        limit.map(|limit| limit.saturating_sub(start.elapsed())),
                    ));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("pipe lock poisoned"));
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if limit.is_some_and(|limit| start.elapsed() >= limit) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe deadline expired",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "pipe listener stopped")
}
impl Read for LocalStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (mut guard, limit) = self.lock(self.read_timeout.get())?;
        let pipe = guard.as_mut().ok_or_else(closed)?;
        self.runtime.block_on(async {
            let read=async { match limit { Some(limit)=>tokio::time::timeout(limit,pipe.read(buf)).await?,None=>pipe.read(buf).await } };
            tokio::select! { biased; _=self.connection.cancelled()=>Err(closed()), result=read=>result }
        })
    }
}
impl Write for LocalStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (mut guard, limit) = self.lock(self.write_timeout.get())?;
        let pipe = guard.as_mut().ok_or_else(closed)?;
        self.connection
            .incomplete_write
            .store(true, std::sync::atomic::Ordering::Release);
        let result = self.runtime.block_on(async {
            let write = async {
                let write = async { let written = pipe.write(buf).await?; pipe.flush().await?; Ok(written) };
                match limit { Some(limit) => tokio::time::timeout(limit, write).await?, None => write.await }
            };
            tokio::select! { biased; _=self.connection.cancelled()=>Err(closed()), result=write=>result }
        });
        if result.is_ok() {
            self.connection
                .incomplete_write
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Clone)]
pub struct ListenerStop(Arc<Connection>);
impl ListenerStop {
    pub fn stop(&self) {
        self.0.close();
    }
}
pub struct LocalListener {
    listener: AsyncListener,
    stop: ListenerStop,
    connections: Mutex<Vec<std::sync::Weak<Connection>>>,
    runtime: Arc<Runtime>,
}
impl LocalListener {
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let runtime = runtime()?;
        let listener = {
            let _entered = runtime.enter();
            AsyncListener::bind(path)?
        };
        Ok(Self {
            runtime,
            listener,
            connections: Mutex::new(Vec::new()),
            stop: ListenerStop(Arc::new(Connection {
                pipe: Mutex::new(None),
                cancelled: std::sync::atomic::AtomicBool::new(false),
                incomplete_write: std::sync::atomic::AtomicBool::new(false),
                wake: tokio::sync::Notify::new(),
            })),
        })
    }
    pub fn stop_handle(&self) -> ListenerStop {
        self.stop.clone()
    }
    pub fn accept(&self) -> io::Result<(LocalStream, ())> {
        let (pipe, addr) = self.runtime.block_on(async {
            tokio::select! { biased; _=self.stop.0.cancelled()=>Err(closed()), result=self.listener.accept()=>result }
        })?;
        let stream = LocalStream::new(self.runtime.clone(), pipe);
        let mut connections = self
            .connections
            .lock()
            .map_err(|_| io::Error::other("pipe registry poisoned"))?;
        connections.retain(|connection| connection.strong_count() > 0);
        connections.push(Arc::downgrade(&stream.connection));
        Ok((stream, addr))
    }
    pub fn incoming(&self) -> impl Iterator<Item = io::Result<LocalStream>> + '_ {
        std::iter::from_fn(|| Some(self.accept().map(|(stream, _)| stream)))
    }
}
impl Drop for LocalListener {
    fn drop(&mut self) {
        if let Ok(connections) = self.connections.lock() {
            for connection in connections.iter().filter_map(std::sync::Weak::upgrade) {
                connection.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{CreateWellKnownSid, TOKEN_USER, WinWorldSid};

    #[tokio::test]
    async fn a_busy_pipe_connect_expires_without_waiting_for_the_current_client() {
        let unique = tempfile::tempdir().unwrap();
        let path = pipe_path(&unique.path().to_string_lossy()).unwrap();
        let security = Security::new().unwrap();
        let mut attributes = security.attributes();
        let _server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    &path,
                    (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES)
                        .cast(),
                )
        }
        .unwrap();
        let _client = AsyncStream::connect(&path).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            AsyncStream::connect_timeout(&path, Duration::from_millis(20)),
        )
        .await
        .expect("a busy named pipe must honor its connect deadline");
        let error = match result {
            Ok(_) => panic!("a second client occupied the single busy pipe instance"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn an_accepted_pipe_checks_the_client_token_sid_and_disconnects_a_mismatch() {
        tokio::time::timeout(
            Duration::from_secs(5),
            rejected_client_does_not_block_the_next(),
        )
        .await
        .expect("rejecting a pipe client or accepting its successor stalled");
    }

    async fn rejected_client_does_not_block_the_next() {
        let unique = tempfile::tempdir().unwrap();
        let path = pipe_path(&unique.path().to_string_lossy()).unwrap();
        let mut listener = AsyncListener::bind(&path).unwrap();
        // The object DACL still allows this peer. Inject a different expected user
        // to exercise the independent client-token check rather than CreateFile ACLs.
        let mut foreign_sid = vec![0usize; 16];
        let mut size = std::mem::size_of_val(foreign_sid.as_slice()) as u32;
        super::super::checked(unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                std::ptr::null_mut(),
                foreign_sid.as_mut_ptr().cast(),
                &mut size,
            )
        })
        .unwrap();
        unsafe {
            (*listener.owner.as_mut_ptr().cast::<TOKEN_USER>()).User.Sid =
                foreign_sid.as_mut_ptr().cast();
        }
        let mut client = AsyncStream::connect(&path).await.unwrap();
        let error = match listener.accept().await {
            Ok(_) => panic!("a client with a different SID was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut byte = [0];
        assert!(matches!(client.read(&mut byte).await, Ok(0) | Err(_)));
        // Reconnect before polling accept and while the rejected client is
        // still alive. A disconnected-but-reused instance stays busy here.
        listener.owner = super::super::token_user().unwrap();
        let _client = AsyncStream::connect(&path).await.unwrap();
        let _accepted = listener.accept().await.unwrap();
    }
}
