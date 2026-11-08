// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Windows user identity, owner-only objects and reparse-safe state files.
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem as nt};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};
pub mod ipc;

fn checked(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "object must be private to the current Windows user and contain no reparse points",
    )
}
pub(crate) fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let value: Vec<_> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn token_user() -> io::Result<Vec<usize>> {
    token_information(TokenUser)
}
fn token_information(class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut token = ptr::null_mut();
    unsafe {
        checked(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), class, ptr::null_mut(), 0, &mut size);
    }
    let mut bytes = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    unsafe {
        checked(GetTokenInformation(
            token.as_raw_handle(),
            class,
            bytes.as_mut_ptr().cast(),
            size,
            &mut size,
        ))?;
    }
    Ok(bytes)
}

fn is_default_owner(owner: PSID) -> io::Result<bool> {
    let token = token_information(TokenOwner)?;
    let expected = unsafe { (*token.as_ptr().cast::<TOKEN_OWNER>()).Owner };
    Ok(!owner.is_null() && unsafe { EqualSid(owner, expected) } != 0)
}

fn handle_information(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    unsafe {
        checked(GetFileInformationByHandle(handle, &mut info))?;
    }
    Ok(info)
}

// ReOpenFile rejects directories even with FILE_FLAG_BACKUP_SEMANTICS. An
// empty native relative name reopens the directory object itself, without
// resolving its pathname or any ancestor a second time.
fn reopen_directory_handle(handle: HANDLE, access: u32, write_through: bool) -> io::Result<File> {
    let original = handle_information(handle)?;
    if original.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || original.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let mut empty = 0u16;
    let name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 2,
        Buffer: &mut empty,
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: handle,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut reopened = ptr::null_mut();
    let mut status = unsafe { std::mem::zeroed() };
    let result = unsafe {
        nt::NtCreateFile(
            &mut reopened,
            access | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nt::FILE_OPEN,
            nt::FILE_DIRECTORY_FILE
                | nt::FILE_SYNCHRONOUS_IO_NONALERT
                | nt::FILE_OPEN_REPARSE_POINT
                | if write_through {
                    nt::FILE_WRITE_THROUGH
                } else {
                    0
                },
            ptr::null(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    let file = unsafe { File::from_raw_handle(reopened) };
    validate_file(&file, false)?;
    let actual = handle_information(reopened)?;
    if actual.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || actual.dwVolumeSerialNumber != original.dwVolumeSerialNumber
        || actual.nFileIndexHigh != original.nFileIndexHigh
        || actual.nFileIndexLow != original.nFileIndexLow
    {
        return Err(denied());
    }
    Ok(file)
}

// Elevated Windows tokens can default to Administrators as an object's owner,
// even when the creating library inherited our user-only DACL. Normalize only
// that token's own default owner to TokenUser, through the same opened object.
// No privileges are enabled and no arbitrary user/group ownership is accepted.
fn set_file_user_owner(handle: HANDLE, sid: PSID) -> io::Result<()> {
    let access = WRITE_OWNER | READ_CONTROL | FILE_READ_ATTRIBUTES;
    let file = if handle_information(handle)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        reopen_directory_handle(handle, access, false)?
    } else {
        let reopened = unsafe {
            ReOpenFile(
                handle,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        if reopened == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        unsafe { File::from_raw_handle(reopened) }
    };
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            sid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}
pub fn user_id() -> io::Result<String> {
    let bytes = token_user()?;
    let user = unsafe { &*bytes.as_ptr().cast::<TOKEN_USER>() };
    let mut text = ptr::null_mut();
    unsafe {
        checked(ConvertSidToStringSidW(user.User.Sid, &mut text))?;
    }
    let allocation = LocalAllocation(text.cast());
    let mut size = 0;
    unsafe {
        while *text.add(size) != 0 {
            size += 1;
        }
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, size) });
    drop(allocation);
    Ok(value)
}
/// A stable local endpoint. Workspace identities are hashed, never interpreted as pipe names.
pub fn pipe_path(workspace: &str) -> io::Result<PathBuf> {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in workspace.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(PathBuf::from(format!(
        r"\\.\pipe\lockyard-{}-{hash:016x}",
        user_id()?
    )))
}
/// Descriptor lifetime must cover the native create call. Inheritance stays owner-only.
pub struct Security {
    allocation: LocalAllocation,
}
impl Security {
    pub fn new() -> io::Result<Self> {
        let sid = user_id()?;
        let sddl = wide(Path::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})")))?;
        let mut descriptor = ptr::null_mut();
        unsafe {
            checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ))?;
        }
        Ok(Self {
            allocation: LocalAllocation(descriptor),
        })
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.allocation.0,
            bInheritHandle: 0,
        }
    }
}
// Native security descriptors are immutable after construction and freed only on drop.
unsafe impl Send for Security {}
unsafe impl Sync for Security {}

// Every component after the volume/share root is opened relative to an already
// opened directory. A concurrent junction replacement therefore cannot cause a
// second lookup of an ancestor pathname. OPEN_REPARSE_POINT applies to the one
// child being opened; its attributes are checked on that same handle.
fn open_relative(
    parent: &File,
    name: &std::ffi::OsStr,
    access: u32,
    disposition: u32,
    options: u32,
    security: Option<&Security>,
    share: u32,
) -> io::Result<File> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(
            path.components().next(),
            Some(std::path::Component::Normal(_))
        )
        || name.to_string_lossy().contains(':')
    {
        return Err(denied());
    }
    let mut name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty() || name.contains(&0) || name.len() > (u16::MAX as usize / 2) {
        return Err(denied());
    }
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.map_or(ptr::null(), |security| security.allocation.0.cast()),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut status = unsafe { std::mem::zeroed() };
    let result = unsafe {
        nt::NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | nt::FILE_SYNCHRONOUS_IO_NONALERT | nt::FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    validate_file(&file, options & nt::FILE_NON_DIRECTORY_FILE != 0)?;
    Ok(file)
}
fn absolute(path: &Path) -> io::Result<PathBuf> {
    let path = std::path::absolute(path)?;
    match path.components().next() {
        Some(std::path::Component::Prefix(prefix))
            if matches!(
                prefix.kind(),
                std::path::Prefix::Disk(_)
                    | std::path::Prefix::VerbatimDisk(_)
                    | std::path::Prefix::UNC(_, _)
                    | std::path::Prefix::VerbatimUNC(_, _)
            ) =>
        {
            Ok(path)
        }
        _ => Err(denied()),
    }
}
fn open_path(
    path: &Path,
    access: u32,
    disposition: u32,
    options: u32,
    security: Option<&Security>,
) -> io::Result<File> {
    let path = absolute(path)?;
    let Some(name) = path.file_name() else {
        return Ok(open_directory_access(&path, false, access)?.file);
    };
    let parent = open_directory_access(
        path.parent().ok_or_else(denied)?,
        false,
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
    )?;
    let file = open_relative(
        &parent,
        name,
        access,
        disposition,
        options,
        security,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    parent.validate_chain()?;
    Ok(file)
}

pub fn reject_reparse(path: &Path) -> io::Result<()> {
    let path = absolute(path)?;
    let mut chain: Vec<_> = path.ancestors().collect();
    chain.reverse();
    let mut held = Vec::new();
    for (index, ancestor) in chain.iter().enumerate() {
        let opened = if index == 0 {
            open_volume_root(ancestor, FILE_READ_ATTRIBUTES)
        } else {
            open_relative(
                held.last().ok_or_else(denied)?,
                ancestor.file_name().ok_or_else(denied)?,
                FILE_READ_ATTRIBUTES,
                nt::FILE_OPEN,
                0,
                None,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )
        };
        match opened {
            Ok(file) => {
                if index + 1 != chain.len() && !file.metadata()?.is_dir() {
                    return Err(denied());
                }
                held.push(file);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
/// Validate the descriptor attached to the opened object, not a second pathname lookup.
fn require_private_handle(handle: HANDLE, kind: SE_OBJECT_TYPE) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            kind,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    let user = token_user()?;
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if owner.is_null() || dacl.is_null() {
        return Err(denied());
    }
    let user_owned = unsafe { EqualSid(owner, sid) } != 0;
    if !user_owned && (kind != SE_FILE_OBJECT || !is_default_owner(owner)?) {
        return Err(denied());
    }
    let acl = unsafe { &*dacl };
    if acl.AceCount == 0 {
        return Err(denied());
    }
    let mut allowed = false;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        unsafe {
            checked(GetAce(dacl, index as u32, &mut ace))?;
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0
        /* ACCESS_ALLOWED_ACE_TYPE */
        {
            return Err(denied());
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if unsafe { EqualSid(ace_sid, sid) } == 0 || ace.Mask != FILE_ALL_ACCESS {
            return Err(denied());
        }
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0 {
            allowed = true;
        }
    }
    if !allowed {
        return Err(denied());
    }
    if !user_owned {
        // Existing private files from SQLite or another native library may
        // carry TokenOwner. Validate every ACE before changing ownership: an
        // exposed file must still be rejected without repairing its ACL.
        set_file_user_owner(handle, sid)?;
    }
    Ok(())
}
fn open_metadata(path: &Path) -> io::Result<File> {
    open_path(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        nt::FILE_OPEN,
        0,
        None,
    )
}
pub fn require_private(path: &Path) -> io::Result<()> {
    require_private_file(&open_metadata(path)?)
}
pub fn require_private_file(file: &File) -> io::Result<()> {
    validate_file(file, false)?;
    require_private_handle(file.as_raw_handle(), SE_FILE_OBJECT)
}
fn validate_file(file: &File, regular: bool) -> io::Result<()> {
    let info = handle_information(file.as_raw_handle())?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || regular
            && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> io::Result<()> {
    create_directory(path, false)
}
fn create_directory(path: &Path, create_new: bool) -> io::Result<()> {
    let path = absolute(path)?;
    let Some(name) = path.file_name() else {
        return if create_new {
            Err(io::Error::from(io::ErrorKind::AlreadyExists))
        } else {
            secure_owned(&path)
        };
    };
    let parent_path = path.parent().ok_or_else(denied)?;
    let parent =
        match open_directory_access(parent_path, false, FILE_READ_ATTRIBUTES | FILE_TRAVERSE) {
            Ok(parent) => parent,
            Err(error) if !create_new && error.kind() == io::ErrorKind::NotFound => {
                private_dir(parent_path)?;
                open_directory_access(parent_path, false, FILE_READ_ATTRIBUTES | FILE_TRAVERSE)?
            }
            Err(error) => return Err(error),
        };
    let security = Security::new()?;
    let file = open_relative(
        &parent,
        name,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        if create_new {
            nt::FILE_CREATE
        } else {
            nt::FILE_OPEN_IF
        },
        nt::FILE_DIRECTORY_FILE,
        Some(&security),
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    parent.validate_chain()?;
    if !file.metadata()?.is_dir() {
        return Err(denied());
    }
    secure_file_owned(&file)
}
/// Owner-only analogue of OpenOptions; rights exist before the first byte is written.
#[derive(Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    create: bool,
    create_new: bool,
    truncate: bool,
}
impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(&mut self, value: bool) -> &mut Self {
        self.read = value;
        self
    }
    pub fn write(&mut self, value: bool) -> &mut Self {
        self.write = value;
        self
    }
    pub fn append(&mut self, value: bool) -> &mut Self {
        self.append = value;
        self
    }
    pub fn create(&mut self, value: bool) -> &mut Self {
        self.create = value;
        self
    }
    pub fn create_new(&mut self, value: bool) -> &mut Self {
        self.create_new = value;
        self
    }
    pub fn truncate(&mut self, value: bool) -> &mut Self {
        self.truncate = value;
        self
    }
    pub fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        self.open_with(path.as_ref(), || {})
    }
    fn open_with(&self, path: &Path, before_leaf: impl FnOnce()) -> io::Result<File> {
        let path = absolute(path)?;
        let parent = open_directory_access(
            path.parent().ok_or_else(denied)?,
            false,
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        )?;
        let security = Security::new()?;
        let disposition = if self.create_new {
            nt::FILE_CREATE
        } else if self.create {
            nt::FILE_OPEN_IF
        } else {
            nt::FILE_OPEN
        };
        let access = READ_CONTROL
            | FILE_READ_ATTRIBUTES
            | if self.read { GENERIC_READ } else { 0 }
            | if self.write && !self.append {
                GENERIC_WRITE
            } else {
                0
            }
            | if self.append { FILE_APPEND_DATA } else { 0 };
        before_leaf();
        parent.validate_chain()?;
        let file = open_relative(
            &parent,
            path.file_name().ok_or_else(denied)?,
            access,
            disposition,
            nt::FILE_NON_DIRECTORY_FILE,
            Some(&security),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        parent.validate_chain()?;
        require_private_file(&file)?;
        // Truncation is handle-based and happens only after owner, ACL and type validation.
        if self.truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }
}
/// Atomic replacement of the opened object in a pinned destination directory.
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    rename_paths(from, to, true, false)
}
fn rename_paths(from: &Path, to: &Path, replace: bool, private: bool) -> io::Result<()> {
    let source = open_path(
        from,
        READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE,
        nt::FILE_OPEN,
        0,
        None,
    )?;
    let is_directory = source.metadata()?.is_dir();
    validate_file(&source, !is_directory)?;
    let to = absolute(to)?;
    // Generic configuration writes also target user-selected readable folders.
    // Files staged by fsio retain private ACLs even when the folder is readable.
    let parent = open_directory_access(
        to.parent().ok_or_else(denied)?,
        private,
        READ_CONTROL
            | FILE_READ_ATTRIBUTES
            | FILE_LIST_DIRECTORY
            | FILE_ADD_FILE
            | FILE_TRAVERSE
            | if is_directory {
                FILE_ADD_SUBDIRECTORY
            } else {
                0
            },
    )?;
    let name = to.file_name().ok_or_else(denied)?;
    if replace {
        match open_relative(
            &parent,
            name,
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            nt::FILE_OPEN,
            0,
            None,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(file) => validate_file(&file, !file.metadata()?.is_dir())?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    if private {
        rename_handle(&source, &parent, name, replace)
    } else {
        rename_opened_handle(&source, &parent, name, replace)
    }
}
/// Tighten an owned directory created by a platform-neutral caller.
pub fn secure_owned(path: &Path) -> io::Result<()> {
    let file = open_path(
        path,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        nt::FILE_OPEN,
        0,
        None,
    )?;
    secure_file_owned(&file)
}
fn secure_file_owned(file: &File) -> io::Result<()> {
    validate_file(file, false)?;
    let handle = file.as_raw_handle();
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let error = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    let user = token_user()?;
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let user_owned = unsafe { EqualSid(owner, sid) } != 0;
    if !user_owned && !is_default_owner(owner)? {
        return Err(denied());
    }
    let security = Security::new()?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    unsafe {
        checked(GetSecurityDescriptorDacl(
            security.allocation.0,
            &mut present,
            &mut dacl,
            &mut defaulted,
        ))?;
    }
    let error = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    if !user_owned {
        // Ownership gives READ_CONTROL and WRITE_DAC, but not WRITE_OWNER.
        // Inherited ACLs on an existing directory can therefore let us tighten
        // its DACL without allowing an owner-changing reopen yet. Install the
        // user-only full-access DACL first, then normalize the validated token
        // default owner through the same object. No broader rights are granted.
        set_file_user_owner(handle, sid)?;
    }
    require_private_file(file)
}
pub fn open_public(path: &Path) -> io::Result<File> {
    open_path(
        path,
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        nt::FILE_OPEN,
        nt::FILE_NON_DIRECTORY_FILE,
        None,
    )
}
pub fn read_public(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_public(path)?;
    if file.metadata()?.len() > limit {
        return Err(io::Error::other("file exceeds limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("file exceeds limit"));
    }
    Ok(bytes)
}
pub fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = OpenOptions::new().read(true).open(path)?;
    if file.metadata()?.len() > limit {
        return Err(io::Error::other("file exceeds limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("file exceeds limit"));
    }
    Ok(bytes)
}
pub fn file_identity(file: &File) -> io::Result<(u32, u64)> {
    let info = handle_information(file.as_raw_handle())?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}
pub fn rename_create_only(from: &Path, to: &Path) -> io::Result<()> {
    rename_paths(from, to, false, true)
}

/// A private directory and the ancestor handles that prevent path redirection.
pub struct Directory {
    file: File,
    _ancestors: Vec<File>,
}
impl std::ops::Deref for Directory {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
impl Directory {
    fn validate_chain(&self) -> io::Result<()> {
        for directory in self._ancestors.iter().chain(std::iter::once(&self.file)) {
            validate_file(directory, false)?;
            if !directory.metadata()?.is_dir() {
                return Err(denied());
            }
        }
        Ok(())
    }
}
pub fn open_directory(path: &Path) -> io::Result<Directory> {
    open_directory_inner(path, true)
}
/// Pin a user-selected output folder; the published payload still has a private ACL.
pub fn open_output_directory(path: &Path) -> io::Result<Directory> {
    open_directory_inner(path, false)
}
fn open_directory_inner(path: &Path, private: bool) -> io::Result<Directory> {
    open_directory_access(
        path,
        private,
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE,
    )
}
/// Check an endpoint state directory without requiring write access to it.
pub fn require_private_directory(path: &Path) -> io::Result<()> {
    open_directory_access(path, true, READ_CONTROL | FILE_READ_ATTRIBUTES).map(|_| ())
}
fn open_volume_root(path: &Path, access: u32) -> io::Result<File> {
    let handle = unsafe {
        CreateFileW(
            wide(path)?.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    validate_file(&file, false)?;
    if !file.metadata()?.is_dir() {
        return Err(denied());
    }
    Ok(file)
}
fn open_directory_access(path: &Path, private: bool, access: u32) -> io::Result<Directory> {
    let path = absolute(path)?;
    let mut chain: Vec<_> = path.ancestors().collect();
    chain.reverse();
    let mut ancestors = Vec::new();
    for (index, ancestor) in chain.iter().enumerate() {
        let leaf = index + 1 == chain.len();
        let rights = if leaf {
            access
        } else {
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE
        };
        let file = if index == 0 {
            open_volume_root(ancestor, rights)?
        } else {
            open_relative(
                ancestors.last().ok_or_else(denied)?,
                ancestor.file_name().ok_or_else(denied)?,
                rights,
                nt::FILE_OPEN,
                0,
                None,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?
        };
        if !file.metadata()?.is_dir() {
            return Err(denied());
        }
        if leaf {
            if private {
                require_private_file(&file)?;
            }
            let directory = Directory {
                file,
                _ancestors: ancestors,
            };
            directory.validate_chain()?;
            return Ok(directory);
        }
        ancestors.push(file);
    }
    Err(denied())
}
/// Refuse DOS aliases and short names by checking the normalized name of the opened object.
pub fn require_final_path(file: &File, expected: &Path) -> io::Result<()> {
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    if !expected.is_absolute() {
        return Err(denied());
    }
    let mut final_name = vec![0u16; 512];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                final_name.as_mut_ptr(),
                final_name.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize >= final_name.len() {
            if length > 32768 {
                return Err(denied());
            }
            final_name.resize(length as usize + 1, 0);
            continue;
        }
        final_name.truncate(length as usize);
        break;
    }
    fn comparable(name: &[u16]) -> Vec<u16> {
        let mut name: Vec<_> = name
            .iter()
            .map(|&unit| {
                if unit == b'/' as u16 {
                    b'\\' as u16
                } else {
                    unit
                }
            })
            .collect();
        let prefix: Vec<_> = r"\\?\UNC\".encode_utf16().collect();
        if name.starts_with(&prefix) {
            name.splice(..prefix.len(), [b'\\' as u16, b'\\' as u16]);
        } else {
            let prefix: Vec<_> = r"\\?\".encode_utf16().collect();
            if name.starts_with(&prefix) {
                name.drain(..prefix.len());
            }
        }
        while name.len() > 3 && name.last() == Some(&(b'\\' as u16)) {
            name.pop();
        }
        name
    }
    let actual = comparable(&final_name);
    let expected: Vec<_> = expected.as_os_str().encode_wide().collect();
    let expected = comparable(&expected);
    if actual.len() > i32::MAX as usize
        || expected.len() > i32::MAX as usize
        || unsafe {
            CompareStringOrdinal(
                actual.as_ptr(),
                actual.len() as i32,
                expected.as_ptr(),
                expected.len() as i32,
                1,
            )
        } != CSTR_EQUAL
    {
        return Err(denied());
    }
    Ok(())
}

/// Prevent an already validated file name being replaced while a library reopens it.
pub fn pin_file(file: &File) -> io::Result<File> {
    require_private_file(file)?;
    // Windows ignores sharing restrictions on metadata-only opens. A data
    // access right makes omission of FILE_SHARE_DELETE actually pin the name.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub fn console_handler(
    handler: unsafe extern "system" fn(u32) -> i32,
    add: bool,
) -> io::Result<()> {
    unsafe {
        checked(windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(handler),
            i32::from(add),
        ))
    }
}

fn reopen_writable(file: &File) -> io::Result<File> {
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { File::from_raw_handle(handle) };
    require_private_file(&result)?;
    Ok(result)
}
pub fn sync_file(file: &File) -> io::Result<()> {
    reopen_writable(file)?.sync_all()
}
pub fn truncate_file(file: &File, length: u64) -> io::Result<()> {
    reopen_writable(file)?.set_len(length)
}
/// Publish the verified source object relative to an opened private directory.
pub fn publish_handle(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    replace: bool,
) -> io::Result<()> {
    require_private_file(parent)?;
    rename_handle(file, parent, name, replace)
}
/// Publish a private object to an explicitly selected, pinned output directory.
pub fn publish_output_handle(
    file: &File,
    parent: &Directory,
    name: &std::ffi::OsStr,
) -> io::Result<()> {
    rename_handle(file, parent, name, false)
}
fn rename_handle(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    replace: bool,
) -> io::Result<()> {
    require_private_file(file)?;
    rename_opened_handle(file, parent, name, replace)?;
    if file.metadata()?.is_dir() {
        Ok(())
    } else {
        sync_file(file)
    }
}
// Generic fsio renames may move ordinary user-owned readable files/directories;
// the private publication entry points validate their stronger policy above.
fn rename_opened_handle(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    replace: bool,
) -> io::Result<()> {
    let is_directory = file.metadata()?.is_dir();
    validate_file(file, !is_directory)?;
    validate_file(parent, false)?;
    if !parent.metadata()?.is_dir() {
        return Err(denied());
    }
    // Obtain any data-flush rights before mutation. A readable/readonly source
    // can still be renamed through DELETE rights, so failure to obtain a write
    // handle must not turn that supported operation into an error after rename.
    let flush = if !is_directory {
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_WRITE_THROUGH,
            )
        };
        (handle != INVALID_HANDLE_VALUE).then(|| unsafe { File::from_raw_handle(handle) })
    } else {
        None
    };
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(
            path.components().next(),
            Some(std::path::Component::Normal(_))
        )
        || name.to_string_lossy().contains(':')
    {
        return Err(denied());
    }
    let name: Vec<u16> = name.encode_wide().collect();
    if name.contains(&0) || name.len() > 255 {
        return Err(denied());
    }
    // Follow the native contract's conservative header-plus-name size; the
    // trailing placeholder/padding is not part of FileNameLength.
    let bytes = size_of::<nt::FILE_RENAME_INFORMATION>() + name.len() * 2;
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<nt::FILE_RENAME_INFORMATION>();
    let access = DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES;
    let renamed = if is_directory {
        reopen_directory_handle(file.as_raw_handle(), access, true)?
    } else {
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_WRITE_THROUGH,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        unsafe { File::from_raw_handle(handle) }
    };
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = (name.len() * 2) as u32;
        ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        // The Win32 FileRenameInfo wrapper rewrites relative names and can
        // reject a non-null RootDirectory with ERROR_INVALID_PARAMETER. Use
        // the native contract matching our NtCreateFile handles and retain
        // the destination directory anchor instead of resolving a full path.
        let mut status = std::mem::zeroed();
        let result = nt::NtSetInformationFile(
            renamed.as_raw_handle(),
            &mut status,
            info.cast(),
            bytes as u32,
            nt::FileRenameInformation,
        );
        if result < 0 {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(result) as i32
            ));
        }
    }
    if let Some(flush) = flush {
        flush.sync_all()?;
    }
    Ok(())
}
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    create_directory(path, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn assert_user_owner(file: &File) {
        let mut owner = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let _descriptor = LocalAllocation(descriptor);
        let user = token_user().unwrap();
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        assert_ne!(
            unsafe { EqualSid(owner, sid) },
            0,
            "owner must be TokenUser"
        );
    }

    fn file_dacl(file: &File) -> (LocalAllocation, *mut ACL) {
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(result, ERROR_SUCCESS, "read the real file's DACL");
        assert!(!dacl.is_null());
        (LocalAllocation(descriptor), dacl)
    }

    fn replace_file_dacl(file: &File, dacl: *mut ACL) -> (LocalAllocation, *mut ACL) {
        // Use a security read/write handle for SetSecurityInfo and readback.
        // A WRITE_DAC-only reopen failed with ERROR_ACCESS_DENIED in native CI.
        // Reopen the same object instead of resolving its pathname again.
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "security reopen: {}",
            io::Error::last_os_error()
        );
        let handle = unsafe { File::from_raw_handle(handle) };
        let result = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, ERROR_SUCCESS, "install the test DACL");
        file_dacl(&handle)
    }

    #[test]
    fn default_owner_is_normalized_only_after_the_private_acl_is_validated() {
        let root = tempfile::tempdir().unwrap();
        // tempfile and SQLite use the process token's default owner, which
        // can be Administrators on an elevated CI runner.
        private_dir(root.path()).unwrap();
        let directory = open_directory(root.path()).unwrap();
        assert_user_owner(&directory);
        let path = root.path().join("native-library-sidecar");
        fs::write(&path, b"native library bytes").unwrap();
        let file = open_metadata(&path).unwrap();
        require_private_file(&file).unwrap();
        assert_user_owner(&file);
        assert_eq!(fs::read(&path).unwrap(), b"native library bytes");

        // The same default owner is insufficient if another user has access.
        let public = root.path().join("exposed");
        fs::write(&public, b"leave exposed bytes alone").unwrap();
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&public)
                .args(["/grant", "*S-1-1-0:R"])
                .status()
                .unwrap()
                .success()
        );
        assert!(require_private(&public).is_err());
        assert_eq!(fs::read(&public).unwrap(), b"leave exposed bytes alone");

        let mut world = vec![0usize; 16];
        let mut size = std::mem::size_of_val(world.as_slice()) as u32;
        checked(unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                ptr::null_mut(),
                world.as_mut_ptr().cast(),
                &mut size,
            )
        })
        .unwrap();
        assert!(!is_default_owner(world.as_mut_ptr().cast()).unwrap());
    }

    #[test]
    fn existing_owner_control_can_tighten_a_directory_before_normalizing_its_owner() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_path(
            root.path(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
            nt::FILE_OPEN,
            0,
            None,
        )
        .unwrap();
        // Reproduce an inherited ACL that allows owner control but does not
        // grant WRITE_OWNER. Elevated Windows tokens can give this directory
        // TokenOwner (Administrators), which must later become TokenUser.
        let security = Security::new().unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        unsafe {
            checked(GetSecurityDescriptorDacl(
                security.allocation.0,
                &mut present,
                &mut dacl,
                &mut defaulted,
            ))
            .unwrap();
            let mut ace = ptr::null_mut();
            checked(GetAce(dacl, 0, &mut ace)).unwrap();
            (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask =
                READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        }
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    directory.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null_mut(),
                )
            },
            0
        );
        let user = token_user().unwrap();
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        assert_eq!(
            set_file_user_owner(directory.as_raw_handle(), sid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied,
            "owner control alone must not imply WRITE_OWNER"
        );
        assert!(require_private_file(&directory).is_err());
        private_dir(root.path()).unwrap();
        require_private_file(&directory).unwrap();
        assert_user_owner(&directory);
        let child = root.path().join("private-child");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&child)
            .unwrap();
        require_private(&child).unwrap();
    }

    #[test]
    fn directory_owner_reopen_keeps_the_original_object_after_its_name_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("original");
        private_dir(&path).unwrap();
        let directory = open_metadata(&path).unwrap();
        let identity = file_identity(&directory).unwrap();
        let moved = root.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("replacement-marker"), b"untouched").unwrap();
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
                .status()
                .unwrap()
                .success()
        );
        assert!(require_private(&path).is_err());
        let replacement = open_metadata(&path).unwrap();
        let reopened = reopen_directory_handle(
            directory.as_raw_handle(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            false,
        )
        .unwrap();
        assert_eq!(file_identity(&reopened).unwrap(), identity);
        assert_ne!(
            file_identity(&reopened).unwrap(),
            file_identity(&replacement).unwrap()
        );
        let user = token_user().unwrap();
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // ReOpenFile(directory) fails even when TokenOwner already is TokenUser.
        // Reopening by pathname would instead act on the replacement directory.
        set_file_user_owner(directory.as_raw_handle(), sid).unwrap();
        assert_eq!(file_identity(&directory).unwrap(), identity);
        assert_user_owner(&directory);
        require_private(&moved).unwrap();
        assert!(require_private(&path).is_err());
        assert_eq!(
            fs::read(path.join("replacement-marker")).unwrap(),
            b"untouched"
        );
    }

    #[test]
    fn relative_publication_preserves_create_only_and_replace_with_short_unicode_names() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        let output = root.path().join("output");
        private_dir(&staging).unwrap();
        private_dir(&output).unwrap();
        let temporary = staging.join("payload");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        file.write_all(b"first").unwrap();
        file.sync_all().unwrap();
        let parent = open_directory(&output).unwrap();
        let name = std::ffi::OsStr::new("я");
        publish_handle(&file, &parent, name, false).unwrap();
        assert!(!temporary.exists());
        assert_eq!(fs::read(output.join(name)).unwrap(), b"first");
        assert_user_owner(&file);
        drop(file);
        let mut next = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        next.write_all(b"second").unwrap();
        next.sync_all().unwrap();
        assert_eq!(
            publish_handle(&next, &parent, name, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(output.join(name)).unwrap(), b"first");
        publish_handle(&next, &parent, name, true).unwrap();
        assert_eq!(fs::read(output.join(name)).unwrap(), b"second");
        assert!(!temporary.exists());
        require_private(&output.join(name)).unwrap();
    }

    #[test]
    fn private_open_pins_ancestors_before_opening_the_leaf() {
        use std::io::{Read, Write};
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("ancestor/private");
        private_dir(&parent).unwrap();
        let path = parent.join("key");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap()
            .write_all(b"original key")
            .unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .open_with(&path, || {
                assert!(
                    fs::rename(root.path().join("ancestor"), root.path().join("redirected"))
                        .is_err(),
                    "an ancestor must stay pinned across the leaf open"
                );
            })
            .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original key");

        // An existing metadata-write handle can mutate a directory in place;
        // denying rename alone is insufficient. No key may be created there.
        let staging = root.path().join("staging");
        let target = root.path().join("target");
        private_dir(&staging).unwrap();
        private_dir(&target).unwrap();
        let attacker = open_path(
            &staging,
            FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
            nt::FILE_OPEN,
            0,
            None,
        )
        .unwrap();
        let target = target.canonicalize().unwrap();
        let target: Vec<_> = target.as_os_str().encode_wide().collect();
        let mut substitute: Vec<_> = r"\??\".encode_utf16().collect();
        substitute.extend_from_slice(target.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&target));
        let length = (substitute.len() * 2) as u16;
        let mut reparse = Vec::new();
        reparse.extend_from_slice(
            &windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes(),
        );
        reparse.extend_from_slice(&(12 + length).to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&length.to_le_bytes());
        reparse.extend_from_slice(&(length + 2).to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        for unit in substitute.into_iter().chain([0, 0]) {
            reparse.extend_from_slice(&unit.to_le_bytes());
        }
        let result =
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open_with(&staging.join("key"), || {
                    let mut returned = 0;
                    unsafe {
                        checked(windows_sys::Win32::System::IO::DeviceIoControl(
                            attacker.as_raw_handle(),
                            windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT,
                            reparse.as_ptr().cast(),
                            reparse.len() as u32,
                            ptr::null_mut(),
                            0,
                            &mut returned,
                            ptr::null_mut(),
                        ))
                        .unwrap();
                    }
                });
        assert!(
            result.is_err(),
            "a mutated pinned parent must be refused before staging a key"
        );
        assert!(
            !staging.join("key").exists(),
            "the junction target must remain untouched"
        );
        drop(attacker);
        fs::remove_dir(staging).unwrap();
    }

    #[test]
    fn owner_allow_ace_with_incomplete_mask_is_refused() {
        let root = tempfile::tempdir().unwrap();
        private_dir(root.path()).unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.path().join("key"))
            .unwrap();
        let security = Security::new().unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        unsafe {
            checked(GetSecurityDescriptorDacl(
                security.allocation.0,
                &mut present,
                &mut dacl,
                &mut defaulted,
            ))
            .unwrap();
            let mut ace = ptr::null_mut();
            checked(GetAce(dacl, 0, &mut ace)).unwrap();
            (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask = READ_CONTROL;
        }
        let (_actual_descriptor, actual_dacl) = replace_file_dacl(&file, dacl);
        assert_user_owner(&file);
        assert_eq!(unsafe { (*actual_dacl).AceCount }, 1);
        let mut ace = ptr::null_mut();
        unsafe {
            checked(GetAce(actual_dacl, 0, &mut ace)).unwrap();
        }
        assert_eq!(
            unsafe { (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask },
            READ_CONTROL,
            "the real file must retain the intentionally incomplete owner mask"
        );
        assert_eq!(
            require_private_file(&file).unwrap_err().to_string(),
            denied().to_string(),
            "owner SID alone cannot make an incomplete ACL acceptable"
        );
    }

    #[test]
    fn final_handle_path_rejects_an_alternate_expected_name() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        private_dir(&canonical).unwrap();
        let directory = open_directory(&canonical).unwrap();
        require_final_path(&directory, &canonical).unwrap();
        assert!(require_final_path(&directory, &canonical.join("alias")).is_err());
    }

    #[test]
    fn replacing_configuration_in_a_readable_workspace_preserves_private_output() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        private_dir(&workspace).unwrap();
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&workspace)
                .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
                .status()
                .unwrap()
                .success()
        );
        assert!(require_private_directory(&workspace).is_err());
        let config = workspace.join(".mcp.json");
        fs::write(&config, b"old readable configuration").unwrap();
        assert!(require_private(&config).is_err());
        crate::fsio::replace(&config, b"new private configuration", 0o600).unwrap();
        require_private(&config).unwrap();
        assert_eq!(fs::read(&config).unwrap(), b"new private configuration");
        let instructions = workspace.join("AGENTS.md");
        crate::fsio::replace(&instructions, b"instructions", 0o600).unwrap();
        require_private(&instructions).unwrap();
        let target = root.path().join("target");
        private_dir(&target).unwrap();
        let junction = workspace.join("junction");
        assert!(
            std::process::Command::new("cmd.exe")
                .args(["/c", "mklink", "/J"])
                .arg(&junction)
                .arg(&target)
                .status()
                .unwrap()
                .success()
        );
        assert!(crate::fsio::replace(&junction, b"refused", 0o600).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_dir(junction).unwrap();
    }

    #[test]
    fn generic_rename_moves_readable_directories_and_files_by_handle() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        private_dir(&workspace).unwrap();
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&workspace)
                .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
                .status()
                .unwrap()
                .success()
        );
        let source = workspace.join("source");
        let destination = workspace.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("readable"), b"payload").unwrap();
        assert!(require_private_directory(&source).is_err());
        crate::fsio::rename(&source, &destination).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(destination.join("readable")).unwrap(), b"payload");
        crate::fsio::rename(destination.join("readable"), workspace.join("renamed")).unwrap();
        assert_eq!(fs::read(workspace.join("renamed")).unwrap(), b"payload");
    }

    #[test]
    fn foreign_sid_has_no_access_and_a_foreign_allow_ace_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        private_dir(directory.path()).unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.path().join("state"))
            .unwrap();
        let (_descriptor, dacl) = file_dacl(&file);
        let mut guest = ptr::null_mut();
        unsafe {
            checked(ConvertStringSidToSidW(
                wide(Path::new("S-1-5-32-546")).unwrap().as_ptr(),
                &mut guest,
            ))
            .unwrap();
        }
        let _guest = LocalAllocation(guest);
        let mut trustee = unsafe { std::mem::zeroed::<TRUSTEE_W>() };
        unsafe {
            BuildTrusteeWithSidW(&mut trustee, guest);
        }
        let mut rights = 0;
        assert_eq!(
            unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) },
            0
        );
        assert_eq!(
            rights, 0,
            "foreign SID must have no rights on the real file"
        );
        let sddl = wide(Path::new(&format!(
            "O:{}D:P(A;;FA;;;{})(A;;FR;;;S-1-5-32-546)",
            user_id().unwrap(),
            user_id().unwrap()
        )))
        .unwrap();
        let mut broadened = ptr::null_mut();
        unsafe {
            checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut broadened,
                ptr::null_mut(),
            ))
            .unwrap();
        }
        let _broadened = LocalAllocation(broadened);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        unsafe {
            checked(GetSecurityDescriptorDacl(
                broadened,
                &mut present,
                &mut dacl,
                &mut defaulted,
            ))
            .unwrap();
        }
        let (_actual_descriptor, actual_dacl) = replace_file_dacl(&file, dacl);
        assert_user_owner(&file);
        assert_eq!(
            unsafe { GetEffectiveRightsFromAclW(actual_dacl, &trustee, &mut rights) },
            ERROR_SUCCESS
        );
        assert_ne!(
            rights & FILE_READ_DATA,
            0,
            "the real file must contain the intentionally added foreign read grant"
        );
        assert_eq!(
            require_private_file(&file).unwrap_err().to_string(),
            denied().to_string(),
            "a foreign allow ACE must be refused by ACL validation"
        );
    }
}
