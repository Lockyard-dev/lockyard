// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::sandbox::syscall;
use super::*;
pub(super) fn install() -> Result<()> {
    // Classic BPF: reject foreign syscall ABI and x32 before syscall number matching.
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("native seccomp requires an explicitly supported syscall ABI");
    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x15,
            jt,
            jf,
            k,
        }
    }
    let mut filter = vec![
        statement(0x20, 4),
        jump(ARCH, 1, 0),
        statement(0x06, 0x80000000),
        statement(0x20, 0),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        statement(0x06, 0x80000000),
    ];
    for number in [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_open_by_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ] {
        filter.extend([
            jump(number as u32, 0, 1),
            statement(0x06, 0x00050000 | libc::EPERM as u32),
        ]);
    }
    filter.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        statement(0x06, 0x00050000 | libc::ENOSYS as u32),
    ]);
    filter.extend([
        jump(libc::SYS_clone as u32, 0, 3),
        statement(0x20, 16),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWCGROUP) as u32,
        },
        statement(0x06, 0x00050000 | libc::EPERM as u32),
        statement(0x06, 0x7fff0000),
    ]);
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    syscall(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
        .map_err(|_| ExecutorError("native_no_new_privileges_unavailable"))?;
    syscall(unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) })
        .map_err(|_| ExecutorError("native_seccomp_unavailable"))
}
