//! Live process memory access.
//!
//! [`ProcessHandle`] reads and writes another process's address space and lists
//! its mapped regions; [`ProcessSource`] exposes a chosen region as a live
//! [`DataSource`] so the whole editor (view, scanner, inspector, templates,
//! disassembly) works directly on running memory.
//!
//! Backends: macOS (Mach VM), Linux (`/proc/<pid>/mem` + `maps`). Reading or
//! writing another process generally needs elevated privileges (root, or
//! `task_for_pid`/`ptrace` permission); reading *our own* process never does,
//! which is what the unit tests exercise.

use std::io;

use super::source::DataSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MemRegion {
    pub fn end(&self) -> u64 {
        self.base + self.size
    }
}

/// True if the editor is running with elevated privileges (root / Administrator).
/// Touching *another* process's memory generally requires this.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = core::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation: TOKEN_ELEVATION = core::mem::zeroed();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        false
    }
}

/// Platform-specific, human-readable guidance for gaining the privilege needed
/// to read/write another process's memory.
pub fn privilege_note() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macOS: run bewitched as root (sudo), or code-sign it with the \
         com.apple.security.cs.debugger / get-task-allow entitlement. \
         System Integrity Protection blocks Apple/system processes regardless."
    }
    #[cfg(target_os = "linux")]
    {
        "Linux: run bewitched as root (sudo), or grant CAP_SYS_PTRACE / set \
         /proc/sys/kernel/yama/ptrace_scope=0 for non-root attaching."
    }
    #[cfg(target_os = "windows")]
    {
        "Windows: run bewitched as Administrator (SeDebugPrivilege) to open other \
         processes."
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "Reading another process's memory requires elevated privileges."
    }
}

/// Process id of the editor itself — always openable without privileges.
pub fn own_pid() -> u32 {
    std::process::id()
}

// =============================== macOS =====================================
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::port::mach_port_t;
    use mach2::traps::{mach_task_self, task_for_pid};
    use mach2::vm::{mach_vm_read_overwrite, mach_vm_region, mach_vm_write};
    use mach2::vm_region::{vm_region_basic_info_64, VM_REGION_BASIC_INFO_64};
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

    pub struct ProcessHandle {
        task: mach_port_t,
    }

    impl ProcessHandle {
        pub fn open_self() -> io::Result<Self> {
            Ok(Self {
                task: unsafe { mach_task_self() },
            })
        }

        pub fn open(pid: u32) -> io::Result<Self> {
            let mut task: mach_port_t = 0;
            if pid == super::own_pid() {
                return Self::open_self();
            }
            let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut task) };
            if kr != KERN_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "task_for_pid({pid}) failed (kr={kr}) — administrator/root required. {}",
                        super::privilege_note()
                    ),
                ));
            }
            Ok(Self { task })
        }

        pub fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut out: mach_vm_size_t = 0;
            let kr = unsafe {
                mach_vm_read_overwrite(
                    self.task,
                    addr as mach_vm_address_t,
                    buf.len() as mach_vm_size_t,
                    buf.as_mut_ptr() as mach_vm_address_t,
                    &mut out,
                )
            };
            if kr != KERN_SUCCESS {
                return Err(io::Error::other(format!(
                    "mach_vm_read_overwrite @ {addr:#x} failed (kr={kr})"
                )));
            }
            Ok(out as usize)
        }

        pub fn write(&self, addr: u64, data: &[u8]) -> io::Result<usize> {
            if data.is_empty() {
                return Ok(0);
            }
            let kr = unsafe {
                mach_vm_write(
                    self.task,
                    addr as mach_vm_address_t,
                    data.as_ptr() as mach2::vm_types::vm_offset_t,
                    data.len() as u32,
                )
            };
            if kr != KERN_SUCCESS {
                return Err(io::Error::other(format!(
                    "mach_vm_write @ {addr:#x} failed (kr={kr})"
                )));
            }
            Ok(data.len())
        }

        pub fn regions(&self) -> io::Result<Vec<MemRegion>> {
            let mut out = Vec::new();
            let mut addr: mach_vm_address_t = 0;
            loop {
                let mut size: mach_vm_size_t = 0;
                let mut info: vm_region_basic_info_64 = unsafe { std::mem::zeroed() };
                // VM_REGION_BASIC_INFO_COUNT_64 = sizeof(info) / sizeof(int)
                let mut count: u32 =
                    (std::mem::size_of::<vm_region_basic_info_64>() / std::mem::size_of::<i32>())
                        as u32;
                let mut object: mach_port_t = 0;
                let kr = unsafe {
                    mach_vm_region(
                        self.task,
                        &mut addr,
                        &mut size,
                        VM_REGION_BASIC_INFO_64,
                        &mut info as *mut _ as *mut i32,
                        &mut count,
                        &mut object,
                    )
                };
                if kr != KERN_SUCCESS {
                    break;
                }
                let prot = info.protection;
                out.push(MemRegion {
                    base: addr,
                    size,
                    readable: prot & mach2::vm_prot::VM_PROT_READ != 0,
                    writable: prot & mach2::vm_prot::VM_PROT_WRITE != 0,
                    executable: prot & mach2::vm_prot::VM_PROT_EXECUTE != 0,
                });
                addr += size;
                if out.len() > 100_000 {
                    break;
                }
            }
            Ok(out)
        }
    }
}

// =============================== Linux =====================================
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::FileExt;

    pub struct ProcessHandle {
        pid: u32,
        mem: File,
    }

    impl ProcessHandle {
        pub fn open_self() -> io::Result<Self> {
            Self::open(std::process::id())
        }

        pub fn open(pid: u32) -> io::Result<Self> {
            let mem = OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{pid}/mem"))
                .or_else(|_| File::open(format!("/proc/{pid}/mem")))
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::PermissionDenied && pid != super::own_pid() {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "cannot open /proc/{pid}/mem — administrator/root required. {}",
                                super::privilege_note()
                            ),
                        )
                    } else {
                        e
                    }
                })?;
            Ok(Self { pid, mem })
        }

        pub fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.mem.read_at(buf, addr)
        }

        pub fn write(&self, addr: u64, data: &[u8]) -> io::Result<usize> {
            self.mem.write_at(data, addr)
        }

        pub fn regions(&self) -> io::Result<Vec<MemRegion>> {
            let mut maps = String::new();
            File::open(format!("/proc/{}/maps", self.pid))?.read_to_string(&mut maps)?;
            let mut out = Vec::new();
            for line in maps.lines() {
                // format: start-end perms offset dev inode pathname
                let mut it = line.split_whitespace();
                let Some(range) = it.next() else { continue };
                let Some(perms) = it.next() else { continue };
                let mut rr = range.split('-');
                let (Some(a), Some(b)) = (rr.next(), rr.next()) else { continue };
                let (Ok(base), Ok(end)) =
                    (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
                else {
                    continue;
                };
                let p = perms.as_bytes();
                out.push(MemRegion {
                    base,
                    size: end - base,
                    readable: p.first() == Some(&b'r'),
                    writable: p.get(1) == Some(&b'w'),
                    executable: p.get(2) == Some(&b'x'),
                });
            }
            Ok(out)
        }
    }
}

// =============================== Windows ===================================
#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use core::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ReadProcessMemory, WriteProcessMemory,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    pub struct ProcessHandle {
        handle: HANDLE,
        own: bool,
    }

    // A process HANDLE is a kernel handle valid across our threads.
    unsafe impl Send for ProcessHandle {}
    unsafe impl Sync for ProcessHandle {}

    impl ProcessHandle {
        pub fn open_self() -> io::Result<Self> {
            Ok(Self {
                handle: unsafe { GetCurrentProcess() },
                own: true,
            })
        }

        pub fn open(pid: u32) -> io::Result<Self> {
            if pid == super::own_pid() {
                return Self::open_self();
            }
            let access =
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
            let handle = unsafe { OpenProcess(access, FALSE, pid) };
            if handle.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "OpenProcess({pid}) failed — administrator required. {}",
                        super::privilege_note()
                    ),
                ));
            }
            Ok(Self { handle, own: false })
        }

        pub fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    self.handle,
                    addr as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    &mut read,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(read)
        }

        pub fn write(&self, addr: u64, data: &[u8]) -> io::Result<usize> {
            if data.is_empty() {
                return Ok(0);
            }
            let mut wrote: usize = 0;
            let ok = unsafe {
                WriteProcessMemory(
                    self.handle,
                    addr as *mut c_void,
                    data.as_ptr() as *const c_void,
                    data.len(),
                    &mut wrote,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(wrote)
        }

        pub fn regions(&self) -> io::Result<Vec<MemRegion>> {
            let mut out = Vec::new();
            let mut addr: u64 = 0;
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
                let got = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        addr as *const c_void,
                        &mut mbi,
                        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if got == 0 {
                    break;
                }
                let base = mbi.BaseAddress as u64;
                let size = mbi.RegionSize as u64;
                if mbi.State == MEM_COMMIT {
                    let p = mbi.Protect;
                    let readable = matches!(
                        p,
                        PAGE_READONLY
                            | PAGE_READWRITE
                            | PAGE_WRITECOPY
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                    );
                    let writable = matches!(
                        p,
                        PAGE_READWRITE
                            | PAGE_WRITECOPY
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                    );
                    let executable = matches!(
                        p,
                        PAGE_EXECUTE
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                    );
                    out.push(MemRegion {
                        base,
                        size,
                        readable,
                        writable,
                        executable,
                    });
                }
                addr = base.saturating_add(size);
                if size == 0 || out.len() > 1_000_000 {
                    break;
                }
            }
            Ok(out)
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.own && !self.handle.is_null() {
                unsafe { CloseHandle(self.handle) };
            }
        }
    }
}

// ============================ other platforms ==============================
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::*;

    pub struct ProcessHandle;

    impl ProcessHandle {
        pub fn open_self() -> io::Result<Self> {
            Err(unsupported())
        }
        pub fn open(_pid: u32) -> io::Result<Self> {
            Err(unsupported())
        }
        pub fn read(&self, _addr: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Err(unsupported())
        }
        pub fn write(&self, _addr: u64, _data: &[u8]) -> io::Result<usize> {
            Err(unsupported())
        }
        pub fn regions(&self) -> io::Result<Vec<MemRegion>> {
            Err(unsupported())
        }
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "live process memory is not implemented on this platform yet",
        )
    }
}

pub use imp::ProcessHandle;

/// A live, region-bounded view of a process's memory as a [`DataSource`].
pub struct ProcessSource {
    handle: std::sync::Arc<ProcessHandle>,
    base: u64,
    len: u64,
    label: String,
}

impl ProcessSource {
    pub fn new(handle: std::sync::Arc<ProcessHandle>, base: u64, len: u64, label: impl Into<String>) -> Self {
        Self {
            handle,
            base,
            len,
            label: label.into(),
        }
    }

    pub fn handle(&self) -> &std::sync::Arc<ProcessHandle> {
        &self.handle
    }

    pub fn base(&self) -> u64 {
        self.base
    }
}

impl DataSource for ProcessSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.len || buf.is_empty() {
            return 0;
        }
        let want = buf.len().min((self.len - offset) as usize);
        self.handle
            .read(self.base + offset, &mut buf[..want])
            .unwrap_or(0)
    }

    fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn reads_own_memory() {
        let marker: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        let h = ProcessHandle::open_self().expect("open self");
        let addr = marker.as_ptr() as u64;
        let mut buf = [0u8; 8];
        let n = h.read(addr, &mut buf).expect("read self");
        assert_eq!(n, 8);
        assert_eq!(buf, marker);
        // keep `marker` alive until after the read
        std::hint::black_box(&marker);
    }

    #[test]
    fn writes_own_memory() {
        let mut target: [u8; 4] = [0, 0, 0, 0];
        let h = ProcessHandle::open_self().expect("open self");
        let addr = target.as_mut_ptr() as u64;
        h.write(addr, &[1, 2, 3, 4]).expect("write self");
        assert_eq!(target, [1, 2, 3, 4]);
    }

    #[test]
    fn process_source_reads_region() {
        let marker: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x00,
        ];
        let h = Arc::new(ProcessHandle::open_self().unwrap());
        let src = ProcessSource::new(h, marker.as_ptr() as u64, 16, "self");
        assert_eq!(DataSource::len(&src), 16);
        let mut got = [0u8; 4];
        let n = src.read_at(4, &mut got);
        assert_eq!(n, 4);
        assert_eq!(got, marker[4..8]);
        std::hint::black_box(&marker);
    }

    #[test]
    fn write_through_visible_via_source() {
        // simulate the live-edit loop: a ProcessSource over our own buffer, then
        // poke a byte via the handle and read it back through the source.
        let mut target: [u8; 8] = [0; 8];
        let h = Arc::new(ProcessHandle::open_self().unwrap());
        let addr = target.as_mut_ptr() as u64;
        let src = ProcessSource::new(h.clone(), addr, 8, "self");
        h.write(addr + 3, &[0xAB]).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(src.read_at(3, &mut buf), 1);
        assert_eq!(buf[0], 0xAB);
        assert_eq!(target[3], 0xAB);
    }

    #[test]
    fn privilege_helpers() {
        // own PID always opens without privileges, regardless of elevation
        assert!(ProcessHandle::open(own_pid()).is_ok());
        // guidance is non-empty and mentions elevation
        let note = privilege_note().to_lowercase();
        assert!(note.contains("root") || note.contains("administrator"));
        // is_elevated returns without panicking (value depends on how tests run)
        let _ = is_elevated();
    }

    #[test]
    fn lists_regions() {
        let h = ProcessHandle::open_self().unwrap();
        let regions = h.regions().expect("regions");
        assert!(!regions.is_empty(), "expected at least one mapped region");
        // our own marker address should fall inside some readable region
        assert!(regions.iter().any(|r| r.readable));
    }
}
