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
            let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut task) };
            if kr != KERN_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("task_for_pid({pid}) failed (kr={kr}); needs root or entitlement"),
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
                .or_else(|_| File::open(format!("/proc/{pid}/mem")))?;
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

// ============================ other platforms ==============================
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
    fn lists_regions() {
        let h = ProcessHandle::open_self().unwrap();
        let regions = h.regions().expect("regions");
        assert!(!regions.is_empty(), "expected at least one mapped region");
        // our own marker address should fall inside some readable region
        assert!(regions.iter().any(|r| r.readable));
    }
}
