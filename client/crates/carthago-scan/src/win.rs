//! Thin Windows helpers shared by the scanners. Reads of foreign memory go through
//! `ReadProcessMemory` on our own process, so a region freed mid-scan returns an error
//! instead of faulting the game. Module names come from psapi's remote-read path, which
//! does not take the loader lock.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetMappedFileNameW, K32GetModuleBaseNameW, K32GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::pe::Reader;

pub const GENERIC_READ: u32 = 0x8000_0000;

windows_link::link!("ntdll.dll" "system" fn NtGetNextThread(process : HANDLE, thread : HANDLE, access : u32, attributes : u32, flags : u32, new_thread : *mut HANDLE) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtGetNextProcess(process : HANDLE, access : u32, attributes : u32, flags : u32, new_process : *mut HANDLE) -> NTSTATUS);

pub fn query(addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let n = unsafe { VirtualQuery(addr as *const c_void, &mut m, size_of::<MEMORY_BASIC_INFORMATION>()) };
    (n != 0).then_some(m)
}

pub fn is_exec(protect: u32) -> bool {
    protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

pub fn is_writable(protect: u32) -> bool {
    protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

pub fn is_readable(protect: u32) -> bool {
    protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        && protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

/// Copies our own memory without risking an access violation.
pub fn read_self(addr: usize, buf: &mut [u8]) -> bool {
    let mut n = 0usize;
    let ok = unsafe { ReadProcessMemory(GetCurrentProcess(), addr as *const c_void, buf.as_mut_ptr().cast(), buf.len(), &mut n) };
    ok != 0 && n == buf.len()
}

pub fn read_ptr(addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    read_self(addr as usize, &mut b).then(|| u64::from_le_bytes(b))
}

/// A mapped image in our process, addressed by RVA.
pub struct Mapped(pub usize);

impl Reader for Mapped {
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        read_self(self.0.wrapping_add(off as usize), buf)
    }
}

/// Loader-list module handles (bases).
pub fn modules(out: &mut Vec<usize>) {
    let mut buf: Vec<HMODULE> = vec![std::ptr::null_mut(); 512];
    loop {
        let mut needed = 0u32;
        let ok = unsafe {
            K32EnumProcessModulesEx(GetCurrentProcess(), buf.as_mut_ptr(), (buf.len() * size_of::<HMODULE>()) as u32, &mut needed, LIST_MODULES_ALL)
        };
        let n = needed as usize / size_of::<HMODULE>();
        if ok == 0 || n <= buf.len() {
            out.clear();
            if ok != 0 {
                out.extend(buf[..n].iter().map(|&h| h as usize));
            }
            return;
        }
        buf.resize(n, std::ptr::null_mut());
    }
}

fn utf16(buf: &[u16], n: u32) -> Option<String> {
    (n != 0).then(|| String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())]))
}

pub fn module_base_name(base: usize) -> Option<String> {
    let mut buf = [0u16; 128];
    let n = unsafe { K32GetModuleBaseNameW(GetCurrentProcess(), base as HMODULE, buf.as_mut_ptr(), buf.len() as u32) };
    utf16(&buf, n)
}

pub fn module_path(base: usize) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let n = unsafe { K32GetModuleFileNameExW(GetCurrentProcess(), base as HMODULE, buf.as_mut_ptr(), buf.len() as u32) };
    utf16(&buf, n)
}

/// NT device path of the file mapped at `addr` (`\Device\HarddiskVolume3\...`).
pub fn mapped_file(addr: usize) -> Option<Vec<u16>> {
    let mut buf = vec![0u16; 1024];
    let n = unsafe { K32GetMappedFileNameW(GetCurrentProcess(), addr as *const c_void, buf.as_mut_ptr(), buf.len() as u32) };
    (n != 0).then(|| {
        buf.truncate(n as usize);
        buf
    })
}

pub fn mapped_file_base_name(addr: usize) -> String {
    mapped_file(addr).map(|w| crate::paths::base_name(&String::from_utf16_lossy(&w)).to_owned()).unwrap_or_default()
}

/// Base name of the image a code address belongs to; empty when it is not image-backed.
pub fn owner_module_name(addr: u64) -> String {
    match query(addr as usize) {
        Some(m) if m.Type == windows_sys::Win32::System::Memory::MEM_IMAGE => {
            module_base_name(m.AllocationBase as usize).unwrap_or_else(|| mapped_file_base_name(m.AllocationBase as usize))
        }
        _ => String::new(),
    }
}

/// Image base name of another process (`PROCESS_QUERY_LIMITED_INFORMATION`).
pub fn process_image_name(pid: u32) -> String {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return String::new();
    }
    let name = process_image_name_of(h);
    unsafe { CloseHandle(h) };
    name
}

pub(crate) fn process_image_name_of(h: HANDLE) -> String {
    let mut buf = vec![0u16; 1024];
    let mut n = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } == 0 {
        return String::new();
    }
    crate::paths::base_name(&String::from_utf16_lossy(&buf[..n as usize])).to_owned()
}

/// Read-only file handle for positioned reads (`pe::Reader`).
pub struct File(HANDLE);

// SAFETY: the handle is owned and only used for synchronous positioned reads.
unsafe impl Send for File {}

impl File {
    /// Opens a file by NT device path through the `\\?\GLOBALROOT` namespace.
    pub fn open_nt(nt_path: &[u16]) -> Option<Self> {
        let mut w: Vec<u16> = r"\\?\GLOBALROOT".encode_utf16().collect();
        w.extend_from_slice(nt_path);
        Self::open_wide(w)
    }

    pub fn open(path: &str) -> Option<Self> {
        Self::open_wide(path.encode_utf16().collect())
    }

    fn open_wide(mut w: Vec<u16>) -> Option<Self> {
        w.push(0);
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(Self(h))
    }
}

impl Reader for File {
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.Anonymous.Anonymous.Offset = off as u32;
        ov.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
        let mut n = 0u32;
        let ok = unsafe { ReadFile(self.0, buf.as_mut_ptr(), buf.len() as u32, &mut n, &mut ov) };
        ok != 0 && n as usize == buf.len()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Owned kernel handle, closed on drop.
pub struct Owned(pub HANDLE);

impl Owned {
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: process and thread handles may be used and closed from any thread.
unsafe impl Send for Owned {}

/// Opens the on-disk file of a loaded module: the mapped-file name (no loader lock), then
/// the loader path as a fallback.
pub fn open_module_file(base: usize) -> Option<File> {
    mapped_file(base).and_then(|nt| File::open_nt(&nt)).or_else(|| module_path(base).and_then(|p| File::open(&p)))
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
