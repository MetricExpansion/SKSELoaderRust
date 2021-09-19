//! Helper functions that are useful to other crates.

use std::ffi::c_void;
use std::intrinsics::copy_nonoverlapping;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};

use scan_fmt::scan_fmt;
use wide_literals::w;
use widestring::{WideCStr, WideCString, WideChar};
use winapi::shared::minwindef::{DWORD, MAX_PATH};
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winuser::{MessageBoxW, MB_OK};
use winapi::um::winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

/// A helper function to quickly show a message box. Panics if `msg` cannot be converted to a [CString].
pub fn quick_msg_box(msg: &str) {
    let message = WideCString::from_str(msg).unwrap_or_default();
    let title = w!("SKSE Loader");
    unsafe {
        MessageBoxW(null_mut(), message.as_ptr(), title, MB_OK);
    }
}

/// A helper function similar to [copy_nonoverlapping] (in fact, wrapping that function), which allows writing to executable pages.
pub unsafe fn write_protected_buffer(addr: *mut c_void, data: *const c_void, length: usize) {
    let mut old_protect = 0;
    VirtualProtect(
        addr,
        length,
        PAGE_EXECUTE_READWRITE,
        (&mut old_protect) as _,
    );
    copy_nonoverlapping(data, addr, length);
    VirtualProtect(addr, length, old_protect, (&mut old_protect) as _);
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SkyrimVersionInfo {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

pub fn identify_skyrim_version() -> Option<SkyrimVersionInfo> {
    // let exe_name = unsafe { get_file_version_string(&WideCString::from_str("\\StringFileInfo\\040904B0\\ProductName").unwrap()) }?.to_string_lossy();
    let version_info = FileVersionInfo::for_current_module()?;
    let version_number = unsafe {
        version_info.get_info_item_string(
            &WideCString::from_str("\\StringFileInfo\\040904B0\\ProductVersion").unwrap(),
        )
    }?
    .to_string_lossy();
    let (major, minor, patch, _) =
        scan_fmt!(&version_number, "{}.{}.{}.{}", u32, u32, u32, u32).ok()?;
    Some(SkyrimVersionInfo {
        major,
        minor,
        patch,
    })
}

struct FileVersionInfo {
    buffer: Vec<c_char>,
}

impl FileVersionInfo {
    fn for_current_module() -> Option<FileVersionInfo> {
        let exe_path = unsafe {
            let mut buffer = vec![0; MAX_PATH];
            if GetModuleFileNameW(
                GetModuleHandleW(null()),
                buffer.as_mut_ptr(),
                buffer.len() as DWORD,
            ) == 0
            {
                return None;
            };
            WideCString::from_vec_with_nul_unchecked(buffer)
        };
        let version_info = unsafe {
            let mut size = 0;
            let size = GetFileVersionInfoSizeW(exe_path.as_ptr(), &mut size);
            let mut buffer = vec![0 as c_char; size as usize];
            if GetFileVersionInfoW(
                exe_path.as_ptr(),
                0,
                buffer.len() as DWORD,
                buffer.as_mut_ptr() as *mut c_void,
            ) == 0
            {
                return None;
            };
            buffer
        };
        Some(FileVersionInfo {
            buffer: version_info,
        })
    }

    unsafe fn get_info_item_string(&self, info_item: &WideCStr) -> Option<WideCString> {
        let mut ptr: *mut c_void = null_mut();
        let mut size = 0;
        if VerQueryValueW(
            self.buffer.as_ptr() as *const c_void,
            info_item.as_ptr(),
            &mut ptr,
            &mut size,
        ) == 0
            || ptr.is_null()
        {
            return None;
        };
        let ptr_to_string = ptr as *const WideChar;
        Some(WideCString::from_ptr_with_nul_unchecked(
            ptr_to_string,
            size as usize,
        ))
    }
}
