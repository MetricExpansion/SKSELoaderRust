//! Helper functions that are useful to other crates.

use std::error::Error;
use std::ffi::{c_void, CStr, CString};
use std::intrinsics::copy_nonoverlapping;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};

use scan_fmt::scan_fmt;
use wide_literals::w;
use widestring::{WideCStr, WideCString, WideChar};
use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH};
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS, IMAGE_SNAP_BY_ORDINAL, IMAGE_THUNK_DATA, PAGE_EXECUTE_READWRITE,
};
use winapi::um::winuser::{MessageBoxW, MB_OK};
use winapi::um::winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

/// Searches the IAT for imported functions in a specified DLL.
pub unsafe fn get_iat_addr(
    module: HMODULE,
    search_dll_name: &str,
    search_import_name: &str,
) -> Result<Option<*mut ()>, Box<dyn Error>> {
    let search_import_name = CString::new(search_import_name)?;
    let search_dll_name = CString::new(search_dll_name)?;
    let base = module as usize;
    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_header = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let mut import_table = (base
        + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
    // Loop over available DLLs in the IAT and look for the one we want.
    while *(*import_table).u.Characteristics() != 0 {
        let dll_name = CStr::from_ptr((base + ((*import_table).Name) as usize) as *const c_char);
        if search_dll_name.as_c_str() == dll_name {
            let mut thunk_data = (base + *(*import_table).u.OriginalFirstThunk() as usize)
                as *const IMAGE_THUNK_DATA;
            let mut iat = (base + (*import_table).FirstThunk as usize) as *const usize;
            // Once we have the desired DLL, loop over the imported function entries to find the one we want.
            while *((*thunk_data).u1.Ordinal()) != 0 {
                if !IMAGE_SNAP_BY_ORDINAL(*(*thunk_data).u1.Ordinal()) {
                    let import_info = (base + (*(*thunk_data).u1.AddressOfData() as usize))
                        as *const IMAGE_IMPORT_BY_NAME;
                    let name = CStr::from_ptr((*import_info).Name.as_ptr());
                    if search_import_name.as_c_str() == name {
                        // We found it! Return it.
                        return Ok(Some(iat as *mut ()));
                    }
                }
                // Step to next entry in DLL imports table.
                thunk_data = thunk_data.add(1);
                iat = iat.add(1);
            }
        }
        // Step to next DLL in IAT.
        import_table = import_table.add(1);
    }
    // Didn't find anything :(
    Ok(None)
}

/// A helper function to quickly show a message box. Panics if `msg` cannot be converted to a [CString].
pub fn quick_msg_box(msg: &str) {
    let message = WideCString::from_str(msg).unwrap_or_default();
    let title = w!("Message from Rust");
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
    let version_number = unsafe {
        get_file_version_string(
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

unsafe fn get_file_version_string(info_item: &WideCStr) -> Option<WideCString> {
    let exe_path = {
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
    let version_info = {
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
        let mut ptr: *mut c_void = null_mut();
        let mut size = 0;
        if VerQueryValueW(
            buffer.as_ptr() as *const c_void,
            info_item.as_ptr(),
            &mut ptr,
            &mut size,
        ) == 0
            || ptr.is_null()
        {
            return None;
        };
        let ptr_to_string = ptr as *const WideChar;
        WideCString::from_ptr_with_nul_unchecked(ptr_to_string, size as usize)
    };
    Some(version_info)
}
