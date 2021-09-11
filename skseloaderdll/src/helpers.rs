//! Helper functions that are useful to other crates.

use std::error::Error;
use std::ffi::{c_void, CStr, CString};
use std::intrinsics::copy_nonoverlapping;
use std::os::raw::c_char;
use std::ptr::null_mut;

use winapi::shared::minwindef::HMODULE;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS, IMAGE_SNAP_BY_ORDINAL, IMAGE_THUNK_DATA, PAGE_EXECUTE_READWRITE,
};
use winapi::um::winuser::{MessageBoxA, MB_OK};

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
    let message = CString::new(msg).unwrap();
    let title = CString::new("Message from Rust").unwrap();
    unsafe {
        MessageBoxA(null_mut(), message.as_ptr(), title.as_ptr(), MB_OK);
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
