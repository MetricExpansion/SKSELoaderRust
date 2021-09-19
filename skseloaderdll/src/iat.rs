//! Tools to help extract information from the Windows IAT.

use std::error::Error;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS, IMAGE_SNAP_BY_ORDINAL, IMAGE_THUNK_DATA,
};

pub struct IatDllIter {
    base: usize,
    import_table: *const IMAGE_IMPORT_DESCRIPTOR,
}

pub struct IatDll {
    base: usize,
    pub dll_name: CString,
    thunk_data: *const IMAGE_THUNK_DATA,
    iat: *const usize,
}

impl Iterator for IatDll {
    type Item = IatDllImport;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            while *((*self.thunk_data).u1.Ordinal()) != 0 {
                if !IMAGE_SNAP_BY_ORDINAL(*(*self.thunk_data).u1.Ordinal()) {
                    let import_info = (self.base
                        + (*(*self.thunk_data).u1.AddressOfData() as usize))
                        as *const IMAGE_IMPORT_BY_NAME;
                    let name = CStr::from_ptr((*import_info).Name.as_ptr()).to_owned();
                    let addr = self.iat as *mut ();
                    self.thunk_data = self.thunk_data.add(1); // Increment for next iteration
                    self.iat = self.iat.add(1); // Increment for next iteration
                    return Some(IatDllImport { name, addr });
                }
                self.thunk_data = self.thunk_data.add(1);
                self.iat = self.iat.add(1);
            }
            None
        }
    }
}

pub struct IatDllImport {
    pub name: CString,
    pub addr: *mut (),
}

impl Iterator for IatDllIter {
    type Item = IatDll;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if *(*self.import_table).u.Characteristics() != 0 {
                let dll_name = CStr::from_ptr(
                    (self.base + ((*self.import_table).Name) as usize) as *const c_char,
                )
                .to_owned();
                let thunk_data = (self.base + *(*self.import_table).u.OriginalFirstThunk() as usize)
                    as *const IMAGE_THUNK_DATA;
                let iat = (self.base + (*self.import_table).FirstThunk as usize) as *const usize;
                self.import_table = self.import_table.add(1); // Increment for next iteration
                Some(IatDll {
                    base: self.base,
                    dll_name,
                    thunk_data,
                    iat,
                })
            } else {
                None
            }
        }
    }
}

/// Create an iterator for the IAT DLL imports.
pub unsafe fn get_iat_iter(module: HMODULE) -> IatDllIter {
    let base = module as usize;
    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_header = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let import_table = (base
        + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
    IatDllIter { base, import_table }
}

/// Searches the IAT for imported functions in a specified DLL.
#[deprecated(
    note = "`get_iat_addr` is deprecated in favor of iterator form. Use `get_iat_iter` instead."
)]
#[allow(dead_code)]
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
