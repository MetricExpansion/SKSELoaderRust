// Ref: https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html

use detour::RawDetour;
use log::*;
use std::error::Error;
use std::ffi::{c_void, CStr, CString};
use std::intrinsics::copy_nonoverlapping;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use widestring::WideCString;
use winapi::shared::minwindef::{BOOL, FALSE, HMODULE, TRUE};
use winapi::shared::ntdef::ULONG;
use winapi::um::libloaderapi::{GetModuleHandleA, GetModuleHandleW, GetProcAddress, LoadLibraryW};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::processthreadsapi::ExitProcess;
use winapi::um::winnt::{
    HANDLE, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_SNAP_BY_ORDINAL, IMAGE_THUNK_DATA,
    PAGE_EXECUTE_READWRITE, PVOID,
};
use winapi::um::winuser::{MessageBoxA, MB_OK};

fn main(_base: winapi::shared::minwindef::LPVOID) {
    simple_logger::SimpleLogger::new().init().unwrap();
    // quick_msg_box("Hello from Rust!");
    hook_thread_info();
    hook_skse_loader();
}

// SKSE loading

fn hook_skse_loader() {
    info!("Searching for __telemetry_main_invoke_trigger in VCRUNTIME140.dll");
    let addr = unsafe {
        get_iat_addr(
            GetModuleHandleA(null()),
            "VCRUNTIME140.dll",
            "__telemetry_main_invoke_trigger",
        )
    };
    match addr {
        Ok(Some(addr)) => {
            info!("Found it at {:?}", addr);
            unsafe {
                let addr = std::mem::transmute::<*mut _, *mut TelemFn>(addr);
                __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL = *addr;
                let new_addr: TelemFn = Some(__telemetry_main_invoke_trigger_replacement);
                write_protected_buffer(
                    addr as *mut c_void,
                    std::mem::transmute::<*const _, *const c_void>(&new_addr as *const TelemFn),
                    std::mem::size_of::<*const c_void>(),
                );
            }
            // let addr_new = unsafe { get_iat_addr(GetModuleHandleA(null()), "VCRUNTIME140.dll", "__telemetry_main_invoke_trigger") }.unwrap().unwrap() as *const TelemFn;
            // quick_msg_box(&format!("Patched __telemetry_main_invoke_trigger to {:?}! New address is {:?}", __telemetry_main_invoke_trigger_replacement as *const (), unsafe { *addr_new }));
        }
        Ok(None) => {
            quick_msg_box("Did not find it!");
            error!("Did not find it!");
        }
        Err(error) => {
            quick_msg_box("Error when finding it!");
            error!("Error occurred during search: {}", error);
        }
    }
}

type TelemFn = Option<unsafe extern "cdecl" fn(*mut c_void)>;

static mut __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL: TelemFn = None;
static mut SKSE_LOADED: bool = false;

pub unsafe extern "cdecl" fn __telemetry_main_invoke_trigger_replacement(args: *mut c_void) {
    let func = if let Some(func) = __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL {
        func
    } else {
        quick_msg_box("__TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL was None! Exiting...");
        ExitProcess(42);
        return;
    };
    load_skse();
    func(args);
}

unsafe fn load_skse() {
    // Add custom logic here...
    if SKSE_LOADED {
        return;
    }
    // TODO: Get the actual game path and identify the game version and construct DLL path properly.
    let skse_dll_path = WideCString::from_str("skse64_1_5_73.dll").unwrap();
    let result = LoadLibraryW(skse_dll_path.as_ptr());
    if result.is_null() {
        quick_msg_box("Failed to load SKSE! Terminating!");
        ExitProcess(42);
    }
    SKSE_LOADED = true;
}

// Debugger enable

type ThreadInfoFn = unsafe extern "stdcall" fn(HANDLE, ULONG, PVOID, ULONG) -> BOOL;
static mut ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL: Option<ThreadInfoFn> = None;

pub unsafe extern "stdcall" fn zw_set_information_thread_detour(
    thread_handle: HANDLE,
    thread_information_class: ULONG,
    thread_information: PVOID,
    thread_information_length: ULONG,
) -> BOOL {
    let func = if let Some(func) = ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL {
        func
    } else {
        quick_msg_box("ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL was None! Exiting...");
        ExitProcess(42);
        return FALSE;
    };
    // This prevents the debugger protection from happening.
    if thread_information_class == 0x11 {
        return TRUE;
    }
    return func(
        thread_handle,
        thread_information_class,
        thread_information,
        thread_information_length,
    );
}

fn hook_thread_info() {
    let addr = unsafe {
        let mod_name = WideCString::from_str("ntdll.dll").unwrap();
        let fn_name = CString::new("ZwSetInformationThread").unwrap();
        let addr = GetProcAddress(GetModuleHandleW(mod_name.as_ptr()), fn_name.as_ptr());
        Some(std::mem::transmute::<_, ThreadInfoFn>(addr))
    };
    let addr = if let Some(addr) = addr {
        addr
    } else {
        quick_msg_box("Failed to get address of ZwSetInformationThread! Terminating!");
        unsafe { ExitProcess(42) };
        return;
    };
    unsafe {
        let h = if let Ok(h) = RawDetour::new(
            addr as *const (),
            zw_set_information_thread_detour as *const (),
        ) {
            h
        } else {
            quick_msg_box("Failed to get hook ZwSetInformationThread! Terminating!");
            ExitProcess(42);
            return;
        };
        ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL = std::mem::transmute(h.trampoline());
        let enabled = h.enable();
        if let Err(_) = enabled {
            quick_msg_box("Failed to enable trampoline! Terminating!");
            ExitProcess(42);
        }
        std::mem::forget(h);
    }
}

// DLL entry point

#[no_mangle]
pub extern "stdcall" fn DllMain(
    hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> i32 {
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            unsafe {
                // start loading
                winapi::um::libloaderapi::DisableThreadLibraryCalls(hinst_dll);
            }
            main(hinst_dll as _);
            return true as i32;
        }
        _ => true as i32,
    }
}

// Helper functions

unsafe fn get_iat_addr(
    module: HMODULE,
    search_dll_name: &str,
    search_import_name: &str,
) -> Result<Option<*mut c_void>, Box<dyn Error>> {
    let search_import_name = CString::new(search_import_name)?;
    let search_dll_name = CString::new(search_dll_name)?;
    let base = module as usize;
    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_header = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let mut import_table = (base
        + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
    while *(*import_table).u.Characteristics() != 0 {
        let dll_name = CStr::from_ptr((base + ((*import_table).Name) as usize) as *const c_char);
        trace!("DLL name: {:?}", dll_name);
        if search_dll_name.as_c_str() == dll_name {
            let mut thunk_data = (base + *(*import_table).u.OriginalFirstThunk() as usize)
                as *const IMAGE_THUNK_DATA;
            let mut iat = (base + (*import_table).FirstThunk as usize) as *const usize;
            while *((*thunk_data).u1.Ordinal()) != 0 {
                if !IMAGE_SNAP_BY_ORDINAL(*(*thunk_data).u1.Ordinal()) {
                    let import_info = (base + (*(*thunk_data).u1.AddressOfData() as usize))
                        as *const IMAGE_IMPORT_BY_NAME;
                    let name = CStr::from_ptr((*import_info).Name.as_ptr());
                    trace!("Function {:?} in DLL {:?}", name, dll_name);
                    if search_import_name.as_c_str() == name {
                        return Ok(Some(iat as *mut c_void));
                    }
                }
                thunk_data = thunk_data.add(1);
                iat = iat.add(1);
            }
        }
        import_table = import_table.add(1);
    }
    Ok(None)
}

fn quick_msg_box(msg: &str) {
    let message = CString::new(msg).unwrap();
    let title = CString::new("Message from Rust").unwrap();
    unsafe {
        MessageBoxA(null_mut(), message.as_ptr(), title.as_ptr(), MB_OK);
    }
}

unsafe fn write_protected_buffer(addr: *mut c_void, data: *const c_void, length: usize) {
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
