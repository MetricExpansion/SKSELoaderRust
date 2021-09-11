// Ref: https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html

use log::*;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA, IMAGE_SNAP_BY_ORDINAL, IMAGE_IMPORT_BY_NAME, PAGE_EXECUTE_READWRITE};
use std::ffi::{c_void, CStr, CString};
use winapi::shared::minwindef::{HMODULE};
use std::error::Error;
use std::os::raw::c_char;
use winapi::um::libloaderapi::{GetModuleHandleA, LoadLibraryW};
use std::ptr::{null, null_mut};
use winapi::um::winuser::{MessageBoxA, MB_OK};
use winapi::um::memoryapi::VirtualProtect;
use std::intrinsics::copy_nonoverlapping;
use winapi::um::processthreadsapi::ExitProcess;
use widestring::WideCString;


fn main(_base: winapi::shared::minwindef::LPVOID) {
    simple_logger::SimpleLogger::new().init().unwrap();
    quick_msg_box("Hello from Rust!");
    info!("DLL main() called.");
    info!("This is a Rust DLL running inside of another process!");
    info!("Searching for __telemetry_main_invoke_trigger in VCRUNTIME140.dll");
    let addr = unsafe { get_iat_addr(GetModuleHandleA(null()), "VCRUNTIME140.dll", "__telemetry_main_invoke_trigger") };
    match addr {
        Ok(Some(addr)) => {
            info!("Found it at {:?}", addr);
            unsafe {
                let addr = std::mem::transmute::<*mut _, *mut TelemFn>(addr);
                __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL = *addr;
                quick_msg_box(&format!("Found __telemetry_main_invoke_trigger at {:?}!", __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL.unwrap() as *const c_void));
                let new_addr: TelemFn = Some(__telemetry_main_invoke_trigger_replacement);
                write_protected_buffer(
                    addr as *mut c_void,
                    std::mem::transmute::<*const _, *const c_void>(&new_addr as *const TelemFn),
                    std::mem::size_of::<*const c_void>());
            }
            // let addr_new = unsafe { get_iat_addr(GetModuleHandleA(null()), "VCRUNTIME140.dll", "__telemetry_main_invoke_trigger") }.unwrap().unwrap() as *const TelemFn;
            // quick_msg_box(&format!("Patched __telemetry_main_invoke_trigger to {:?}! New address is {:?}", __telemetry_main_invoke_trigger_replacement as *const c_void, unsafe { *addr_new }));
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
    quick_msg_box("__telemetry_main_invoke_trigger intercepted!");
    let func = if let Some(func) = __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL { func } else {
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
    let skse_dll_path = WideCString::from_str("skse64_1_5_73.dll").unwrap();
    let result = LoadLibraryW(skse_dll_path.as_ptr());
    if result.is_null() {
        quick_msg_box("Failed to load SKSE! Terminating!");
    } else {
        quick_msg_box("Loaded SKSE!");
    }
    SKSE_LOADED = true;

}

#[no_mangle]
pub extern "stdcall" fn DllMain(
    hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> i32 {
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            unsafe { // start loading
                winapi::um::libloaderapi::DisableThreadLibraryCalls(hinst_dll);
            }
            main(hinst_dll as _);
            return true as i32;
        }
        _ => true as i32,
    }
}

unsafe fn get_iat_addr(module: HMODULE, search_dll_name: &str, search_import_name: &str) -> Result<Option<*mut c_void>, Box<dyn Error>> {
    let search_import_name = CString::new(search_import_name)?;
    let search_dll_name = CString::new(search_dll_name)?;
    let base = module as usize;
    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_header = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let mut import_table = (base + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
    while *(*import_table).u.Characteristics() != 0 {
        let dll_name = CStr::from_ptr((base + ((*import_table).Name) as usize) as *const c_char);
        trace!("DLL name: {:?}", dll_name);
        if search_dll_name.as_c_str() == dll_name {
            let mut thunk_data = (base + *(*import_table).u.OriginalFirstThunk() as usize) as *const IMAGE_THUNK_DATA;
            let mut iat = (base + (*import_table).FirstThunk as usize) as *const usize;
            while *((*thunk_data).u1.Ordinal()) != 0 {
                if !IMAGE_SNAP_BY_ORDINAL(*(*thunk_data).u1.Ordinal()) {
                    let import_info = (base + (*(*thunk_data).u1.AddressOfData() as usize)) as *const IMAGE_IMPORT_BY_NAME;
                    let name = CStr::from_ptr((*import_info).Name.as_ptr());
                    trace!("Function {:?} in DLL {:?}", name, dll_name);
                    if search_import_name.as_c_str() == name  {
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
    unsafe { MessageBoxA(null_mut(),  message.as_ptr(), title.as_ptr(), MB_OK); }
}

unsafe fn write_protected_buffer(addr: *mut c_void, data: *const c_void, length: usize) {
    let mut old_protect = 0;
    VirtualProtect(addr, length, PAGE_EXECUTE_READWRITE, (&mut old_protect) as _);
    copy_nonoverlapping(data, addr, length);
    VirtualProtect(addr, length, old_protect, (&mut old_protect) as _);
}