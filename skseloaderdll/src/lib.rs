use detour::RawDetour;
use std::error::Error;
use std::ffi::{c_void, CStr, CString};
use std::intrinsics::copy_nonoverlapping;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use widestring::WideCString;
use winapi::shared::minwindef::{BOOL, HMODULE, TRUE};
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
    // quick_msg_box("Hello from Rust!");
    // Register a panic handler to kill the game if we have any issues.
    std::panic::set_hook(Box::new(|info| {
        match info.payload().downcast_ref::<&str>() {
            Some(message) => quick_msg_box(&format!("PANIC!: {}", message)),
            None => quick_msg_box(&format!("PANIC! Unknown reason.")),
        }
        unsafe {
            ExitProcess(42);
        }
    }));
    hook_thread_info();
    hook_skse_loader();
    // quick_msg_box("Load complete!");
}

// # SKSE loading
// SKSE loading is done by a process called IAT hooking. A function in the MSVC C Runtime will have
// its address in the IAT replaced with a function we control. There, we load SKSE and then call
// the original function. The function we hook is __telemetry_main_invoke_trigger.
// Ref: https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking

fn hook_skse_loader() {
    // Get the pointer to the IAT entry for __telemetry_main_invoke_trigger.
    let addr = unsafe {
        get_iat_addr(
            GetModuleHandleA(null()),
            "VCRUNTIME140.dll",
            "__telemetry_main_invoke_trigger",
        )
        .expect("Error {} when finding __telemetry_main_invoke_trigger! Terminating!")
        .expect("Did not find __telemetry_main_invoke_trigger! Terminating!")
    };
    unsafe {
        // Stash the function pointer in the IAT into a global variable for later use.
        let addr: *mut TelemFn = std::mem::transmute::<*mut _, _>(addr);
        __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL = *addr;
        // Now write the address of our replacement to the IAT.
        let new_addr: TelemFn = Some(__telemetry_main_invoke_trigger_replacement);
        write_protected_buffer(
            addr as *mut c_void,
            std::mem::transmute::<*const _, *const c_void>(&new_addr as *const TelemFn),
            std::mem::size_of::<*const c_void>(),
        );
    }
}

type TelemFn = Option<unsafe extern "cdecl" fn(*mut c_void)>;

static mut __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL: TelemFn = None;
static mut SKSE_LOADED: bool = false;

/// The replacement function for __telemetry_main_invoke_trigger that will load SKSE and then call the original.
pub unsafe extern "cdecl" fn __telemetry_main_invoke_trigger_replacement(args: *mut c_void) {
    load_skse();
    __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL
        .expect("__TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL was None! Exiting...")(args);
}

unsafe fn load_skse() {
    // Make sure to only do it once!
    if SKSE_LOADED {
        return;
    }
    // Very simple, just call LoadLibrary and let the SKSE DLL do all the work to patch the game!
    // TODO: Get the actual game path and identify the game version and construct DLL path properly.
    let skse_dll_path = WideCString::from_str("skse64_1_5_73.dll").unwrap();
    let result = LoadLibraryW(skse_dll_path.as_ptr());
    if result.is_null() {
        panic!("Failed to load SKSE! Terminating!");
    }
    SKSE_LOADED = true;
}

// # Anti-debugger disable
// The game prevents debugging by calling a kernel function ZwSetInformationThread that will
// tell Windows that it's not OK to debug it. We will patch this function so that we can screen
// out the calls that specifically set that flag.

type ThreadInfoFn = unsafe extern "stdcall" fn(HANDLE, ULONG, PVOID, ULONG) -> BOOL;
static mut ZW_SET_INFORMATION_THREAD_ORIGINAL: Option<ThreadInfoFn> = None;

/// Our replacement for ZwSetInformationThread that will filter out calls that set the anti-debug flag.
pub unsafe extern "stdcall" fn zw_set_information_thread_detour(
    thread_handle: HANDLE,
    thread_information_class: ULONG,
    thread_information: PVOID,
    thread_information_length: ULONG,
) -> BOOL {
    // This prevents the debugger protection from happening.
    if thread_information_class == 0x11 {
        return TRUE;
    }
    // Use the trampoline to call the original function.
    return ZW_SET_INFORMATION_THREAD_ORIGINAL
        .expect("ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL was None! Exiting...")(
        thread_handle,
        thread_information_class,
        thread_information,
        thread_information_length,
    );
}

fn hook_thread_info() {
    // First, we find the address of the ZwSetInformationThread function.
    let addr = unsafe {
        let mod_name = WideCString::from_str("ntdll.dll").unwrap();
        let fn_name = CString::new("ZwSetInformationThread").unwrap();
        let addr = GetProcAddress(GetModuleHandleW(mod_name.as_ptr()), fn_name.as_ptr());
        if addr.is_null() {
            panic!("Failed to get address of ZwSetInformationThread! Terminating!")
        }
        std::mem::transmute::<_, ThreadInfoFn>(addr)
    };
    unsafe {
        // We use the Detours library to patch the function so that it unconditionally jumps to our
        // version.
        let h = RawDetour::new(
            addr as *const (),
            zw_set_information_thread_detour as *const (),
        )
        .expect("Failed to get hook ZwSetInformationThread! Terminating!");
        // Detours will create a trampoline that we can use to call the original function. We save
        // the address of the trampoline to a global so that we can use it in our detour function.
        ZW_SET_INFORMATION_THREAD_ORIGINAL = std::mem::transmute(h.trampoline());
        h.enable()
            .expect("Failed to enable trampoline! Terminating!");
        std::mem::forget(h);
    }
}

// DLL entry point
// Ref: https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html

#[no_mangle]
pub extern "stdcall" fn DllMain(
    hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> i32 {
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            unsafe {
                // We don't about messages besides DLL_PROCESS_ATTACH. Disable them.
                winapi::um::libloaderapi::DisableThreadLibraryCalls(hinst_dll);
            }
            // Call our main!
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
