//! # SKSE loading
//! SKSE loading is done by a process called IAT hooking. A function in the MSVC C Runtime will have
//! its address in the IAT replaced with a function we control. There, we load SKSE and then call
//! the original function. The function we hook is __telemetry_main_invoke_trigger.
//! See [Reference](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking).

use std::ffi::c_void;
use std::ptr::null;

use widestring::WideCString;
use winapi::um::libloaderapi::{GetModuleHandleA, LoadLibraryW};

use crate::helpers::*;

pub fn hook_skse_loader() {
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
        crate::helpers::write_protected_buffer(
            addr as *mut c_void,
            std::mem::transmute::<*const _, *const c_void>(&new_addr as *const TelemFn),
            std::mem::size_of::<*const c_void>(),
        );
    }
}

type TelemFn = Option<unsafe extern "cdecl" fn(*mut c_void)>;

static mut __TELEMETRY_MAIN_INVOKE_TRIGGER_ORIGINAL: TelemFn = None;
static mut SKSE_LOADED: bool = false;

/// The replacement function for `__telemetry_main_invoke_trigger` that will load SKSE and then call the original.
unsafe extern "cdecl" fn __telemetry_main_invoke_trigger_replacement(args: *mut c_void) {
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
