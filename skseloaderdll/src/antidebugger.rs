//! # Anti-debugger disable
//! The game prevents debugging by calling a kernel function `ZwSetInformationThread` that will
//! tell Windows that it's not OK to debug it. We will patch this function so that we can screen
//! out the calls that specifically set that flag.

use std::ffi::CString;

use atomic::Atomic;
use detour::RawDetour;
use std::sync::atomic::Ordering;
use widestring::WideCString;
use winapi::shared::minwindef::{BOOL, TRUE};
use winapi::shared::ntdef::ULONG;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::winnt::{HANDLE, PVOID};

type ThreadInfoFn = unsafe extern "stdcall" fn(HANDLE, ULONG, PVOID, ULONG) -> BOOL;

static ZW_SET_INFORMATION_THREAD_ORIGINAL: Atomic<Option<ThreadInfoFn>> = Atomic::new(None);

/// Our replacement for `ZwSetInformationThread` that will filter out calls that set the anti-debug flag.
unsafe extern "stdcall" fn zw_set_information_thread_detour(
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
        .load(Ordering::SeqCst)
        .expect("ZW_SET_INFORMATION_THREAD_DETOUR_ORIGINAL was None! Exiting...")(
        thread_handle,
        thread_information_class,
        thread_information,
        thread_information_length,
    );
}

/// The main function here that will perform the hooking.
pub fn hook_thread_info() {
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
        ZW_SET_INFORMATION_THREAD_ORIGINAL
            .store(std::mem::transmute(h.trampoline()), Ordering::SeqCst);
        h.enable()
            .expect("Failed to enable trampoline! Terminating!");
        std::mem::forget(h);
    }
}
