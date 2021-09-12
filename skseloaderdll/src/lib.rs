use helpers::quick_msg_box;
use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::{libloaderapi::DisableThreadLibraryCalls, processthreadsapi::ExitProcess},
};

mod antidebugger;
mod helpers;
mod skse_load;

/// The actual main function.
fn main(_base: LPVOID) {
    // helpers::quick_msg_box("Hello from Rust!");
    helpers::identify_skyrim_version();
    antidebugger::hook_thread_info();
    skse_load::hook_skse_loader();
    // quick_msg_box("Load complete!");
}

/// DLL entry point. On initial process attach, sets up the panic handler and calls [main].
/// See [Reference](https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html)
#[no_mangle]
pub extern "stdcall" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> i32 {
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            unsafe {
                // We care don't about messages besides DLL_PROCESS_ATTACH. Disable them.
                DisableThreadLibraryCalls(hinst_dll);
            }
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
            // Call our main!
            main(hinst_dll as _);
            return true as i32;
        }
        _ => true as i32,
    }
}
