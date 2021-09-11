use helpers::quick_msg_box;
use winapi::um::processthreadsapi::ExitProcess;

mod antidebugger;
mod helpers;
mod skse_load;

/// The actual main function.
fn main(_base: winapi::shared::minwindef::LPVOID) {
    // helpers::quick_msg_box("Hello from Rust!");
    antidebugger::hook_thread_info();
    skse_load::hook_skse_loader();
    quick_msg_box("Load complete!");
}

/// DLL entry point. On initial process attach, sets up the panic handler and calls [main].
/// See [Reference](https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html)
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

// Helper functions
