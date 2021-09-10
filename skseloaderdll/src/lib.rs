use std::error::Error;

// Much of this is copy-pasted from https://www.unknowncheats.me/forum/rust-language-/330583-pure-rust-injectable-dll.html

/// This is ran on attachment of the Rust DLL, and returns a Result to indicate
/// an error if there happens to be one.
fn dll_attach(_base: winapi::shared::minwindef::LPVOID) -> Result<(), Box<dyn Error>> {
    // prints stuff to the console of where it was ran; this also works on non-games!
    println!("this was injected by Rust!");
    // println!("the PID is {}", process.pid());

    // ok this worked out fine; say that it all went ok
    Ok(())
}

/// This is ran on the detachment of the Rust DLL. It returns a Result to indicate
/// whether were errors.
fn dll_detach() -> Result<(), Box<dyn Error>> {
    Ok(())
}

// make a wrapper which has to be unsafe to use and also depends on
// the system's own calling methodology
unsafe extern "system" fn dll_attach_wrapper(base: winapi::shared::minwindef::LPVOID) -> u32 {
    use std::panic; // local import

    // make sure that when attached, it doesn't fuck us over somehow (thru panicking)
    match panic::catch_unwind(|| dll_attach(base)) {
        Err(e) => {
            eprintln!("`dll_attach` has panicked: {:#?}", e);
        }
        Ok(r) => match r {
            Ok(()) => {}
            Err(e) => { // something went wrong without panicking; time to tell us what it is and potentially diagnose
                eprintln!("`dll_attach` returned an Err: {:#?}", e);
            }
        },
    }

    // for the DLL not to instantly stop, block the dll_attach function

    // make sure that when detaching, it doesn't fuck us over somehow (thru panicking)
    match panic::catch_unwind(|| dll_detach()) {
        Err(e) => {
            eprintln!("`dll_detach` has panicked: {:#?}", e);
        }
        Ok(r) => match r {
            Ok(()) => {}
            Err(e) => {
                eprintln!("`dll_detach` returned an Err: {:#?}", e);
            }
        },
    }

    // free the lib and exit the thread.
    // the thread should just stop working now
    winapi::um::libloaderapi::FreeLibraryAndExitThread(base as _, 1);

    // in the case that windows is a fuckwit, panic
    unreachable!()
}
#[no_mangle] // call it "DllMain" in the compiled DLL
pub extern "stdcall" fn DllMain(
    hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> i32 {
    match fdw_reason { // match for what reason it's calling us
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            unsafe { // start loading
                winapi::um::libloaderapi::DisableThreadLibraryCalls(hinst_dll);
                winapi::um::processthreadsapi::CreateThread( // make a thread to live in
                                                             std::ptr::null_mut(),
                                                             0,
                                                             Some(dll_attach_wrapper),
                                                             hinst_dll as _,
                                                             0,
                                                             std::ptr::null_mut(),
                );
            }
            return true as i32; // say it went a-ok
        }
        winapi::um::winnt::DLL_PROCESS_DETACH => { // start detaching
            if !lpv_reserved.is_null() {
                match std::panic::catch_unwind(|| dll_detach()) {
                    Err(e) => {
                        eprintln!("`dll_detach` has panicked: {:#?}", e);
                    }
                    Ok(r) => match r {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("`dll_detach` returned an Err: {:#?}", e);
                        }
                    },
                }
            }

            return true as i32;
        }
        _ => true as i32, // it went a-ok because we dont know what happened so lol fuck off
    }
}
