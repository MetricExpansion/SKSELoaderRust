use byte_strings::c_str;
#[allow(unused_imports)]
use std::ffi::CString;
#[allow(unused_imports)]
use std::ptr::{null, null_mut};
#[allow(unused_imports)]
use winapi::shared::minwindef::{BOOL, FALSE};
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;
use winapi::um::processthreadsapi::{
    CreateProcessA, CreateRemoteThread, OpenProcess, ResumeThread, PROCESS_INFORMATION,
    STARTUPINFOA,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_SUSPENDED, INFINITE, WAIT_ABANDONED, WAIT_OBJECT_0};
use winapi::um::winnt::{
    MEM_COMMIT, PAGE_EXECUTE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

fn main() {
    let exe = c_str!("C:\\Users\\m\\Downloads\\CinebenchR20\\Cinebench.exe");
    let dll_path = c_str!("C:\\Users\\m\\Downloads\\CinebenchR20\\vcruntime140.dll");
    let sync = true;
    let timeout = true;

    let mut startup_info = STARTUPINFOA::default();
    let mut process_info = PROCESS_INFORMATION::default();

    // Create the process image, but suspended.
    let create_result = unsafe {
        CreateProcessA(
            exe.as_ptr(),
            null_mut(),       // no args
            null_mut(),       // default process security
            null_mut(),       // default thread security
            FALSE,            // don't inherit handles
            CREATE_SUSPENDED, // start the main thread as suspended
            null_mut(),       // no new env
            null_mut(),       // no new cwd
            &mut startup_info,
            &mut process_info,
        )
    };
    if create_result == FALSE {
        panic!("Failed to launch process!");
    }

    // Get the process handle
    let proc_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            process_info.dwProcessId,
        )
    };
    if proc_handle.is_null() {
        panic!("Could not get process handle!")
    }

    // Create a page in memory to store the argument to LoadLibraryA
    let hook_base = unsafe {
        VirtualAllocEx(
            proc_handle,
            null_mut(),
            8192,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as usize
    };
    if hook_base == 0 {
        panic!("Could not get hook base!")
    }

    // Get the address of LoadLibraryA to use as entry-point in a new thread created in child.
    // We make use of the fact that kernel32.dll is always at the safe offset in all processes
    // in a given boot of Windows.
    let lla_addr = unsafe {
        GetProcAddress(
            GetModuleHandleA(c_str!("kernel32.dll").as_ptr()),
            c_str!("LoadLibraryA").as_ptr(),
        ) as usize
    };
    if lla_addr == 0 {
        panic!("Could not get LoadLibraryA address!")
    }

    dbg!(hook_base, lla_addr);

    // Write the DLL string into my memory page.
    let _bytes_written = unsafe {
        let mut bytes_written = 0;
        WriteProcessMemory(
            proc_handle,
            hook_base as *mut _,
            dll_path.as_ptr() as *const _,
            dll_path.to_bytes_with_nul().len(),
            &mut bytes_written,
        );
        bytes_written
    };

    // Create the thread in the process that will load the DLL and run the DLL main.
    let thread = unsafe {
        CreateRemoteThread(
            proc_handle,
            null_mut(),
            0,
            std::mem::transmute::<usize, LPTHREAD_START_ROUTINE>(lla_addr),
            hook_base as *mut _,
            0,
            null_mut(),
        )
    };
    if thread.is_null() {
        panic!("Could not create thread in process!")
    }

    unsafe {
        CloseHandle(proc_handle);
    }

    // Wait for thread to finish
    if sync {
        match unsafe { WaitForSingleObject(thread, if timeout { 1000 * 60 } else { INFINITE }) } {
            WAIT_OBJECT_0 => { /* success */ }
            WAIT_ABANDONED => {
                panic!("Wait was abandoned")
            }
            WAIT_TIMEOUT => {
                panic!("Wait timeout")
            }
            other => {
                panic!("Other error in WaitForSingleObject: {}", other)
            }
        }
    }

    // Finally launch the process
    unsafe {
        ResumeThread(process_info.hThread);
    }
}
