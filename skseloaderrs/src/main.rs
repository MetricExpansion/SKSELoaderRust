use byte_strings::c_str;
use log::*;
#[allow(unused_imports)]
use std::ffi::CString;
use std::ops::Deref;
use std::path::PathBuf;
#[allow(unused_imports)]
use std::ptr::{null, null_mut};
use structopt::StructOpt;
use widestring::WideCString;
use winapi::{
    shared::minwindef::FALSE,
    shared::winerror::WAIT_TIMEOUT,
    um::handleapi::CloseHandle,
    um::libloaderapi::{GetModuleHandleA, GetProcAddress},
    um::memoryapi::{VirtualAllocEx, WriteProcessMemory},
    um::minwinbase::LPTHREAD_START_ROUTINE,
    um::processthreadsapi::{
        CreateProcessW, CreateRemoteThread, OpenProcess, ResumeThread, PROCESS_INFORMATION,
        STARTUPINFOW,
    },
    um::synchapi::WaitForSingleObject,
    um::winbase::{CREATE_SUSPENDED, INFINITE, WAIT_ABANDONED, WAIT_OBJECT_0},
    um::winnt::{
        HANDLE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PROCESS_CREATE_THREAD,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    },
};

#[derive(Debug, StructOpt)]
struct Options {
    executable: PathBuf,
    dll: PathBuf,
    #[structopt(long)]
    no_sync: bool,
    #[structopt(long)]
    no_timeout: bool,
}

fn main() {
    // Program init
    let opt = Options::from_args();
    simple_logger::SimpleLogger::new().init().unwrap();
    // Check the paths
    if !opt.executable.exists() {
        warn!(
            "The executable path {} may not exist.",
            opt.executable.to_string_lossy()
        );
    }
    if !opt.dll.exists() {
        warn!("The DLL path {} may not exist.", opt.dll.to_string_lossy());
    }

    // Convert the executable to UCS-2 string and DLL path to ASCII string.
    let exe = WideCString::from_os_str(opt.executable.as_os_str()).unwrap();
    let dll_path = opt
        .dll
        .into_os_string()
        .into_string()
        .expect("Could not convert DLL path to ASCII!");

    // Other parameters
    let sync = !opt.no_sync;
    let timeout = !opt.no_timeout;

    // Create the process image, but suspended.
    info!("Creating process {}.", exe.to_string_lossy());
    let (main_proc_handle, main_thread_handle, process_id) = unsafe {
        let mut startup_info = STARTUPINFOW::default();
        let mut process_info = PROCESS_INFORMATION::default();
        let result = CreateProcessW(
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
        );
        if result == FALSE {
            error!("Failed to create process!");
            panic!();
        }
        (
            HandleWrapper::from_handle(process_info.hProcess),
            HandleWrapper::from_handle(process_info.hThread),
            process_info.dwProcessId,
        )
    };
    info!("Process started.");

    // Get the process handle
    info!("Getting a handle to the process.");
    let proc_handle = HandleWrapper::from_handle(unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            process_id,
        )
    });
    if proc_handle.is_null() {
        error!("Could not get process handle!");
        panic!()
    }

    // Create a page in memory to store the argument to LoadLibraryA
    info!("Creating a memory page to store thread start args.");
    let hook_base = unsafe {
        VirtualAllocEx(
            proc_handle.handle,
            null_mut(),
            8192,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as usize
    };
    if hook_base == 0 {
        error!("Could not get hook base!");
        panic!()
    }

    // Get the address of LoadLibraryA to use as entry-point in a new thread created in child.
    // We make use of the fact that kernel32.dll is always at the safe offset in all processes
    // in a given boot of Windows.
    info!("Getting address of LoadLibraryA.");
    let lla_addr = unsafe {
        GetProcAddress(
            GetModuleHandleA(c_str!("kernel32.dll").as_ptr()),
            c_str!("LoadLibraryA").as_ptr(),
        ) as usize
    };
    if lla_addr == 0 {
        error!("Could not get LoadLibraryA address!");
        panic!()
    }

    info!("Memory Page Address: {}", hook_base);
    info!("LoadLibraryA Address: {}", lla_addr);

    // Write the DLL string into my memory page.
    info!("Writing DLL path {} into memory page.", dll_path);
    let _bytes_written = unsafe {
        let mut bytes_written = 0;
        WriteProcessMemory(
            proc_handle.handle,
            hook_base as *mut _,
            dll_path.as_ptr() as *const _,
            dll_path.len(),
            &mut bytes_written,
        );
        bytes_written
    };

    // Create the thread in the process that will load the DLL and run the DLL main.
    info!("Invoking LoadLibraryA thread in process.");
    let thread = unsafe {
        CreateRemoteThread(
            proc_handle.handle,
            null_mut(),
            0,
            std::mem::transmute::<usize, LPTHREAD_START_ROUTINE>(lla_addr),
            hook_base as *mut _,
            0,
            null_mut(),
        )
    };
    if thread.is_null() {
        error!("Could not create thread in process!");
        panic!()
    }

    drop(proc_handle);

    // Wait for thread to finish
    if sync {
        match unsafe { WaitForSingleObject(thread, if timeout { 1000 * 60 } else { INFINITE }) } {
            WAIT_OBJECT_0 => {
                info!("DLL initialization completed.")
            }
            WAIT_ABANDONED => {
                error!("Wait was abandoned");
                panic!()
            }
            WAIT_TIMEOUT => {
                error!("Wait timeout");
                panic!()
            }
            other => {
                error!("Other error in WaitForSingleObject: {}", other);
                panic!()
            }
        }
    }

    // Finally launch the process
    info!("Resuming the process.");
    unsafe {
        ResumeThread(main_thread_handle.handle);
        info!("Process started.");
        WaitForSingleObject(main_proc_handle.handle, INFINITE);
    }
    info!("Process finished.");
}

struct HandleWrapper {
    handle: HANDLE,
}

impl HandleWrapper {
    fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Into<HANDLE> for HandleWrapper {
    fn into(self) -> HANDLE {
        self.handle
    }
}

impl Deref for HandleWrapper {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
