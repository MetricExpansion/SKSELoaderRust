# SKSE Loader in Rust

This is an implementation of the [SKSE Loader](http://skse.silverlock.org) in Rust. To build it, simply clone this repo and run

    cargo build

on a Windows system with MSVC and Rust installed.

The executable that is generated takes two arguments:

    skseloaderrs.exe [PATH_TO_EXE] [PATH_TO_DLL]

For injecting SKSE into Skyrim, make sure CWD is the game install folder, and then use `SkyrimSE.exe` as the EXE and this project's `skseloaderdll.dll` as the DLL. Make sure the `skse64_1_5_73.dll` (this will be made to automatically detect the game version later) is in the same directory as well (it should be if SKSE is installed correctly). The game should launch with SKSE injected and anti-debugging protections disabled.
