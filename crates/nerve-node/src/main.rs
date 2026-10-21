//! `nerve-node`: the node daemon and its command line.

fn main() {
    // DLLs from System32 only, never from the program's own folder: the
    // downloaded program runs from the downloads, and as administrator when
    // it installs, so a DLL put beside it would run with those rights
    // (build.rs delays the DLLs that would load before this line). Every
    // supported Windows can; one that cannot gets no further.
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
        };
        // SAFETY: a flag for this process's DLL search.
        if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
            std::process::exit(1);
        }
    }
    std::process::exit(nerve_node::entry::main());
}
