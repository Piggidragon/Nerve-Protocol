//! Links the message table of the node's Windows Event Log entries
//! (src/eventlog.rs) into the program, so the Event Viewer shows their text.
//! Windows' linker takes a `.res` file as it takes an object; the GNU one
//! does not, so a windows-gnu build goes without it.

#[allow(dead_code)]
#[path = "src/eventlog.rs"]
mod eventlog;

fn main() {
    println!("cargo:rerun-if-changed=src/eventlog.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let res = out.join("eventlog.res");
    std::fs::write(&res, eventlog::resource()).expect("write eventlog.res");
    // Every program of the crate, its tests included, carries the table.
    println!("cargo:rustc-link-arg={}", res.display());
}
