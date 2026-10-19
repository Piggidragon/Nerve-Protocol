//! `nerve-node-desktop`: the node with its desktop app, in one program. Started
//! with arguments it is `nerve-node`, which the app runs for every action;
//! started without any it opens the window.

// No console window behind the app on Windows; the CLI attaches to the
// console it was started from (nerve_node_desktop::console). A shell does not wait
// for a GUI program, though: in a terminal, `nerve-node.exe` is the CLI, or
// `start /wait` runs this one.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    // Not `args()`: a path for the CLI need not be UTF-8.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    // The elevated broker of the app (nerve_node_desktop::broker), started by
    // the app itself.
    if words.first() == Some(&Some(nerve_node_desktop::broker::ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve_node_desktop::broker::main(&rest));
    }
    // A nerve:// link alone, which the desktop hands to the app when one is
    // opened (no command of nerve-node): the app goes straight to pairing.
    if let [Some(link)] = words.as_slice()
        && link.to_ascii_lowercase().starts_with("nerve://")
    {
        if let Err(e) = nerve_node_desktop::app::run(Some(link.to_string())) {
            eprintln!("nerve-node-desktop: {e}");
            std::process::exit(1);
        }
        return;
    }
    if !args.is_empty() {
        #[cfg(windows)]
        nerve_node_desktop::console::attach();
        std::process::exit(nerve_node::entry::main());
    }
    if let Err(e) = nerve_node_desktop::app::run(None) {
        eprintln!("nerve-node-desktop: {e}");
        std::process::exit(1);
    }
}
