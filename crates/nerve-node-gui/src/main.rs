//! `nerve-node-gui`: the node with its desktop app, in one program. Started
//! with arguments it is `nerve-node`, which the app runs for every action;
//! started without any it opens the window.

// No console window behind the app on Windows; the CLI attaches to the
// console it was started from (nerve_node_gui::console). A shell does not wait
// for a GUI program, though: in a terminal, `nerve-node.exe` is the CLI, or
// `start /wait` runs this one.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if std::env::args_os().len() > 1 {
        #[cfg(windows)]
        nerve_node_gui::console::attach();
        std::process::exit(nerve_node::entry::main());
    }
    if let Err(e) = nerve_node_gui::app::run() {
        eprintln!("nerve-node-gui: {e}");
        std::process::exit(1);
    }
}
