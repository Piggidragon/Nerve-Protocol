//! `nerve-node-desktop`: the node with its desktop app, in one program. Started
//! with arguments it is `nerve-node`, which the app runs for every action;
//! started without any it opens the window.

// No console window behind the app on Windows; the CLI attaches to the
// console it was started from (nerve_node_desktop::console). A shell does not wait
// for a GUI program, though: in a terminal, `nerve-node.exe` is the CLI, or
// `start /wait` runs this one.
#![cfg_attr(windows, windows_subsystem = "windows")]

use nerve_node_desktop::instance::Asked;

fn main() {
    // This program is the desktop app's edition of the node: installed as
    // nerve-node-desktop, with its menu entry and link handler.
    nerve_node::edition::set(&nerve_node_desktop::parts::EDITION);
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
    // The uninstall of Apps & features on Windows opens the app's.
    let start = match words.as_slice() {
        [Some(link)] if link.to_ascii_lowercase().starts_with("nerve://") => {
            Some(Asked::link(link))
        }
        [Some(arg)] if *arg == nerve_node_desktop::parts::UNINSTALL_ARG => Some(Asked {
            uninstall: true,
            ..Asked::default()
        }),
        [] => Some(Asked::default()),
        _ => None,
    };
    let Some(start) = start else {
        #[cfg(windows)]
        nerve_node_desktop::console::attach();
        std::process::exit(nerve_node::entry::main());
    };
    use nerve_node_desktop::app::Failed;
    use nerve_node_desktop::deps;
    let fail = |e: &str| -> ! {
        eprintln!("nerve-node-desktop: {e}");
        // Started from the menu, nobody reads stderr.
        deps::notify("Nerve cannot open its window", e);
        std::process::exit(1);
    };
    match nerve_node_desktop::app::run(start) {
        Ok(()) => {}
        Err(Failed::NoDisplay(e)) => fail(&e),
        Err(Failed::Window(e)) => {
            let chosen = std::env::var(deps::BACKEND_VAR).ok();
            match deps::after_window_error(&e, chosen.as_deref()) {
                deps::Next::Software => {
                    eprintln!(
                        "nerve-node-desktop: the GPU renderer did not start ({e}); drawing in software"
                    );
                    std::process::exit(deps::rerun_in_software());
                }
                deps::Next::Fail(e) => fail(&e),
            }
        }
        Err(Failed::Other(e)) => {
            eprintln!("nerve-node-desktop: {e}");
            std::process::exit(1);
        }
    }
}
