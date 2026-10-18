//! `nerve-node`: the node daemon and its command line.

fn main() {
    std::process::exit(nerve_node::entry::main());
}
