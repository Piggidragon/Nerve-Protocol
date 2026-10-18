//! Compiles the app's Slint files (ui/) into Rust, with the fluent style for
//! the few std widgets it takes (the scroll bars, AboutSlint): the app draws
//! its own controls.

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("the Slint files compile");
}
