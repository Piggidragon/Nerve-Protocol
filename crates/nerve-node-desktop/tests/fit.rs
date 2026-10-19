//! The app fits a screen of 1280x800: its windows open no larger than such a
//! screen leaves them, what an install, update or uninstall did fits the
//! installer and the dialogs without scrolling, and a longer step or dialog
//! scrolls inside the window.

use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::{AppWindow, Install, Pick, Prefs, Store};
use slint::{ComponentHandle, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel};

/// What a screen of 1280x800 leaves a window's content: less a panel (the
/// taskbar of Windows is 48 pixels high) and the window's title bar.
const ROOM: (f32, f32) = (1280.0, 720.0);
/// The app's window, as it opens.
const APP: (u32, u32) = (1180, 700);

fn lines(n: usize, text: &str) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        (0..n)
            .map(|i| SharedString::from(format!("{text} ({i})")))
            .collect::<Vec<_>>(),
    ))
}

/// The installer's window, as it opens.
const INSTALLER: (u32, u32) = (760, 640);

/// The bottom `rows` of the window. A dialog's card ends 24 pixels above
/// the window's foot when its content scrolls, and higher when it fits.
fn bottom(pixels: &SharedPixelBuffer<Rgba8Pixel>, rows: usize) -> Vec<Rgba8Pixel> {
    let (w, h) = (pixels.width() as usize, pixels.height() as usize);
    pixels.as_slice()[(h - rows) * w..].to_vec()
}

/// Whether the bottom rows of the installer show its background only, left
/// of where a scroll bar may be: the step ends above them.
fn foot_is_background(pixels: &SharedPixelBuffer<Rgba8Pixel>) -> bool {
    let w = pixels.width() as usize;
    let background = pixels.as_slice()[0];
    bottom(pixels, 20)
        .chunks(w)
        .all(|row| row[..w - 24].iter().all(|p| *p == background))
}

#[test]
fn every_installer_step_and_dialog_fits_a_small_screen() {
    let screen = Screen::install(APP.0, APP.1, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let fits = |what: &str| {
        let (min, preferred) = screen.wants();
        assert!(
            min.width <= ROOM.0 && min.height <= ROOM.1,
            "{what}: the window cannot be smaller than {min:?}"
        );
        assert!(
            preferred.width <= ROOM.0 && preferred.height <= ROOM.1,
            "{what}: the window opens at {preferred:?}"
        );
    };
    fits("the app");

    // The installer opens smaller still.
    let install = window.global::<Install>();
    install.set_shown(true);
    fits("the installer");

    // A step longer than the installer's window scrolls to its end: the
    // welcome on Windows, with its password field, after a long error.
    screen.resize(INSTALLER.0, INSTALLER.1);
    install.set_windows(true);
    install.set_program("C:\\Program Files\\Nerve\\nerve-node-desktop.exe".into());
    install.set_step("welcome".into());
    install.set_action("install".into());
    install.set_error(
        "the service did not start: a long reason from the system, which goes on for a while so that it wraps over more than one line of the step, and then some more, as Windows says it"
            .into(),
    );
    assert!(
        !foot_is_background(&screen.draw()),
        "the step is not longer than the window"
    );
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(380.0, 320.0),
            delta_x: 0.0,
            delta_y: -5000.0,
        });
    assert!(
        foot_is_background(&screen.draw()),
        "a long step of the installer does not scroll to its end"
    );

    // What an install, update or uninstall did fits the installer's window
    // without scrolling, the buttons below it: its foot is the window's
    // background.
    install.set_error("".into());
    install.set_warnings(lines(1, "Warning: update-desktop-database is not on this machine, so the desktop may not know yet that Nerve opens nerve:// links"));
    install.set_did(lines(
        12,
        "removed Nerve from the application menu and the link handler of nerve:// links",
    ));
    for action in ["install", "update", "uninstall"] {
        install.set_step("done".into());
        install.set_action(action.into());
        assert!(
            foot_is_background(&screen.draw()),
            "the installer's last step of {action} does not fit its window"
        );
    }
    install.set_shown(false);
    fits("the app after the installer");

    // The dialogs in the app's window: a short one ends well above the
    // window's foot, so does the last step of an update or uninstall, and a
    // dialog longer than the window scrolls inside it.
    screen.resize(APP.0, APP.1);
    install.set_did(lines(
        16,
        "removed Nerve from the application menu and the link handler of nerve:// links",
    ));
    let store = window.global::<Store>();
    store.set_elevate_open(true);
    let foot = bottom(&screen.draw(), 26);
    store.set_elevate_open(false);
    install.set_action("uninstall".into());
    install.set_uninstall_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the uninstall's last step does not fit the window"
    );
    install.set_uninstall_open(false);
    install.set_action("update".into());
    install.set_update_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the update's last step does not fit the window"
    );
    install.set_update_open(false);
    let prefs = window.global::<Prefs>();
    prefs.set_relay_edit_name("laptop-2".into());
    prefs.set_relay_edit_centers(ModelRc::new(VecModel::from(
        (0..30)
            .map(|i| Pick {
                name: format!("center-{i}").into(),
                on: i % 2 == 0,
            })
            .collect::<Vec<_>>(),
    )));
    prefs.set_relay_edit_own(true);
    prefs.set_relay_edit_open(true);
    assert!(
        bottom(&screen.draw(), 20) == foot[foot.len() - 20 * APP.0 as usize..],
        "a dialog longer than the window runs out of it"
    );
}
