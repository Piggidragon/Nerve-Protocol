//! Screenshots of every page of the app, light and dark, drawn without a
//! screen by Slint's software renderer, for judging the look: a node of its
//! own under a temporary folder, paired with fake centers through the app,
//! its daemon running, and the app asking it as it does on a desktop. The
//! software renderer draws no shadows; the app on a desktop does.
//!
//! `NERVE_GUI_SHOTS=<folder> cargo test -p nerve-node-gui --test shots -- --ignored`

use std::path::{Path, PathBuf};

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_node_gui::app::{Ctl, Exec};
use nerve_node_gui::headless::Screen;
use nerve_node_gui::runner::Runner;
use nerve_node_gui::{AppWindow, Load, NodeStatus, Page, Store};
use slint::ComponentHandle;

const WIDTH: u32 = 1180;
const HEIGHT: u32 = 780;
const SCALE: f32 = 2.0;

struct Shots<'a> {
    screen: Screen,
    window: &'a AppWindow,
    out: PathBuf,
}

impl Shots<'_> {
    /// Saves the window as `<name>-light.png` and `<name>-dark.png`.
    fn take(&self, name: &str) {
        self.window.global::<Store>().set_toast_shown(false);
        self.take_as_is(name);
    }

    /// [`Shots::take`] with the note in the corner, if one shows.
    fn take_as_is(&self, name: &str) {
        for (dark, scheme) in [(false, "light"), (true, "dark")] {
            self.window.invoke_set_dark(dark);
            let pixels = self.screen.draw();
            let path = self.out.join(format!("{name}-{scheme}.png"));
            let file = std::fs::File::create(&path).unwrap();
            let mut png = png::Encoder::new(file, pixels.width(), pixels.height());
            png.set_color(png::ColorType::Rgba);
            png.set_depth(png::BitDepth::Eight);
            let mut w = png.write_header().unwrap();
            w.write_image_data(pixels.as_bytes()).unwrap();
            eprintln!("wrote {}", path.display());
        }
    }
}

fn decided(
    paths: &NodePaths,
    ago_ms: u64,
    center: &str,
    (cap, action): (&str, &str),
    target: &str,
    reason: Option<&str>,
) {
    let now = nerve_node::now_ms();
    nerve_policy::audit::AuditLog::new(paths.audit_log())
        .decision(&nerve_policy::audit::Entry {
            ts: now - ago_ms,
            center: center.into(),
            cap: cap.into(),
            action: action.into(),
            target: target.into(),
            decision: if reason.is_some() {
                "forbidden"
            } else {
                "allowed"
            }
            .into(),
            code: None,
            session: None,
            reason: reason.map(str::to_string),
        })
        .unwrap();
}

#[test]
#[ignore = "writes screenshots; NERVE_GUI_SHOTS names the folder"]
fn every_page_light_and_dark() {
    let Some(out) = std::env::var_os("NERVE_GUI_SHOTS").map(PathBuf::from) else {
        eprintln!("NERVE_GUI_SHOTS is not set");
        return;
    };
    std::fs::create_dir_all(&out).unwrap();
    let screen = Screen::install(
        (WIDTH as f32 * SCALE) as u32,
        (HEIGHT as f32 * SCALE) as u32,
        SCALE,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-gui").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let cli = runner.clone();
    let run = move |args: &[&str]| cli.run(args).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    let shots = Shots {
        screen,
        window: &window,
        out,
    };

    // Asking: the first moment of the app.
    store.set_status(NodeStatus::default());
    store.set_status_load(Load::Loading);
    shots.take("overview-loading");

    // A new node: not running, nothing paired.
    ctl.refresh_status();
    shots.take("overview-new");
    store.invoke_show(Page::Centers);
    shots.take("centers-empty");

    // Pairing through the app.
    let home = rt.block_on(FakeCenter::start(true)).unwrap();
    let lab = rt.block_on(FakeCenter::start(false)).unwrap();
    let office = rt.block_on(FakeCenter::start(false)).unwrap();
    store.invoke_pair_start();
    let link = home.link().render();
    store.set_pair_link(link.clone().into());
    store.set_pair_name("home".into());
    shots.take("pair-link");
    store.invoke_pair_check(link.into(), "home".into());
    shots.take("pair-confirm");
    store.invoke_pair_confirm();
    for (c, name) in [(&lab, "lab"), (&office, "office")] {
        run(&["center", "add", &c.link().render(), "--name", name, "--yes"]);
    }
    run(&["mode", "set", "folder", "--center", "home"]);
    run(&["center", "grant", "settings", "write", "--center", "home"]);
    run(&["mode", "set", "user", "--for", "8", "--center", "lab"]);
    run(&["center", "pause", "--center", "office"]);
    // lab's center went away.
    run(&["config", "set", "center.lab.url", "http://127.0.0.1:9"]);
    drop(lab);

    // Calls the centers made, as the node records them.
    let home_dir = "/home/alex";
    decided(
        &paths,
        3 * 86_400_000,
        "lab",
        ("exec", "run"),
        "make release",
        None,
    );
    decided(
        &paths,
        26 * 3_600_000,
        "office",
        ("fs", "list"),
        &format!("{home_dir}/Documents"),
        Some("no allow rule matches /home/alex/Documents"),
    );
    decided(
        &paths,
        3 * 3_600_000,
        "home",
        ("fs", "read"),
        &format!("{home_dir}/projects/site/README.md"),
        None,
    );
    decided(
        &paths,
        52 * 60_000,
        "home",
        ("exec", "run"),
        "git push --force origin main",
        Some("the command \"git push --force origin main\" is denied (exec.run:git push --force*)"),
    );
    decided(
        &paths,
        14 * 60_000,
        "home",
        ("exec", "run"),
        "sudo systemctl restart nginx",
        Some("no sudo allow entry matches the command \"sudo systemctl restart nginx\""),
    );
    decided(
        &paths,
        5 * 60_000,
        "home",
        ("fs", "write"),
        &format!("{home_dir}/projects/site/dist/index.html"),
        None,
    );
    decided(
        &paths,
        2 * 60_000,
        "home",
        ("exec", "run"),
        "cargo test --workspace",
        Some("no allow rule matches the command \"cargo test --workspace\""),
    );

    // The node runs, and links to home; lab cannot be reached, office waits.
    let mut opts = NodeOptions::new(paths.clone());
    opts.home = root.to_path_buf();
    opts.exe = Some(env!("CARGO_BIN_EXE_nerve-node-gui").into());
    opts.full_rights = Some(false);
    opts.cgroups = Some(Err(
        "the node runs outside a cgroup it may manage; start it as the installed service, or under systemd-run --user --scope -p Delegate=yes".into(),
    ));
    let node = rt.block_on(Daemon::start(opts)).unwrap();
    for _ in 0..100 {
        let s = run(&["status"]);
        let up = |n: &str| {
            s["centers"].as_array().unwrap().iter().any(|c| {
                c["name"] == n
                    && c["status"]
                        .as_str()
                        .is_some_and(|t| t != "connecting" && t != "not connected")
            })
        };
        if up("home") && up("lab") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    store.invoke_show(Page::Overview);
    shots.take("overview");
    store.invoke_show(Page::Centers);
    shots.take("centers");
    store.invoke_center_unpair("office".into());
    shots.take("centers-unpair");
    store.set_confirm_open(false);

    store.invoke_show(Page::Audit);
    shots.take("audit");
    let rows = store.get_audit();
    let push = (0..slint::Model::row_count(&rows))
        .find(|i| slint::Model::row_data(&rows, *i).unwrap().target == "cargo test --workspace")
        .unwrap();
    store.invoke_audit_rule(push as i32, "allow".into(), true);
    shots.take_as_is("audit-rule-added");
    store.set_toast_shown(false);
    store.invoke_audit_filter(true);
    shots.take("audit-refused");
    store.invoke_audit_filter(false);

    store.invoke_panic();
    store.invoke_show(Page::Overview);
    store.set_toast_shown(false);
    shots.take("overview-locked");
    store.invoke_unlock();
    store.set_toast_shown(false);

    for (page, name) in [
        (Page::Policy, "policy"),
        (Page::Log, "log"),
        (Page::Settings, "settings"),
        (Page::Help, "help"),
    ] {
        store.invoke_show(page);
        shots.take(name);
    }
    store.invoke_show(Page::Overview);
    store.set_about_open(true);
    shots.take("about");
    store.set_about_open(false);

    // A node.toml changed by hand: the CLI refuses it, and the app says so.
    rt.block_on(node.stop());
    let file = paths.config_file();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("mode = \"folder\"", "mode = \"user\"")).unwrap();
    store.invoke_show(Page::Centers);
    shots.take("centers-error");
    drop((home, office));
}
