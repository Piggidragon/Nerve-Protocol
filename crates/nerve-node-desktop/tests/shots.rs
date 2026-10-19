//! Screenshots of every page of the app, light and dark, drawn without a
//! screen by Slint's software renderer, for judging the look: a node of its
//! own under a temporary folder, set up and paired with fake centers through
//! the app, its daemon running, and the app asking it as it does on a
//! desktop. The software renderer draws no shadows; the app on a desktop
//! does. Long pages also come whole, as `<page>-full`.
//!
//! `NERVE_DESKTOP_SHOTS=<folder> cargo test -p nerve-node-desktop --test shots -- --ignored`

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_node_desktop::app::{Choose, Ctl, Exec};
use nerve_node_desktop::broker::Launch;
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Install, Load, Logs, NodeStatus, Page, Perm, Prefs, Store};
use slint::{ComponentHandle, Model};

const WIDTH: u32 = 1180;
const HEIGHT: u32 = 780;
const SCALE: f32 = 2.0;
/// The installer's window.
const INSTALLER: (u32, u32) = (760, 640);
/// Long values, so the shots show how they fit.
const OFFICE: &str = "office-workstation-second-floor";
const LAB_URL: &str =
    "https://nerve-center.platform-engineering.internal.example.com:8443/teams/nerve";
const DEEP: &str =
    "alex/projects/clients/northwind/infrastructure/terraform/modules/networking/vpc-peering";
const LONG_RULE: &str = "docker compose -f deploy/docker-compose.production.yml --project-name northwind-platform up -d --remove-orphans";

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

    /// The page `height` logical pixels high, as `<name>-full`.
    fn take_full(&self, name: &str, height: u32) {
        self.screen.resize(
            (WIDTH as f32 * SCALE) as u32,
            (height as f32 * SCALE) as u32,
        );
        self.take(&format!("{name}-full"));
        self.screen.resize(
            (WIDTH as f32 * SCALE) as u32,
            (HEIGHT as f32 * SCALE) as u32,
        );
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

/// Waits for a command that keeps answering to bring what `done` looks for.
fn until(ctl: &Ctl, done: impl Fn() -> bool) {
    for _ in 0..80 {
        ctl.pump();
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "writes screenshots; NERVE_DESKTOP_SHOTS names the folder"]
fn every_page_light_and_dark() {
    let Some(out) = std::env::var_os("NERVE_DESKTOP_SHOTS").map(PathBuf::from) else {
        eprintln!("NERVE_DESKTOP_SHOTS is not set");
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
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
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
    let perm = window.global::<Perm>();
    let prefs = window.global::<Prefs>();
    let shots = Shots {
        screen,
        window: &window,
        out,
    };

    // Asking: the first moment of the app.
    store.set_status(NodeStatus::default());
    store.set_status_load(Load::Loading);
    shots.take("overview-loading");

    // A new node: its service stopped, nothing paired.
    store.set_service_state("stopped".into());
    store.set_service_enabled(true);
    ctl.refresh_status();
    shots.take("overview-new");
    store.invoke_show(Page::Centers);
    shots.take("centers-empty");

    // The first-run steps, as the app opens them on a new node.
    let home = rt.block_on(FakeCenter::start(true)).unwrap();
    store.invoke_setup_start();
    store.set_setup_name("build-server-basement-rack3-left".into());
    shots.take("setup-name");
    // A name the node refuses: the step says why.
    store.set_setup_name("build-server-in-the-basement-rack-3-left-side".into());
    store.invoke_setup_next();
    shots.take("setup-name-refused");
    store.set_setup_name("build-server-basement-rack3-left".into());
    store.invoke_setup_next();
    shots.take("setup-keys");
    store.invoke_setup_next();
    store.set_pair_link(home.link().render().into());
    store.set_pair_name("home".into());
    shots.take("setup-center");
    store.invoke_setup_next();
    shots.take("setup-confirm");
    store.invoke_setup_next();
    store.set_setup_mode("folder".into());
    shots.take("setup-mode");
    store.invoke_setup_next();
    shots.take("setup-done");
    store.set_setup_open(false);

    // Pairing from the Centers page.
    let lab = rt.block_on(FakeCenter::start(false)).unwrap();
    let office = rt.block_on(FakeCenter::start(false)).unwrap();
    store.invoke_pair_start();
    let link = lab.link().render();
    store.set_pair_link(link.clone().into());
    store.set_pair_name("lab".into());
    shots.take("pair-link");
    store.invoke_pair_check(link.into(), "lab".into());
    shots.take("pair-confirm");
    store.invoke_pair_confirm();
    run(&[
        "center",
        "add",
        &office.link().render(),
        "--name",
        OFFICE,
        "--yes",
    ]);
    run(&["center", "grant", "settings", "write", "--center", "home"]);
    run(&["mode", "set", "user", "--for", "8", "--center", "lab"]);
    run(&["center", "pause", "--center", OFFICE]);
    // lab's center is far away, and cannot be reached.
    run(&["config", "set", "center.lab.url", LAB_URL]);
    drop(lab);
    // home's folders and rules.
    for (folder, rights) in [
        ("alex/projects/site", vec!["+r", "+w", "+x"]),
        ("alex/Documents", vec!["+r"]),
        ("alex/scratch", vec!["+r", "+w"]),
        (DEEP, vec!["+r", "+x"]),
    ] {
        let p = root.join(folder);
        std::fs::create_dir_all(&p).unwrap();
        let p = p.display().to_string();
        let mut args = vec!["folder", "add", &p];
        args.extend(rights);
        args.extend(["--center", "home"]);
        run(&args);
    }
    for (list, rule) in [
        ("allow", "git status"),
        ("allow", "cargo test --workspace"),
        ("allow", LONG_RULE),
        ("deny", "git push --force origin main"),
        ("deny", "rm -rf /"),
        ("sudo", "sudo systemctl restart nginx"),
    ] {
        run(&["rule", "add", list, rule, "--center", "home"]);
    }
    run(&["cap", "set", "exec.signal", "off", "--center", "home"]);
    run(&["relay", "add", "laptop-2"]);

    // Calls the centers made, as the node records them.
    let alex = root.join("alex").display().to_string();
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
        OFFICE,
        ("fs", "list"),
        &format!("{alex}/Documents"),
        Some(&format!("no allow rule matches {alex}/Documents")),
    );
    decided(
        &paths,
        3 * 3_600_000,
        "home",
        ("fs", "read"),
        &format!("{alex}/projects/site/README.md"),
        None,
    );
    decided(
        &paths,
        52 * 60_000,
        "home",
        ("exec", "run"),
        "git push --force origin main",
        Some(
            "the command \"git push --force origin main\" is denied (exec.run:git push --force origin main)",
        ),
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
        11 * 60_000,
        "home",
        ("fs", "read"),
        &format!("{}/{DEEP}/main.tf", root.display()),
        None,
    );
    decided(
        &paths,
        8 * 60_000,
        "home",
        ("exec", "run"),
        &format!(
            "{LONG_RULE} && docker compose -f deploy/docker-compose.production.yml logs --tail 200 --follow api worker scheduler"
        ),
        Some(
            "no allow rule matches the command: it chains commands or holds an expression (; & | $ ` ( ) < > @ { } % ' \" # , \\, a line break, or a word such as powershell, cmd, iex or -Command); only an allow rule that names it exactly covers that",
        ),
    );
    decided(
        &paths,
        5 * 60_000,
        "home",
        ("fs", "write"),
        &format!("{alex}/projects/site/dist/index.html"),
        None,
    );
    decided(
        &paths,
        2 * 60_000,
        "home",
        ("exec", "run"),
        "npm run build",
        Some("no allow rule matches the command \"npm run build\""),
    );

    // The node runs, and links to home; lab cannot be reached, office waits.
    // The node writes its log, which the Log page shows.
    nerve_transport::log::install(nerve_transport::log::Level::Info, false);
    let mut opts = NodeOptions::new(paths.clone());
    opts.home = root.to_path_buf();
    opts.full_rights = Some(false);
    opts.exe = Some(env!("CARGO_BIN_EXE_nerve-node-desktop").into());
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
        std::thread::sleep(Duration::from_millis(100));
    }

    store.invoke_show(Page::Overview);
    store.set_service_state("running".into());
    shots.take("overview");
    store.set_busy("service-restart".into());
    shots.take("overview-service-restarting");
    store.set_busy("".into());
    store.invoke_show(Page::Centers);
    shots.take("centers");
    store.invoke_center_unpair(OFFICE.into());
    shots.take("centers-unpair");
    store.set_confirm_open(false);

    store.invoke_show(Page::Audit);
    until(&ctl, || store.get_audit().row_count() >= 7);
    shots.take("audit");
    shots.take_full("audit", 2300);
    let rows = store.get_audit();
    let build = (0..rows.row_count())
        .find(|i| rows.row_data(*i).unwrap().target == "npm run build")
        .unwrap();
    store.invoke_audit_rule(build as i32, "allow".into(), true);
    until(&ctl, || {
        store
            .get_audit()
            .row_data(0)
            .is_some_and(|r| r.kind == "settings")
    });
    shots.take_as_is("audit-rule-added");
    store.invoke_audit_filter(true);
    until(&ctl, || {
        let r = store.get_audit();
        r.row_count() > 0 && r.iter().all(|e| e.badge == "Refused")
    });
    shots.take("audit-refused");
    store.invoke_audit_filter(false);

    store.invoke_panic();
    store.invoke_show(Page::Overview);
    shots.take("overview-locked");
    store.invoke_unlock();

    // Permissions of home.
    store.invoke_show(Page::Policy);
    perm.invoke_pick(0);
    shots.take("permissions");
    shots.take_full("permissions", 2050);
    perm.invoke_mode_pick("user".into());
    perm.set_mode_timed(true);
    shots.take("permissions-mode");
    perm.set_mode_open(false);
    let picked = root.join("alex/projects/api");
    std::fs::create_dir_all(&picked).unwrap();
    ctl.set_chooser(Arc::new(move |c| {
        (c == Choose::Folder).then(|| picked.clone())
    }));
    perm.invoke_folder_choose();
    perm.set_folder_write(true);
    shots.take("permissions-folder");
    perm.set_folder_open(false);
    perm.invoke_sudo_ask();
    perm.set_sudo_password("hunter2hunter2".into());
    shots.take("permissions-sudo");
    perm.set_sudo_open(false);

    // The log the running node wrote.
    store.invoke_show(Page::Log);
    until(&ctl, || window.global::<Logs>().get_rows().row_count() >= 3);
    ctl.feed_ready();
    shots.take("log");

    window
        .global::<Install>()
        .set_program("/usr/local/bin/nerve-node-desktop".into());
    store.invoke_show(Page::Settings);
    shots.take("settings");
    shots.take_full("settings", 1900);
    prefs.invoke_proxy_edit();
    prefs.set_proxy_new_url("http://proxy.example:3128".into());
    prefs.set_proxy_new_headers("Proxy-Authorization: Bearer …".into());
    prefs.set_proxy_new_password("correct horse".into());
    shots.take("settings-proxy");
    prefs.set_proxy_open(false);
    prefs.invoke_relay_token("laptop-2".into());
    shots.take("settings-relay-token");
    prefs.set_once_open(false);
    prefs.invoke_relay_edit(0);
    prefs.invoke_relay_edit_pick(0, true);
    prefs.set_relay_edit_own(true);
    shots.take("settings-relay-node");
    prefs.set_relay_edit_open(false);
    let backup = root.join("nerve-node.backup");
    ctl.set_chooser(Arc::new(move |_| Some(backup.clone())));
    prefs.invoke_backup_choose();
    prefs.set_backup_pass("correct horse battery".into());
    prefs.set_backup_pass2("correct horse".into());
    shots.take("settings-backup");
    prefs.set_backup_open(false);

    // Settings' update and uninstall.
    let install = window.global::<Install>();
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    install.invoke_ask_update();
    shots.take("settings-update");
    let new = root.join("Downloads/nerve-node-desktop-x86_64-linux");
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    ctl.set_chooser(Arc::new(move |_| Some(new.clone())));
    install.invoke_choose_file();
    shots.take("settings-update-file");
    install.set_step("working".into());
    shots.take("settings-update-working");
    install.set_step("done".into());
    install.set_installed_version("0.0.6".into());
    install.set_did(lines(&[
        "read the new program from /home/alex/Downloads/nerve-node-desktop-x86_64-linux",
        "replaced nerve-node-desktop 0.0.5 with 0.0.6",
        "restarted the service nerve-node.service",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
    ]));
    shots.take("settings-update-done");
    install.set_update_open(false);
    install.set_did(lines(&[]));
    install.invoke_ask_uninstall();
    shots.take("settings-uninstall");
    install.set_purge(true);
    install.set_error("uninstall needs root: run `sudo nerve-node uninstall`".into());
    shots.take("settings-uninstall-failed");
    install.set_error("".into());
    install.set_step("done".into());
    install.set_did(lines(&[
        "stopped the service nerve-node.service",
        "removed the service unit /etc/systemd/system/nerve-node.service",
        "deleted /etc/nerve",
        "deleted /var/lib/nerve",
        "removed the user nerve",
        "removed Nerve from the application menu",
        "nerve:// links no longer open in Nerve",
        "removed the program /usr/local/bin/nerve-node-desktop",
    ]));
    shots.take("settings-uninstall-done");
    install.set_uninstall_open(false);
    install.set_purge(false);

    store.invoke_show(Page::Help);
    shots.take("help");
    store.invoke_show(Page::Overview);
    store.set_about_open(true);
    shots.take("about");
    store.set_about_open(false);

    // An installed node: why the app asks for administrator rights.
    ctl.needs_rights(Launch::Plain);
    shots.take("elevate");
    store.invoke_elevate_allow();

    // A node.toml changed by hand: the CLI refuses it, and the app says so.
    ctl.end();
    rt.block_on(node.stop());
    let file = paths.config_file();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("mode = \"folder\"", "mode = \"user\"")).unwrap();
    store.invoke_show(Page::Centers);
    shots.take("centers-error");

    // The installer, as the downloaded file shows it, in its own size.
    shots.screen.resize(
        (INSTALLER.0 as f32 * SCALE) as u32,
        (INSTALLER.1 as f32 * SCALE) as u32,
    );
    let install = window.global::<Install>();
    let bin = root.join("usr/local/bin/nerve-node-desktop");
    ctl.installer(Launch::Plain, &bin);
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    install.set_step("welcome".into());
    install.set_node_only(false);
    shots.take("installer-welcome");
    // The system refuses (here: no root); the step says why.
    install.invoke_install();
    shots.take("installer-failed");
    install.set_error("".into());
    install.set_windows(true);
    install.set_account("alex".into());
    install.set_program("C:\\Program Files\\Nerve\\nerve-node-desktop.exe".into());
    install.set_password("hunter2hunter2".into());
    shots.take("installer-welcome-windows");
    install.set_windows(false);
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    install.set_node_only(true);
    shots.take("installer-node-only");
    install.set_action("install".into());
    install.set_step("done".into());
    install.set_did(lines(&[
        "the user nerve is there already",
        "put the program at /usr/local/bin/nerve-node-desktop",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
        "/usr/local/bin/nerve-node is a link to /usr/local/bin/nerve-node-desktop now, so the command nerve-node runs it",
        "the service nerve-node.service runs as nerve and starts with the machine",
    ]));
    shots.take("installer-node-only-done");
    install.set_windows(true);
    install.set_did(lines(&[
        "put the program at C:\\Program Files\\Nerve\\nerve-node-desktop.exe",
        "put Nerve in the Start menu (C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Nerve.lnk)",
        "nerve:// links open in Nerve (HKEY_LOCAL_MACHINE\\Software\\Classes\\nerve)",
        "put Nerve in Apps & features, where Uninstall removes it",
        "C:\\Program Files\\Nerve\\nerve-node.exe is a link to C:\\Program Files\\Nerve\\nerve-node-desktop.exe now, so the command nerve-node runs it",
        "the service nerve-node runs",
    ]));
    shots.take("installer-node-only-done-windows");
    install.set_windows(false);
    install.set_did(lines(&[]));
    install.set_node_only(false);
    install.set_action("install".into());
    install.set_step("working".into());
    install.set_asking(true);
    shots.take("installer-asking");
    install.set_asking(false);
    shots.take("installer-working");
    install.set_step("done".into());
    install.set_did(lines(&[
        "made the user nerve (uid 991)",
        "/etc/nerve and /var/lib/nerve/state belong to nerve",
        "commands run as alex, who ran install",
        "put the program at /usr/local/bin/nerve-node-desktop",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
        "wrote the service unit /etc/systemd/system/nerve-node.service",
        "the service nerve-node.service runs as nerve and starts with the machine",
    ]));
    install.set_warnings(lines(&[
        "Warning: alex is the account that ran sudo, and a person logs in as it: a command from a center can do what you can. `sudo nerve-node setup --create-user nerve-work` makes an account only the node uses.",
    ]));
    shots.take("installer-done");
    install.set_warnings(lines(&[]));
    install.set_step("installed".into());
    install.set_installed_version("0.0.4".into());
    install.set_newer(true);
    shots.take("installer-installed");
    install.set_installed_version(install.get_version());
    install.set_newer(false);
    shots.take("installer-installed-same");
    install.invoke_ask_uninstall();
    shots.take("installer-uninstall");
    install.set_purge(true);
    shots.take("installer-uninstall-purge");
    install.set_step("done".into());
    install.set_did(lines(&[
        "stopped the service nerve-node.service",
        "removed the service unit /etc/systemd/system/nerve-node.service",
        "deleted /etc/nerve",
        "removed the user nerve",
        "removed the link /usr/local/bin/nerve-node",
        "removed Nerve from the application menu",
        "removed the program /usr/local/bin/nerve-node-desktop",
    ]));
    shots.take("installer-removed");
    install.set_action("update".into());
    install.set_installed_version("0.0.6".into());
    install.set_did(lines(&[
        "replaced nerve-node-desktop 0.0.5 with 0.0.6",
        "restarted the service nerve-node.service",
    ]));
    shots.take("installer-updated");
    drop((home, office));
}

fn lines(l: &[&str]) -> slint::ModelRc<slint::SharedString> {
    slint::ModelRc::new(slint::VecModel::from(
        l.iter()
            .map(|s| slint::SharedString::from(*s))
            .collect::<Vec<_>>(),
    ))
}
