//! The Settings page: the machine's name and where its keys live (`config`),
//! the proxy, the relay, backups, and any setting by its name.

use std::rc::Rc;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Pending, messages};
use crate::{Load, Pick, Prefs, Tone, view};

impl Ctl {
    pub(super) fn prefs_load(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
        self.with_prefs(|p| {
            p.set_name_shown(host.as_str().into());
            p.set_load(Load::Loading);
        });
        self.job(
            |r| {
                (
                    r.run(&["config", "get", "node.name"]),
                    r.run(&["config", "get", "machine.secret_storage"]),
                    r.run(&["proxy", "ls"]),
                    r.run(&["relay", "ls"]),
                    r.run(&["config", "get", "machine.user"]),
                )
            },
            |c, (name, storage, proxy, relay, account)| {
                // A setting that is not set has its default: no name, keys
                // in files.
                let name = name
                    .ok()
                    .and_then(|v| v["value"].as_str().map(str::to_string))
                    .unwrap_or_default();
                if let Ok(v) = &storage {
                    c.keyring_state(v);
                }
                let keyring = storage.is_ok_and(|v| v["value"] == "keyring");
                let all = proxy.and_then(|p| Ok((p, relay?)));
                // Not set: no account, and the node runs no command.
                let account = account
                    .ok()
                    .and_then(|v| v["value"].as_str().map(str::to_string))
                    .unwrap_or_default();
                c.with_prefs(|p| {
                    p.set_name(name.into());
                    p.set_storage(i32::from(keyring));
                    p.set_account(account.into());
                });
                match all {
                    Ok((proxy, relay)) => {
                        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
                        let headers: Vec<String> = proxy["headers"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|h| h.as_str().map(str::to_string))
                            .collect();
                        c.with_prefs(|p| {
                            p.set_proxy(s(&proxy["proxy"]).into());
                            p.set_proxy_pin(s(&proxy["pin"]).into());
                            p.set_proxy_login(s(&proxy["login"]).into());
                            p.set_proxy_headers(headers.join(", ").into());
                            p.set_proxy_problem(s(&proxy["problem"]).into());
                            p.set_relay_listen(s(&relay["listen"]).into());
                            p.set_relay_status(s(&relay["status"]).into());
                            p.set_relay_pin(s(&relay["pin"]).into());
                            p.set_relay_nodes(ModelRc::new(VecModel::from(view::relay_nodes(
                                &relay,
                            ))));
                            p.set_load(Load::Ready);
                            p.set_error(SharedString::new());
                        });
                    }
                    Err(e) => {
                        c.with_prefs(|p| {
                            p.set_load(Load::Failed);
                            p.set_error(e.into());
                        });
                    }
                }
            },
        );
    }

    /// A change on the Settings page: says `said` (or what the command
    /// said, when `said` is empty), then reads the page again.
    fn prefs_change(self: &Rc<Self>, args: Vec<String>, input: Option<String>, said: String) {
        self.command(args, input, move |c, answer| {
            match answer {
                Ok(v) => c.done(&v, said),
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.prefs_load();
            c.refresh_status();
        });
    }

    fn name_save(self: &Rc<Self>, name: &str) {
        let name = name.trim();
        let args = if name.is_empty() {
            vec!["config".into(), "unset".into(), "node.name".into()]
        } else {
            vec![
                "config".into(),
                "set".into(),
                "node.name".into(),
                name.into(),
            ]
        };
        self.prefs_change(
            args,
            None,
            "The name is saved; centers see it at the next link.".into(),
        );
    }

    fn storage_set(self: &Rc<Self>, i: i32) {
        let to = if i == 1 { "keyring" } else { "file" };
        let args = vec![
            "config".into(),
            "set".into(),
            "machine.secret_storage".into(),
            to.into(),
        ];
        self.prefs_change(args, None, String::new());
    }

    fn proxy_edit(&self) {
        self.with_prefs(|p| {
            p.set_proxy_new_url(p.get_proxy());
            p.set_proxy_new_pin(p.get_proxy_pin());
            p.set_proxy_new_headers(SharedString::new());
            p.set_proxy_new_password(SharedString::new());
            p.set_proxy_error(SharedString::new());
            p.set_proxy_open(true);
        });
    }

    fn proxy_set(self: &Rc<Self>) {
        let Some((url, pin, headers, password)) = self.with_prefs(|p| {
            (
                p.get_proxy_new_url().trim().to_string(),
                p.get_proxy_new_pin().trim().to_string(),
                p.get_proxy_new_headers().to_string(),
                p.get_proxy_new_password().to_string(),
            )
        }) else {
            return;
        };
        // The password and the header values go on stdin, never as
        // arguments, which every process of the machine can read.
        let (url, password) = view::proxy_login(&url, &password);
        let mut args = vec!["proxy".into(), "set".into(), url];
        if !pin.is_empty() {
            args.push("--pin".into());
            args.push(pin);
        }
        let headers: Vec<&str> = headers
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let mut input = Vec::new();
        if let Some(pw) = password {
            args.push("--password-stdin".into());
            input.push(pw);
        }
        if !headers.is_empty() {
            args.push("--headers-stdin".into());
            input.extend(headers.iter().map(|h| h.to_string()));
        }
        let input = (!input.is_empty()).then(|| input.join("\n"));
        self.command(args, input, |c, answer| {
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_proxy_open(false);
                        p.set_proxy_new_password(SharedString::new());
                    });
                    c.done(&v, "");
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_proxy_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    /// Opens the dialog of the relayed node in row `i`: the centers this
    /// node has paired, and those the relayed node may reach, ticked.
    fn relay_edit(&self, i: usize) {
        let Some(row) = self
            .with_prefs(|p| p.get_relay_nodes().row_data(i))
            .flatten()
        else {
            return;
        };
        let reach: Vec<String> = row.centers.iter().map(|c| c.to_string()).collect();
        let mut names = self.centers.borrow().clone();
        // One it may reach that is no longer paired stays in sight.
        for c in &reach {
            if !names.contains(c) {
                names.push(c.clone());
            }
        }
        let picks: Vec<Pick> = names
            .into_iter()
            .map(|n| Pick {
                on: reach.contains(&n),
                name: n.into(),
            })
            .collect();
        self.with_prefs(|p| {
            p.set_relay_edit_name(row.name.clone());
            p.set_relay_edit_centers(ModelRc::new(VecModel::from(picks)));
            p.set_relay_edit_own(row.own_limits);
            p.set_relay_edit_links(row.max_links.to_string().into());
            p.set_relay_edit_opens(row.max_opens.to_string().into());
            p.set_relay_edit_error(SharedString::new());
            p.set_relay_edit_busy(false);
            p.set_relay_edit_open(true);
        });
    }

    fn relay_edit_pick(&self, i: usize, on: bool) {
        self.with_prefs(|p| {
            let picks = p.get_relay_edit_centers();
            if let Some(mut pick) = picks.row_data(i) {
                pick.on = on;
                picks.set_row_data(i, pick);
            }
        });
    }

    /// `relay set-centers`, then `relay set-limits`: its own limits, or the
    /// relay's again.
    fn relay_edit_save(self: &Rc<Self>) {
        let Some((name, centers, own, links, opens)) = self.with_prefs(|p| {
            (
                p.get_relay_edit_name().to_string(),
                p.get_relay_edit_centers()
                    .iter()
                    .filter(|c| c.on)
                    .map(|c| c.name.to_string())
                    .collect::<Vec<_>>(),
                p.get_relay_edit_own(),
                p.get_relay_edit_links().trim().to_string(),
                p.get_relay_edit_opens().trim().to_string(),
            )
        }) else {
            return;
        };
        let mut set_centers = vec!["relay".into(), "set-centers".into(), name.clone()];
        for c in centers {
            set_centers.push("--center".into());
            set_centers.push(c);
        }
        let mut set_limits = vec!["relay".into(), "set-limits".into(), name.clone()];
        if own {
            set_limits.extend([
                "--max-links".into(),
                links,
                "--max-opens-per-minute".into(),
                opens,
            ]);
        }
        let failed = |c: &Rc<Ctl>, e: String| {
            c.with_prefs(|p| {
                p.set_relay_edit_busy(false);
                p.set_relay_edit_error(e.into());
            });
            c.prefs_load();
        };
        self.with_prefs(|p| {
            p.set_relay_edit_busy(true);
            p.set_relay_edit_error(SharedString::new());
        });
        self.command(set_centers, None, move |c, answer| match answer {
            Ok(_) => c.command(set_limits, None, move |c, answer| match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_relay_edit_busy(false);
                        p.set_relay_edit_open(false);
                    });
                    c.done(&v, format!("{name}'s centers and limits are saved."));
                    c.prefs_load();
                }
                Err(e) => failed(c, e),
            }),
            Err(e) => failed(c, e),
        });
    }

    /// A relay change whose answer holds a token shown once.
    fn relay_token_shown(self: &Rc<Self>, args: Vec<String>, title: String) {
        self.command(args, None, move |c, answer| {
            match answer {
                Ok(v) => {
                    let mut text = view::relay_token(&v);
                    let restart = c.restart_for(&v);
                    match restart {
                        super::Restart::Soon | super::Restart::AtEnd => text.push_str(
                            "\n\nThe node restarts in a moment, so that the relay takes the token.",
                        ),
                        super::Restart::AtStart => {
                            text.push_str("\n\nThe relay takes the token when the node starts.")
                        }
                        super::Restart::No => {}
                    }
                    c.show_once(&title, &text);
                    if restart == super::Restart::Soon {
                        c.restart_soon();
                    }
                }
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.with_prefs(|p| p.set_relay_new_node(SharedString::new()));
            c.prefs_load();
        });
    }

    fn raw_get(self: &Rc<Self>) {
        let key = self
            .with_prefs(|p| p.get_raw_key().trim().to_string())
            .unwrap_or_default();
        if key.is_empty() {
            return;
        }
        self.command(
            vec!["config".into(), "get".into(), key],
            None,
            |c, answer| {
                c.with_prefs(|p| match answer {
                    Ok(v) => {
                        p.set_raw_shown(view::setting(&v["value"]).into());
                        p.set_raw_error(SharedString::new());
                    }
                    Err(e) => {
                        p.set_raw_shown(SharedString::new());
                        p.set_raw_error(e.into());
                    }
                });
            },
        );
    }

    /// `config set`, `unset`, `add` or `remove` (`verb`) of the setting
    /// the page names.
    fn raw_change(self: &Rc<Self>, verb: &'static str) {
        let Some((key, value)) = self.with_prefs(|p| {
            (
                p.get_raw_key().trim().to_string(),
                p.get_raw_value().to_string(),
            )
        }) else {
            return;
        };
        let mut args = vec!["config".into(), verb.into(), key];
        if verb != "unset" {
            args.push(value);
        }
        self.command(args, None, |c, answer| {
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_raw_value(SharedString::new());
                        p.set_raw_error(SharedString::new());
                    });
                    c.done(&v, "");
                    c.raw_get();
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_raw_error(e.into()));
                }
            }
            c.refresh_status();
        });
    }

    /// `setup --create-user NAME --account-only`: commands run as another
    /// account, made when it is not there. What the CLI warns about such an
    /// account is shown until the owner closes it.
    fn account_use(self: &Rc<Self>) {
        let Some(name) = self.with_prefs(|p| p.get_account_new().trim().to_string()) else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let args = vec![
            "setup".into(),
            "--create-user".into(),
            name.clone(),
            "--account-only".into(),
        ];
        self.account_change(args, None, format!("Commands run as {name}"));
    }

    /// `install` again with the account's new password on stdin: on
    /// Windows the service starts commands with it.
    fn account_password_save(self: &Rc<Self>) {
        let Some(password) = self.with_prefs(|p| p.get_account_password().to_string()) else {
            return;
        };
        if password.is_empty() {
            return;
        }
        // No account yet: install takes the user of the app, as at install.
        let account = self
            .with_prefs(|p| p.get_account().to_string())
            .filter(|a| !a.is_empty())
            .or_else(|| self.with_install(|i| i.get_account().to_string()))
            .unwrap_or_default();
        self.account_change(
            vec!["install".into()],
            Some(password),
            format!("The service has the new password of {account}"),
        );
    }

    fn account_change(self: &Rc<Self>, args: Vec<String>, input: Option<String>, title: String) {
        self.with_prefs(|p| {
            p.set_account_busy(true);
            p.set_account_error(SharedString::new());
        });
        self.command(args, input, move |c, answer| {
            c.with_prefs(|p| {
                p.set_account_busy(false);
                p.set_account_password(SharedString::new());
            });
            match answer {
                Ok(v) => {
                    let (_, warnings) = super::install::steps(&v);
                    // install says a password that does not log the account
                    // on as a warning, and goes on without it.
                    if let Some(no) = warnings
                        .iter()
                        .find(|w| w.starts_with("no account for commands"))
                    {
                        c.with_prefs(|p| p.set_account_error(no.as_str().into()));
                    } else if warnings.is_empty() {
                        c.with_prefs(|p| p.set_account_new(SharedString::new()));
                        c.toast(format!("{title}."), Tone::Ok);
                    } else {
                        c.with_prefs(|p| p.set_account_new(SharedString::new()));
                        c.show_once(&title, &warnings.join("\n"));
                    }
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_account_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    fn backup_choose(self: &Rc<Self>, restore: bool) {
        let chooser = self.chooser.borrow().clone();
        let what = if restore {
            Choose::OpenBackup
        } else {
            Choose::SaveBackup
        };
        self.job(
            move |_| chooser(what),
            move |c, picked| {
                let path = match picked {
                    Ok(Some(path)) => path,
                    Ok(None) => return,
                    Err(e) => return c.no_chooser(e),
                };
                let file: SharedString = path.display().to_string().into();
                c.with_prefs(|p| {
                    if restore {
                        p.set_restore_file(file);
                        p.set_restore_pass(SharedString::new());
                        p.set_restore_replace(false);
                        p.set_restore_without_proxy(false);
                        p.set_restore_in_files(false);
                        p.set_restore_error(SharedString::new());
                        p.set_restore_open(true);
                    } else {
                        p.set_backup_file(file);
                        p.set_backup_pass(SharedString::new());
                        p.set_backup_pass2(SharedString::new());
                        p.set_backup_keyring(false);
                        p.set_backup_error(SharedString::new());
                        p.set_backup_open(true);
                    }
                });
            },
        );
    }

    fn backup_confirm(self: &Rc<Self>) {
        let Some((file, pass, again, keyring)) = self.with_prefs(|p| {
            (
                p.get_backup_file().to_string(),
                p.get_backup_pass().to_string(),
                p.get_backup_pass2().to_string(),
                p.get_backup_keyring(),
            )
        }) else {
            return;
        };
        if pass != again {
            self.with_prefs(|p| p.set_backup_error("The two passphrases differ.".into()));
            return;
        }
        // The system's save dialog asked before it named a file that is
        // there.
        let mut args = vec!["backup".into(), file, "--overwrite".into()];
        if keyring {
            args.push("--include-keyring".into());
        }
        self.with_prefs(|p| p.set_backup_busy(true));
        self.command(args, Some(pass), |c, answer| {
            c.with_prefs(|p| {
                p.set_backup_busy(false);
                p.set_backup_pass(SharedString::new());
                p.set_backup_pass2(SharedString::new());
            });
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| p.set_backup_open(false));
                    c.show_once("The backup is written", &messages(&v));
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_backup_error(e.into()));
                }
            }
        });
    }

    fn restore_confirm(self: &Rc<Self>) {
        let Some((file, pass, replace, without_proxy, in_files)) = self.with_prefs(|p| {
            (
                p.get_restore_file().to_string(),
                p.get_restore_pass().to_string(),
                p.get_restore_replace(),
                p.get_restore_without_proxy(),
                p.get_restore_in_files(),
            )
        }) else {
            return;
        };
        let mut args = vec!["restore".into(), file];
        if replace {
            args.push("--replace".into());
        }
        if without_proxy {
            args.push("--without-proxy".into());
        }
        if in_files {
            args.extend(["--secret-storage".into(), "file".into()]);
        }
        // A restore never goes under a running node: the app stops the
        // service for it and starts it again after, also when the restore
        // failed.
        let running = self
            .with_store(|s| s.get_service_state() == "running")
            .unwrap_or(false);
        self.with_prefs(|p| p.set_restore_busy(true));
        if !running {
            return self.restore_run(args, pass, false);
        }
        self.command(
            vec!["service".into(), "stop".into()],
            None,
            move |c, answer| match answer {
                Ok(_) => c.restore_run(args, pass, true),
                Err(e) => {
                    c.with_prefs(|p| {
                        p.set_restore_busy(false);
                        p.set_restore_error(
                            format!("The node did not stop for the restore: {e}").into(),
                        );
                    });
                    c.refresh_service();
                }
            },
        );
    }

    /// The restore itself, then the start of the service when `start`.
    fn restore_run(self: &Rc<Self>, args: Vec<String>, pass: String, start: bool) {
        self.command(args, Some(pass), move |c, answer| {
            c.with_prefs(|p| p.set_restore_pass(SharedString::new()));
            if !start {
                let stopped = c
                    .with_store(|s| s.get_service_state() == "stopped")
                    .unwrap_or(false);
                let then = if stopped {
                    "Start the node on the Overview: it works with what is restored once it runs."
                } else {
                    "The node works with what is restored once it starts."
                };
                return c.restored(answer, then.into(), false);
            }
            c.command(
                vec!["service".into(), "start".into()],
                None,
                move |c, started| {
                    let then = match started {
                        Ok(_) => {
                            c.with_store(|s| s.set_restart_due(false));
                            "The node started again, with what is restored.".to_string()
                        }
                        Err(e) => {
                            format!("The node did not start again: {e}. Start it on the Overview.")
                        }
                    };
                    c.restored(answer, then, true);
                },
            );
        });
    }

    /// Shows what a restore did, or why it did not, with what became of
    /// the node (`then`); after an error that only when the app stopped
    /// and started it (`said_start`).
    fn restored(
        self: &Rc<Self>,
        answer: Result<serde_json::Value, String>,
        then: String,
        said_start: bool,
    ) {
        self.with_prefs(|p| p.set_restore_busy(false));
        match answer {
            Ok(v) => {
                self.with_prefs(|p| p.set_restore_open(false));
                self.show_once("The backup is restored", &view::restored(&v, &then));
            }
            Err(e) => {
                let e = if said_start {
                    format!("{e}\n{then}")
                } else {
                    e
                };
                self.with_prefs(|p| p.set_restore_error(e.into()));
            }
        }
        self.refresh_service();
        self.refresh_status();
        self.prefs_load();
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let p = window.global::<Prefs>();
    let c = ctl.clone();
    p.on_name_save(move |n| c.name_save(&n));
    let c = ctl.clone();
    p.on_storage_set(move |i| c.storage_set(i));
    let c = ctl.clone();
    p.on_proxy_edit(move || c.proxy_edit());
    let c = ctl.clone();
    p.on_proxy_set(move || c.proxy_set());
    let c = ctl.clone();
    p.on_proxy_remove(move || {
        c.prefs_change(vec!["proxy".into(), "rm".into()], None, String::new())
    });
    let c = ctl.clone();
    p.on_relay_on(move || {
        let address = c
            .with_prefs(|p| p.get_relay_address().trim().to_string())
            .unwrap_or_default();
        c.prefs_change(
            vec!["relay".into(), "set".into(), address],
            None,
            String::new(),
        );
    });
    let c = ctl.clone();
    p.on_relay_off(move || c.prefs_change(vec!["relay".into(), "off".into()], None, String::new()));
    let c = ctl.clone();
    p.on_relay_add(move || {
        let name = c
            .with_prefs(|p| p.get_relay_new_node().trim().to_string())
            .unwrap_or_default();
        let title = format!("Token for {name}");
        c.relay_token_shown(vec!["relay".into(), "add".into(), name], title);
    });
    let c = ctl.clone();
    p.on_relay_token(move |name| {
        let title = format!("New token for {name}");
        c.relay_token_shown(
            vec!["relay".into(), "token".into(), name.to_string()],
            title,
        );
    });
    let c = ctl.clone();
    p.on_relay_remove(move |name| {
        c.prefs_change(
            vec!["relay".into(), "rm".into(), name.to_string()],
            None,
            String::new(),
        )
    });
    let c = ctl.clone();
    p.on_relay_edit(move |i| c.relay_edit(i as usize));
    let c = ctl.clone();
    p.on_relay_edit_pick(move |i, on| c.relay_edit_pick(i as usize, on));
    let c = ctl.clone();
    p.on_relay_edit_save(move || c.relay_edit_save());
    let c = ctl.clone();
    p.on_raw_get(move || c.raw_get());
    let c = ctl.clone();
    p.on_raw_set(move || c.raw_change("set"));
    let c = ctl.clone();
    p.on_raw_unset(move || c.raw_change("unset"));
    let c = ctl.clone();
    p.on_raw_add(move || c.raw_change("add"));
    let c = ctl.clone();
    p.on_account_use(move || c.account_use());
    let c = ctl.clone();
    p.on_account_password_save(move || c.account_password_save());
    let c = ctl.clone();
    p.on_raw_remove(move || c.raw_change("remove"));
    let c = ctl.clone();
    p.on_accept_file(move || {
        c.confirm(
            Pending::Accept,
            "Take node.toml as it is?".into(),
            "The node refuses a node.toml changed outside nerve-node. Taking it signs the file as it is now, with every change in it: read it first.".into(),
            "Take it",
        )
    });
    let c = ctl.clone();
    p.on_backup_choose(move || c.backup_choose(false));
    let c = ctl.clone();
    p.on_backup_confirm(move || c.backup_confirm());
    let c = ctl.clone();
    p.on_restore_choose(move || c.backup_choose(true));
    let c = ctl.clone();
    p.on_restore_confirm(move || c.restore_confirm());
}
