//! The Settings page: the machine's name and where its keys live (`config`),
//! the proxy, the relay, backups, and any setting by its name.

use std::rc::Rc;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Pending, messages};
use crate::{Load, Prefs, Tone, view};

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
                )
            },
            |c, (name, storage, proxy, relay)| {
                // A setting that is not set has its default: no name, keys
                // in files.
                let name = name
                    .ok()
                    .and_then(|v| v["value"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let keyring = storage.is_ok_and(|v| v["value"] == "keyring");
                let all = proxy.and_then(|p| Ok((p, relay?)));
                c.with_prefs(|p| {
                    p.set_name(name.into());
                    p.set_storage(i32::from(keyring));
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
                Ok(v) => {
                    let said = if said.is_empty() { messages(&v) } else { said };
                    c.toast(said, Tone::Ok);
                }
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
                    c.toast(messages(&v), Tone::Ok);
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_proxy_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    /// A relay change whose answer holds a token shown once.
    fn relay_token_shown(self: &Rc<Self>, args: Vec<String>, title: String) {
        self.command(args, None, move |c, answer| {
            match answer {
                Ok(v) => c.show_once(&title, &messages(&v)),
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

    fn raw_change(self: &Rc<Self>, set: bool) {
        let Some((key, value)) = self.with_prefs(|p| {
            (
                p.get_raw_key().trim().to_string(),
                p.get_raw_value().to_string(),
            )
        }) else {
            return;
        };
        let args = if set {
            vec!["config".into(), "set".into(), key, value]
        } else {
            vec!["config".into(), "unset".into(), key]
        };
        self.command(args, None, |c, answer| {
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_raw_value(SharedString::new());
                        p.set_raw_error(SharedString::new());
                    });
                    c.toast(messages(&v), Tone::Ok);
                    c.raw_get();
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_raw_error(e.into()));
                }
            }
            c.refresh_status();
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
                let Some(path) = picked else { return };
                let file: SharedString = path.display().to_string().into();
                c.with_prefs(|p| {
                    if restore {
                        p.set_restore_file(file);
                        p.set_restore_pass(SharedString::new());
                        p.set_restore_replace(false);
                        p.set_restore_without_proxy(false);
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
        let Some((file, pass, replace, without_proxy)) = self.with_prefs(|p| {
            (
                p.get_restore_file().to_string(),
                p.get_restore_pass().to_string(),
                p.get_restore_replace(),
                p.get_restore_without_proxy(),
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
        self.with_prefs(|p| p.set_restore_busy(true));
        self.command(args, Some(pass), |c, answer| {
            c.with_prefs(|p| {
                p.set_restore_busy(false);
                p.set_restore_pass(SharedString::new());
            });
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| p.set_restore_open(false));
                    c.show_once("The backup is restored", &messages(&v));
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_restore_error(e.into()));
                }
            }
            c.refresh_status();
            c.prefs_load();
        });
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
    p.on_raw_get(move || c.raw_get());
    let c = ctl.clone();
    p.on_raw_set(move || c.raw_change(true));
    let c = ctl.clone();
    p.on_raw_unset(move || c.raw_change(false));
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
