//! The center web UI: a small page (vanilla HTML/JS/CSS built into the
//! binary) over a JSON API.
//!
//! Access: the login is a harness token, the same secret the HTTP MCP
//! endpoint takes (one from the environment or a flag, or one made here and
//! kept hashed). Without a login the page is open to this machine only, and
//! the `Host` header must name loopback so a DNS-rebound page cannot reach
//! it. Beyond loopback a login is required and the UI is served over TLS (the
//! caller sees to both). With a login every page but the login form and its
//! assets answers an unknown browser with a redirect to `/login`; the form
//! posts the token once and gets the session cookie (HttpOnly,
//! SameSite=Strict, Secure over TLS), and `POST /logout` ends it. A session
//! ends with its token: when the token is deleted, the cookie stops working.
//! Every state change needs that cookie, the `X-Nerve-CSRF` header from
//! `GET /api/session`, and a matching `Origin` when the browser sends one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nerve_proto::RpcError;
use nerve_transport::http::{self, Request, Response};
use nerve_transport::net::BoxIo;

use crate::center::{Center, Change, audit_rule};
use crate::listen::Server;
use crate::store::{PAIR_CODE_MAX_MINUTES, TokenRecord};
use crate::util::{self, now_ms};

const INDEX: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");
const APP_CSS: &str = include_str!("ui/app.css");
const LOGIN: &str = include_str!("ui/login.html");
const LOGIN_JS: &str = include_str!("ui/login.js");
const THEME_JS: &str = include_str!("ui/theme-init.js");
const ICON: &str = include_str!("ui/icon.svg");

const WRONG_TOKEN: &str = "Wrong token.";
const TOO_MANY: &str = "Too many wrong tokens. Wait a minute and try again.";

pub const COOKIE: &str = "nerve_ui";
pub const CSRF_HEADER: &str = "x-nerve-csrf";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const API_BODY: usize = 1024 * 1024;
/// Wrong tokens allowed per minute before logins pause.
const LOGIN_TRIES: u32 = 5;

struct UiSession {
    csrf: String,
    created: Instant,
    /// SHA-256 (hex) of the token that logged in; none without a login.
    via: Option<String>,
}

pub struct Ui {
    center: Center,
    /// The token from the environment or a flag, besides the stored ones.
    env_token: Option<String>,
    login: bool,
    secure: bool,
    sessions: Mutex<HashMap<String, UiSession>>,
    failures: Mutex<(u32, Instant)>,
}

impl Ui {
    /// `login` is required unless the UI only listens on loopback; `secure`
    /// is whether it is served over TLS. `env_token` is the harness token
    /// from the environment or a flag, if any.
    pub fn new(center: &Center, env_token: Option<String>, login: bool, secure: bool) -> Arc<Ui> {
        Arc::new(Ui {
            center: center.clone(),
            env_token: env_token.filter(|t| !t.is_empty()),
            login,
            secure,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new((0, Instant::now())),
        })
    }

    pub async fn serve(self: Arc<Self>, server: Server) {
        server
            .run(move |io, _| {
                let me = self.clone();
                async move { me.conn(io).await }
            })
            .await
    }

    async fn conn(&self, mut io: BoxIo) {
        let resp = match http::read_request(&mut io, API_BODY).await {
            Ok(req) => self.request(req).await,
            Err(_) => Response::text(400, "bad request"),
        };
        let _ = with_security_headers(resp).write(&mut io).await;
    }

    /// Answers one request.
    pub async fn request(&self, req: Request) -> Response {
        if !self.login && !host_is_loopback(req.header("host")) {
            return Response::text(403, "this UI answers only to a loopback host name");
        }
        // What the login form needs to draw itself is public.
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/app.css") => return Response::new(200, "text/css; charset=utf-8", APP_CSS),
            ("GET", "/theme-init.js") => {
                return Response::new(200, "text/javascript; charset=utf-8", THEME_JS);
            }
            ("GET", "/login.js") => {
                return Response::new(200, "text/javascript; charset=utf-8", LOGIN_JS);
            }
            ("GET", "/icon.svg") => return Response::new(200, "image/svg+xml", ICON),
            _ => {}
        }
        if req.method == "POST"
            && let Some(o) = req.header("origin")
            && !crate::mcp::origin_matches(o, req.header("host"))
        {
            return Response::text(403, "cross-origin requests are refused");
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/login") => return self.login_page(&req),
            ("POST", "/login") => return self.login(&req).await,
            ("POST", "/logout") => return self.logout(&req),
            ("GET", "/api/session") => return self.session_info(&req),
            _ => {}
        }
        let session = self.session_of(&req);
        if !req.path.starts_with("/api/") {
            if req.method != "GET" {
                return Response::text(404, "not found");
            }
            // Not signed in: whatever was asked for, the answer is the login.
            if self.login && session.is_none() {
                return see_other("/login");
            }
            return match req.path.as_str() {
                "/" | "/index.html" => Response::new(200, "text/html; charset=utf-8", INDEX),
                "/app.js" => Response::new(200, "text/javascript; charset=utf-8", APP_JS),
                _ => Response::text(404, "not found"),
            };
        }
        let Some(token) = session else {
            return Response::json(401, &json!({"error": "log in first"}));
        };
        if req.method == "POST" {
            let csrf = self
                .sessions
                .lock()
                .unwrap()
                .get(&token)
                .map(|s| s.csrf.clone());
            let given = req.header(CSRF_HEADER).unwrap_or("");
            if !csrf.is_some_and(|c| util::ct_eq(c.as_bytes(), given.as_bytes())) {
                return Response::json(
                    403,
                    &json!({"error": "the CSRF header is missing or wrong"}),
                );
            }
        }
        let body: Value = if req.body.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => return Response::json(400, &json!({"error": format!("bad JSON: {e}")})),
            }
        };
        match self.api(&req, &body).await {
            Ok(v) => Response::json(200, &v),
            Err((status, v)) => Response::json(status, &v),
        }
    }

    fn session_of(&self, req: &Request) -> Option<String> {
        let token = cookie(req, COOKIE)?;
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, v| {
            v.created.elapsed() < SESSION_TTL
                && v.via.as_deref().is_none_or(|h| {
                    crate::mcp::token_hash_ok(&self.center, self.env_token.as_deref(), h)
                })
        });
        s.contains_key(&token).then_some(token)
    }

    /// Starts a session; `via` is the SHA-256 (hex) of the token that logged in.
    fn new_session(&self, via: Option<String>) -> (String, String) {
        let token = nerve_transport::keys::random_token(32);
        let csrf = nerve_transport::keys::random_token(32);
        self.sessions.lock().unwrap().insert(
            token.clone(),
            UiSession {
                csrf: csrf.clone(),
                created: Instant::now(),
                via,
            },
        );
        (token, csrf)
    }

    fn set_cookie(&self, token: &str) -> String {
        format!(
            "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            SESSION_TTL.as_secs(),
            if self.secure { "; Secure" } else { "" }
        )
    }

    fn clear_cookie(&self) -> String {
        format!(
            "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            if self.secure { "; Secure" } else { "" }
        )
    }

    fn session_info(&self, req: &Request) -> Response {
        if let Some(t) = self.session_of(req) {
            let csrf = self
                .sessions
                .lock()
                .unwrap()
                .get(&t)
                .map(|s| s.csrf.clone());
            return Response::json(
                200,
                &json!({"login": self.login, "logged_in": true, "csrf": csrf}),
            );
        }
        if self.login {
            return Response::json(200, &json!({"login": true, "logged_in": false}));
        }
        // Open on loopback: a session is handed out so the CSRF check still
        // ties every change to this page.
        let (token, csrf) = self.new_session(None);
        Response::json(
            200,
            &json!({"login": false, "logged_in": true, "csrf": csrf}),
        )
        .with_header("Set-Cookie", &self.set_cookie(&token))
    }

    /// The login form, or the page itself when there is nothing to log in to
    /// or the browser is in already.
    fn login_page(&self, req: &Request) -> Response {
        if !self.login || self.session_of(req).is_some() {
            return see_other("/");
        }
        login_form(200, None)
    }

    /// Checks the token the login form posted. The form is a plain browser
    /// post, so the answer is a redirect with the cookie, or the form again
    /// with the reason; the token never appears in a URL or a log.
    async fn login(&self, req: &Request) -> Response {
        if !self.login {
            return see_other("/");
        }
        {
            let mut f = self.failures.lock().unwrap();
            if f.1.elapsed() > Duration::from_secs(60) {
                *f = (0, Instant::now());
            }
            if f.0 >= LOGIN_TRIES {
                return login_form(429, Some(TOO_MANY)).with_header("Retry-After", "60");
            }
        }
        // A pasted token often carries a trailing newline or space.
        let given = req.form_param("token").unwrap_or_default();
        let given = given.trim();
        if given.is_empty() || !crate::mcp::token_ok(&self.center, self.env_token.as_deref(), given)
        {
            self.failures.lock().unwrap().0 += 1;
            tokio::time::sleep(Duration::from_millis(300)).await;
            return login_form(401, Some(WRONG_TOKEN));
        }
        let (token, _) = self.new_session(Some(util::sha256_hex(given.as_bytes())));
        see_other("/").with_header("Set-Cookie", &self.set_cookie(&token))
    }

    /// Ends the browser's session and clears its cookie.
    fn logout(&self, req: &Request) -> Response {
        if let Some(t) = self.session_of(req) {
            self.sessions.lock().unwrap().remove(&t);
        }
        // Without a login the UI has none to go back to.
        let back = if self.login { "/login" } else { "/" };
        see_other(back).with_header("Set-Cookie", &self.clear_cookie())
    }

    async fn api(&self, req: &Request, b: &Value) -> Result<Value, (u16, Value)> {
        let c = &self.center;
        let s = |k: &str| b.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/overview") => Ok(json!({
                "center": {"id": c.id(), "name": c.name(), "url": c.public_url().to_string(), "pin": c.pin()},
                "nodes": c.nodes_json(),
                "alerts": c.alerts(),
                "sessions": c.sessions_json(),
            })),
            ("GET", "/api/stats") => Ok(c.stats_json()),
            ("GET", "/api/audit") => Ok(json!({"decisions": c.audit()})),
            // The node's own command list, read from its CLI definition.
            ("GET", "/api/help") => Ok(json!({"node": nerve_node::cli::help()})),
            ("POST", "/api/pair") => Ok(c.new_pairing()),
            ("POST", "/api/nodes/rename") => c
                .rename(&s("id"), &s("name"))
                .map(|_| json!({}))
                .map_err(bad),
            ("POST", "/api/nodes/remove") => {
                c.remove(&s("id")).await.map(|_| json!({})).map_err(bad)
            }
            ("POST", "/api/sessions/end") => {
                if c.end_session(&s("id")).await {
                    Ok(json!({}))
                } else {
                    Err(bad("no such session"))
                }
            }
            ("GET", "/api/nodes/settings") => {
                let id = req.query_param("id").unwrap_or_default();
                c.node_settings(&id).await.map_err(refused)
            }
            ("POST", "/api/nodes/settings") => c
                .set_node_settings(
                    &s("id"),
                    b.get("document").cloned().unwrap_or(Value::Null),
                    b.get("if_version").cloned().unwrap_or(Value::Null),
                )
                .await
                .map_err(refused),
            ("POST", "/api/nodes/sudo/offer") => c.node_sudo_offer(&s("id")).await.map_err(refused),
            ("POST", "/api/nodes/sudo") => c
                .set_node_sudo(
                    &s("id"),
                    b.get("on").and_then(Value::as_bool).unwrap_or(false),
                    b.get("sealed").cloned().filter(|v| !v.is_null()),
                )
                .await
                .map_err(refused),
            // The four buttons of an audit entry: `list` is allow, deny, or
            // sudo for a sudo command; `cap`, `action` and `target` are the
            // entry's own fields.
            ("POST", "/api/audit/rule") => {
                let wildcard = b.get("wildcard").and_then(Value::as_bool) == Some(true);
                let rule = audit_rule(&s("list"), &s("cap"), &s("action"), &s("target"), wildcard)
                    .map_err(bad)?;
                c.add_rule(&s("node_id"), &s("list"), &rule)
                    .await
                    .map(|v| json!({"rule": rule, "result": v}))
                    .map_err(refused)
            }
            ("GET", "/api/tokens") => Ok(c.read(|st| {
                json!(
                    st.harness_tokens
                        .iter()
                        .map(|t| json!({"id": t.id, "label": t.label, "created_ms": t.created_ms}))
                        .collect::<Vec<_>>()
                )
            })),
            ("POST", "/api/tokens/create") => {
                let label = util::clip(s("label").trim(), 60);
                let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
                let rec = TokenRecord {
                    id: nerve_transport::keys::random_token(12),
                    label: if label.is_empty() {
                        "harness".into()
                    } else {
                        label
                    },
                    hash: util::sha256_hex(token.as_bytes()),
                    created_ms: now_ms(),
                };
                let id = rec.id.clone();
                c.update(|st| st.harness_tokens.push(rec));
                // The token is shown once; only its hash is kept.
                Ok(json!({"id": id, "token": token}))
            }
            ("POST", "/api/tokens/delete") => {
                let id = s("id");
                c.update(|st| st.harness_tokens.retain(|t| t.id != id));
                Ok(json!({}))
            }
            ("GET", "/api/center") => Ok(c.read(|st| {
                json!({
                    "name": st.center_name,
                    "retention_days": st.retention_days,
                    "pair_code_minutes": st.pair_code_minutes,
                })
            })),
            ("POST", "/api/center") => {
                let name = b
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|n| n.trim().to_string());
                if name.as_ref().is_some_and(|n| n.is_empty() || n.len() > 64) {
                    return Err(bad("a center name is 1 to 64 characters"));
                }
                let days = b.get("retention_days").and_then(Value::as_u64);
                if days.is_some_and(|d| !(1..=366).contains(&d)) {
                    return Err(bad("retention is 1 to 366 days"));
                }
                // A value that is not a whole number is refused too, not skipped.
                let minutes = match b.get("pair_code_minutes") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_u64() {
                        Some(m) if (1..=u64::from(PAIR_CODE_MAX_MINUTES)).contains(&m) => Some(m),
                        _ => {
                            return Err(bad(format!(
                                "a pairing code is valid for 1 to {PAIR_CODE_MAX_MINUTES} minutes (24 hours)"
                            )));
                        }
                    },
                };
                c.update(|st| {
                    if let Some(n) = name {
                        st.center_name = n;
                    }
                    if let Some(d) = days {
                        st.retention_days = d as u32;
                    }
                    if let Some(m) = minutes {
                        st.pair_code_minutes = m as u32;
                    }
                });
                c.changed(Change::Nodes);
                Ok(json!({}))
            }
            _ => Err((404, json!({"error": "unknown API call"}))),
        }
    }
}

fn bad(m: impl Into<String>) -> (u16, Value) {
    (400, json!({"error": m.into()}))
}

/// A node's refusal, with its code and reason, for the UI to show.
fn refused(e: RpcError) -> (u16, Value) {
    (
        409,
        json!({"error": e.message, "code": e.kind().as_str(), "data": e.data}),
    )
}

fn see_other(to: &str) -> Response {
    Response::new(303, "text/plain; charset=utf-8", Vec::new()).with_header("Location", to)
}

/// The login page, with the reason for a refusal when there is one.
fn login_form(status: u16, error: Option<&str>) -> Response {
    let (invalid, error) = match error {
        Some(e) => (
            " aria-invalid=\"true\" aria-describedby=\"login-error\"",
            format!("<p id=\"login-error\" class=\"login-error\" role=\"alert\">{e}</p>"),
        ),
        None => ("", String::new()),
    };
    let page = LOGIN
        .replace("{{INVALID}}", invalid)
        .replace("{{ERROR}}", &error);
    Response::new(status, "text/html; charset=utf-8", page)
}

fn cookie(req: &Request, name: &str) -> Option<String> {
    req.header("cookie")?.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// Whether a `Host` header names loopback.
pub fn host_is_loopback(host: Option<&str>) -> bool {
    let Some(h) = host else { return false };
    let name = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|(n, _)| n).unwrap_or(h)
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// `Referrer-Policy: no-referrer` would make a browser send `Origin: null`
/// with the login form (and any other post), which the origin check refuses.
/// `same-origin` sends the real origin to this server and nothing elsewhere.
fn with_security_headers(r: Response) -> Response {
    r.with_header("X-Frame-Options", "DENY")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("Referrer-Policy", "same-origin")
        .with_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
        let mut h = BTreeMap::new();
        for (k, v) in headers {
            h.insert(k.to_ascii_lowercase(), v.to_string());
        }
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: h,
            body: body.as_bytes().to_vec(),
        }
    }

    fn center(dir: &std::path::Path) -> Center {
        nerve_transport::init_crypto();
        Center::open(crate::center::Options {
            state_dir: dir.to_path_buf(),
            name: Some("test".into()),
            public_url: "http://127.0.0.1:1".into(),
        })
        .unwrap()
    }

    fn set_cookie(r: &Response) -> String {
        let v = &r.headers.iter().find(|(k, _)| k == "Set-Cookie").unwrap().1;
        v.split(';').next().unwrap().to_string()
    }

    /// Every command and sub-command of the node CLI, by the words after
    /// `nerve-node`, with its explanation, read straight from clap's tree.
    fn node_commands(cmd: &clap::Command, prefix: &str, out: &mut Vec<(String, String)>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let name = format!("{prefix}{}", sub.get_name());
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            node_commands(sub, &format!("{name} "), out);
            out.push((name, about));
        }
    }

    #[tokio::test]
    async fn the_help_page_lists_every_node_command() {
        use clap::CommandFactory;
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false, false);
        let h = ("Host", "127.0.0.1:7480");
        let session = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = set_cookie(&session);
        // The page: a tab in the menu, drawn from /api/help.
        let index = ui.request(req("GET", "/", &[h, ("Cookie", &ck)], "")).await;
        let index = String::from_utf8(index.body).unwrap();
        assert!(index.contains("href=\"#help\""), "no Help tab in the menu");
        let js = ui
            .request(req("GET", "/app.js", &[h, ("Cookie", &ck)], ""))
            .await;
        let js = String::from_utf8(js.body).unwrap();
        assert!(js.contains("\"/api/help\"") && js.contains("pageHelp"));
        // The data: every command of the CLI definition, with its words, on
        // cards in sections. A noun's own command is in its card's `holds`.
        let r = ui
            .request(req("GET", "/api/help", &[h, ("Cookie", &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        let mut listed: Vec<(String, String)> = Vec::new();
        for s in body["node"]["sections"].as_array().unwrap() {
            assert!(!s["about"].as_str().unwrap().is_empty());
            for c in s["cards"].as_array().unwrap() {
                for held in c["holds"].as_array().unwrap() {
                    // Its sentence is the card's.
                    let held = held.as_str().unwrap().to_string();
                    let about = if c["name"] == held.as_str() {
                        c["about"].as_str().unwrap().to_string()
                    } else {
                        String::new()
                    };
                    listed.push((held, about));
                }
                for v in c["verbs"].as_array().unwrap() {
                    listed.push((
                        v["name"].as_str().unwrap().to_string(),
                        v["about"].as_str().unwrap().to_string(),
                    ));
                }
            }
        }
        let mut cli = Vec::new();
        node_commands(&nerve_node::cli::Cli::command(), "", &mut cli);
        assert!(cli.len() > 40, "{cli:?}");
        for (name, about) in &cli {
            assert!(!about.is_empty(), "`{name}` has no explanation");
            assert!(
                listed.contains(&(name.clone(), about.clone())),
                "`{name}` is not on the help page: {listed:?}"
            );
        }
        assert_eq!(listed.len(), cli.len());
        // The help is for a signed-in browser like every other API.
        let ui = Ui::new(&center(d.path()), Some("nrv_x".into()), true, false);
        let r = ui.request(req("GET", "/api/help", &[h], "")).await;
        assert_eq!(r.status, 401);
    }

    async fn center_settings(ui: &Ui, body: Option<Value>) -> Result<Value, (u16, Value)> {
        match body {
            Some(b) => ui.api(&req("POST", "/api/center", &[], ""), &b).await,
            None => {
                ui.api(&req("GET", "/api/center", &[], ""), &json!({}))
                    .await
            }
        }
    }

    #[tokio::test]
    async fn the_pairing_code_lifetime_is_a_setting_of_1_to_1440_minutes() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false, false);
        // Ten minutes unless the owner changes it.
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 10);
        // Within the range it is stored, and the other settings stay.
        center_settings(&ui, Some(json!({"pair_code_minutes": 1440})))
            .await
            .unwrap();
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 1440);
        assert_eq!(got["retention_days"], 30);
        // Outside it, or not a whole number, it is refused with a message and
        // the stored value stays.
        for bad_value in [json!(1441), json!(0), json!(-5), json!(1.5), json!("20")] {
            let (status, body) =
                center_settings(&ui, Some(json!({"pair_code_minutes": bad_value.clone()})))
                    .await
                    .unwrap_err();
            assert_eq!(status, 400, "{bad_value}");
            let msg = body["error"].as_str().unwrap();
            assert!(msg.contains("1 to 1440 minutes"), "{msg}");
            let got = center_settings(&ui, None).await.unwrap();
            assert_eq!(got["pair_code_minutes"], 1440, "{bad_value}");
        }
        // A refused value changes nothing else in the same request.
        let (status, _) = center_settings(
            &ui,
            Some(json!({"name": "other", "pair_code_minutes": 1441})),
        )
        .await
        .unwrap_err();
        assert_eq!(status, 400);
        assert_eq!(center_settings(&ui, None).await.unwrap()["name"], "test");
        // A save without the field leaves it alone, and it survives a restart.
        center_settings(&ui, Some(json!({"retention_days": 5})))
            .await
            .unwrap();
        drop(ui);
        drop(c);
        let ui = Ui::new(&center(d.path()), None, false, false);
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 1440);
        assert_eq!(got["retention_days"], 5);
    }

    #[test]
    fn loopback_hosts() {
        assert!(host_is_loopback(Some("127.0.0.1:7480")));
        assert!(host_is_loopback(Some("localhost")));
        assert!(host_is_loopback(Some("[::1]:7480")));
        assert!(!host_is_loopback(Some("evil.example:7480")));
        assert!(!host_is_loopback(None));
    }

    #[tokio::test]
    async fn open_ui_needs_loopback_host_cookie_and_csrf() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false, false);
        let h = ("Host", "127.0.0.1:7480");
        // A rebound name is refused.
        let r = ui
            .request(req("GET", "/api/session", &[("Host", "evil.example")], ""))
            .await;
        assert_eq!(r.status, 403);
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        assert_eq!(r.status, 200);
        let ck = set_cookie(&r);
        let csrf = serde_json::from_slice::<Value>(&r.body).unwrap()["csrf"]
            .as_str()
            .unwrap()
            .to_string();
        // No cookie, no API.
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h], ""))
                .await
                .status,
            401
        );
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h, ("Cookie", &ck)], ""))
                .await
                .status,
            200
        );
        // A change without the CSRF header, or from another origin, is refused.
        assert_eq!(
            ui.request(req("POST", "/api/pair", &[h, ("Cookie", &ck)], ""))
                .await
                .status,
            403
        );
        let r = ui
            .request(req(
                "POST",
                "/api/pair",
                &[
                    h,
                    ("Cookie", &ck),
                    ("X-Nerve-CSRF", &csrf),
                    ("Origin", "http://evil.example"),
                ],
                "",
            ))
            .await;
        assert_eq!(r.status, 403);
        let r = ui
            .request(req(
                "POST",
                "/api/pair",
                &[h, ("Cookie", &ck), ("X-Nerve-CSRF", &csrf)],
                "",
            ))
            .await;
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v["link"].as_str().unwrap().starts_with("nerve://pair?"));
    }

    const TOKEN: &str = "nrv_test-token-long";
    const HOST: (&str, &str) = ("Host", "center.example:7480");

    fn locked(dir: &std::path::Path, tls: bool) -> Arc<Ui> {
        Ui::new(&center(dir), Some(TOKEN.into()), true, tls)
    }

    fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
        r.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn body(r: &Response) -> String {
        String::from_utf8_lossy(&r.body).into_owned()
    }

    /// Posts the login form and returns the answer.
    async fn sign_in(ui: &Ui, token: &str) -> Response {
        ui.request(req(
            "POST",
            "/login",
            &[HOST, ("Content-Type", "application/x-www-form-urlencoded")],
            &format!("token={token}"),
        ))
        .await
    }

    #[tokio::test]
    async fn without_a_session_every_page_leads_to_the_login() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        for path in ["/", "/index.html", "/app.js", "/missing"] {
            let r = ui.request(req("GET", path, &[HOST], "")).await;
            assert_eq!(r.status, 303, "{path}");
            assert_eq!(header(&r, "Location"), Some("/login"), "{path}");
            assert!(r.body.is_empty());
        }
        for path in ["/api/overview", "/api/stats", "/api/audit", "/api/tokens"] {
            let r = ui.request(req("GET", path, &[HOST], "")).await;
            assert_eq!(r.status, 401, "{path}");
        }
        let r = ui.request(req("POST", "/api/pair", &[HOST], "")).await;
        assert_eq!(r.status, 401);
        let r = ui.request(req("GET", "/api/session", &[HOST], "")).await;
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            (v["login"].clone(), v["logged_in"].clone()),
            (true.into(), false.into())
        );
        assert!(header(&r, "Set-Cookie").is_none());
        // The login form and what it is drawn with stay reachable.
        let r = ui.request(req("GET", "/login", &[HOST], "")).await;
        assert_eq!(r.status, 200);
        assert!(body(&r).contains(r#"action="/login""#));
        assert!(!body(&r).contains("login-error"));
        for (path, kind) in [
            ("/app.css", "text/css"),
            ("/login.js", "text/javascript"),
            ("/theme-init.js", "text/javascript"),
            ("/icon.svg", "image/svg+xml"),
        ] {
            let r = ui.request(req("GET", path, &[HOST], "")).await;
            assert_eq!(r.status, 200, "{path}");
            assert!(header(&r, "Content-Type").unwrap().starts_with(kind));
        }
    }

    #[tokio::test]
    async fn wrong_token_is_refused_without_echoing_it() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        let r = sign_in(&ui, "not-the-secret").await;
        assert_eq!(r.status, 401);
        assert!(header(&r, "Set-Cookie").is_none());
        assert!(header(&r, "Location").is_none());
        let page = body(&r);
        assert!(page.contains(WRONG_TOKEN));
        assert!(page.contains(r#"aria-invalid="true""#));
        assert!(!page.contains("not-the-secret"));
        // An empty post is no better.
        let r = sign_in(&ui, "").await;
        assert_eq!(r.status, 401);
        assert!(header(&r, "Set-Cookie").is_none());
        let r = ui.request(req("POST", "/login", &[HOST], "")).await;
        assert_eq!(r.status, 401);
        // The token is not accepted in a URL or as JSON either.
        let mut q = req("POST", "/login", &[HOST], "");
        q.query = format!("token={TOKEN}");
        assert_eq!(ui.request(q).await.status, 401);
        let r = ui
            .request(req(
                "POST",
                "/login",
                &[HOST],
                &format!(r#"{{"token":"{TOKEN}"}}"#),
            ))
            .await;
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn correct_token_sets_the_session_cookie() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        let r = sign_in(&ui, TOKEN).await;
        assert_eq!(r.status, 303);
        assert_eq!(header(&r, "Location"), Some("/"));
        let cookie = header(&r, "Set-Cookie").unwrap().to_string();
        for part in [
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=43200",
            "Secure",
            "Path=/",
        ] {
            assert!(cookie.contains(part), "{part} missing in {cookie}");
        }
        assert!(!cookie.contains(TOKEN));
        let ck = set_cookie(&r);
        let with = [HOST, ("Cookie", ck.as_str())];
        for path in ["/", "/app.js"] {
            assert_eq!(ui.request(req("GET", path, &with, "")).await.status, 200);
        }
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            200
        );
        let r = ui.request(req("GET", "/api/session", &with, "")).await;
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["logged_in"], true);
        assert!(v["csrf"].as_str().is_some_and(|c| !c.is_empty()));
        // Signed in, the login form has nothing left to do.
        let r = ui.request(req("GET", "/login", &with, "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        // Over plain HTTP (loopback) the cookie is not marked Secure.
        let plain = locked(d.path(), false);
        let r = sign_in(&plain, TOKEN).await;
        assert!(!header(&r, "Set-Cookie").unwrap().contains("Secure"));
    }

    #[tokio::test]
    async fn the_token_is_read_from_the_form_encoding() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), Some("p&w=d x%".into()), true, true);
        let r = sign_in(&ui, "p%26w%3Dd+x%25").await;
        assert_eq!(r.status, 303);
        assert!(header(&r, "Set-Cookie").is_some());
        // The raw text is not the token.
        assert_eq!(sign_in(&ui, "p&w=d x%").await.status, 401);
    }

    #[tokio::test]
    async fn logout_clears_the_cookie_and_ends_the_session() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        let ck = set_cookie(&sign_in(&ui, TOKEN).await);
        let with = [HOST, ("Cookie", ck.as_str())];
        let r = ui.request(req("POST", "/logout", &with, "")).await;
        assert_eq!(r.status, 303);
        assert_eq!(header(&r, "Location"), Some("/login"));
        let cleared = header(&r, "Set-Cookie").unwrap();
        for part in [
            "nerve_ui=;",
            "Max-Age=0",
            "HttpOnly",
            "SameSite=Strict",
            "Secure",
        ] {
            assert!(cleared.contains(part), "{part} missing in {cleared}");
        }
        // The old cookie is dead on the server too, not just in the browser.
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            401
        );
        let r = ui.request(req("GET", "/", &with, "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/login")));
        // Logging out twice, or without a cookie, is harmless.
        let r = ui.request(req("POST", "/logout", &[HOST], "")).await;
        assert_eq!(r.status, 303);
        // Only a post logs out: a link someone else planted does not.
        let ck = set_cookie(&sign_in(&ui, TOKEN).await);
        let with = [HOST, ("Cookie", ck.as_str())];
        assert_eq!(
            ui.request(req("GET", "/logout", &with, "")).await.status,
            404
        );
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            200
        );
    }

    #[tokio::test]
    async fn login_and_logout_refuse_other_origins() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        let own = format!("https://{}", HOST.1);
        for origin in ["https://evil.example", "null", "http://center.example:1"] {
            let r = ui
                .request(req(
                    "POST",
                    "/login",
                    &[HOST, ("Origin", origin)],
                    &format!("token={TOKEN}"),
                ))
                .await;
            assert_eq!(r.status, 403, "{origin}");
            assert!(header(&r, "Set-Cookie").is_none());
        }
        // The browser's own post names this host.
        let r = ui
            .request(req(
                "POST",
                "/login",
                &[HOST, ("Origin", &own)],
                &format!("token={TOKEN}"),
            ))
            .await;
        assert_eq!(r.status, 303);
        let ck = set_cookie(&r);
        let r = ui
            .request(req(
                "POST",
                "/logout",
                &[HOST, ("Cookie", &ck), ("Origin", "https://evil.example")],
                "",
            ))
            .await;
        assert_eq!(r.status, 403);
        let r = ui
            .request(req("GET", "/api/overview", &[HOST, ("Cookie", &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
    }

    #[tokio::test]
    async fn repeated_wrong_tokens_are_throttled() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path(), true);
        for _ in 0..LOGIN_TRIES {
            assert_eq!(sign_in(&ui, "nope").await.status, 401);
        }
        // Even the right token waits until the minute is over.
        let r = sign_in(&ui, TOKEN).await;
        assert_eq!(r.status, 429);
        assert_eq!(header(&r, "Retry-After"), Some("60"));
        assert!(header(&r, "Set-Cookie").is_none());
        assert!(body(&r).contains(TOO_MANY));
    }

    #[tokio::test]
    async fn an_open_ui_has_no_login() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = ui.request(req("GET", "/", &[h], "")).await;
        assert_eq!(r.status, 200);
        let r = ui.request(req("GET", "/login", &[h], "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui.request(req("POST", "/login", &[h], "token=x")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        assert!(header(&r, "Set-Cookie").is_none());
        let r = ui.request(req("POST", "/logout", &[h], "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
    }

    #[tokio::test]
    async fn a_token_made_in_the_ui_logs_in_and_a_session_ends_with_its_deletion() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        // The token is made in the open UI, as on a fresh center.
        let open = Ui::new(&c, None, false, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = open.request(req("GET", "/api/session", &[h], "")).await;
        let (ck, csrf) = (
            set_cookie(&r),
            serde_json::from_slice::<Value>(&r.body).unwrap()["csrf"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        let made = |label: &str| {
            req(
                "POST",
                "/api/tokens/create",
                &[h, ("Cookie", &ck), ("X-Nerve-CSRF", &csrf)],
                &format!(r#"{{"label":"{label}"}}"#),
            )
        };
        let first = serde_json::from_slice::<Value>(&open.request(made("a")).await.body).unwrap();
        let (token, id) = (
            first["token"].as_str().unwrap().to_string(),
            first["id"].as_str().unwrap().to_string(),
        );
        let other = serde_json::from_slice::<Value>(&open.request(made("b")).await.body).unwrap();

        // Later, with the login on, that same token is the login.
        let ui = Ui::new(&c, None, true, true);
        assert_eq!(sign_in(&ui, "nrv_not-made-here").await.status, 401);
        let r = sign_in(&ui, &format!("  {token}\r\n")).await;
        assert_eq!(r.status, 303);
        let session = set_cookie(&r);
        let with = [HOST, ("Cookie", session.as_str())];
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            200
        );
        let csrf = serde_json::from_slice::<Value>(
            &ui.request(req("GET", "/api/session", &with, "")).await.body,
        )
        .unwrap()["csrf"]
            .as_str()
            .unwrap()
            .to_string();

        // The other token's session survives deleting this one; this one's does not.
        let ck2 = set_cookie(&sign_in(&ui, other["token"].as_str().unwrap()).await);
        let del = req(
            "POST",
            "/api/tokens/delete",
            &[HOST, ("Cookie", &session), ("X-Nerve-CSRF", &csrf)],
            &format!(r#"{{"id":"{id}"}}"#),
        );
        assert_eq!(ui.request(del).await.status, 200);
        let r = ui.request(req("GET", "/api/overview", &with, "")).await;
        assert_eq!(r.status, 401);
        let still = [HOST, ("Cookie", ck2.as_str())];
        assert_eq!(
            ui.request(req("GET", "/api/overview", &still, ""))
                .await
                .status,
            200
        );
        // The deleted token no longer logs in.
        assert_eq!(sign_in(&ui, &token).await.status, 401);
    }

    #[tokio::test]
    async fn the_flag_token_logs_in_whole_and_only_whole() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, Some("from-the-flag".into()), true, true);
        let r = sign_in(&ui, "from-the-flag").await;
        assert_eq!(r.status, 303);
        // Its session lives although no stored token backs it.
        let ck = set_cookie(&r);
        let r = ui
            .request(req("GET", "/api/overview", &[HOST, ("Cookie", &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(sign_in(&ui, "from-the-fla").await.status, 401);
        assert_eq!(sign_in(&ui, "from-the-flag-and-more").await.status, 401);
    }

    #[tokio::test]
    async fn with_the_login_off_a_token_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), Some(TOKEN.into()), false, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = ui.request(req("GET", "/login", &[h], "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui
            .request(req("POST", "/login", &[h], &format!("token={TOKEN}")))
            .await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        assert!(header(&r, "Set-Cookie").is_none());
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            (v["login"].clone(), v["logged_in"].clone()),
            (false.into(), true.into())
        );
        // Still only for this machine.
        let r = ui
            .request(req("GET", "/api/session", &[("Host", "evil.example")], ""))
            .await;
        assert_eq!(r.status, 403);
    }

    #[test]
    fn same_origin_posts_carry_their_origin() {
        let r = with_security_headers(Response::text(200, ""));
        assert_eq!(header(&r, "Referrer-Policy"), Some("same-origin"));
    }

    #[tokio::test]
    async fn tokens_are_shown_once_and_kept_hashed() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false, false);
        let h = ("Host", "localhost:7480");
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = set_cookie(&r);
        let csrf = serde_json::from_slice::<Value>(&r.body).unwrap()["csrf"]
            .as_str()
            .unwrap()
            .to_string();
        let r = ui
            .request(req(
                "POST",
                "/api/tokens/create",
                &[h, ("Cookie", &ck), ("X-Nerve-CSRF", &csrf)],
                r#"{"label":"ci"}"#,
            ))
            .await;
        let token = serde_json::from_slice::<Value>(&r.body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        let state = std::fs::read_to_string(d.path().join(crate::store::FILE)).unwrap();
        assert!(!state.contains(&token));
        assert!(state.contains(&util::sha256_hex(token.as_bytes())));
    }
}
