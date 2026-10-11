//! The center web UI: a small page (vanilla HTML/JS/CSS built into the
//! binary) over a JSON API.
//!
//! Access: on loopback without a password the page is open to this machine
//! only, and the `Host` header must name loopback so a DNS-rebound page
//! cannot reach it. Beyond loopback a password is required and the UI is
//! served over TLS. Every state change needs the session cookie
//! (HttpOnly, SameSite=Strict), the `X-Nerve-CSRF` header from
//! `GET /api/session`, and a matching `Origin` when the browser sends one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nerve_proto::RpcError;
use nerve_transport::http::{self, Request, Response};
use nerve_transport::net::BoxIo;

use crate::center::{Answer, Center, Change, wildcard_of};
use crate::listen::Server;
use crate::store::{Rule, TokenRecord};
use crate::util::{self, now_ms};

const INDEX: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");
const APP_CSS: &str = include_str!("ui/app.css");

pub const COOKIE: &str = "nerve_ui";
pub const CSRF_HEADER: &str = "x-nerve-csrf";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const API_BODY: usize = 1024 * 1024;
/// Wrong passwords allowed per minute before logins pause.
const LOGIN_TRIES: u32 = 5;

struct UiSession {
    csrf: String,
    created: Instant,
}

pub struct Ui {
    center: Center,
    password: Option<String>,
    secure: bool,
    sessions: Mutex<HashMap<String, UiSession>>,
    failures: Mutex<(u32, Instant)>,
}

impl Ui {
    /// `password` is required unless the UI only listens on loopback;
    /// `secure` is whether it is served over TLS.
    pub fn new(center: &Center, password: Option<String>, secure: bool) -> Arc<Ui> {
        Arc::new(Ui {
            center: center.clone(),
            password: password.filter(|p| !p.is_empty()),
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
        if self.password.is_none() && !host_is_loopback(req.header("host")) {
            return Response::text(403, "this UI answers only to a loopback host name");
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => {
                return Response::new(200, "text/html; charset=utf-8", INDEX);
            }
            ("GET", "/app.js") => {
                return Response::new(200, "text/javascript; charset=utf-8", APP_JS);
            }
            ("GET", "/app.css") => return Response::new(200, "text/css; charset=utf-8", APP_CSS),
            _ => {}
        }
        if !req.path.starts_with("/api/") {
            return Response::text(404, "not found");
        }
        if req.method == "POST"
            && let Some(o) = req.header("origin")
            && !crate::mcp::origin_matches(o, req.header("host"))
        {
            return Response::text(403, "cross-origin requests are refused");
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/session") => return self.session_info(&req),
            ("POST", "/api/login") => return self.login(&req).await,
            _ => {}
        }
        let Some(token) = self.session_of(&req) else {
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
        match self.api(&req, &token, &body).await {
            Ok(v) => Response::json(200, &v),
            Err((status, v)) => Response::json(status, &v),
        }
    }

    fn session_of(&self, req: &Request) -> Option<String> {
        let token = cookie(req, COOKIE)?;
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, v| v.created.elapsed() < SESSION_TTL);
        s.contains_key(&token).then_some(token)
    }

    fn new_session(&self) -> (String, String) {
        let token = nerve_transport::keys::random_token(32);
        let csrf = nerve_transport::keys::random_token(32);
        self.sessions.lock().unwrap().insert(
            token.clone(),
            UiSession {
                csrf: csrf.clone(),
                created: Instant::now(),
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
                &json!({"password": self.password.is_some(), "logged_in": true, "csrf": csrf}),
            );
        }
        if self.password.is_some() {
            return Response::json(200, &json!({"password": true, "logged_in": false}));
        }
        // Open on loopback: a session is handed out so the CSRF check still
        // ties every change to this page.
        let (token, csrf) = self.new_session();
        Response::json(
            200,
            &json!({"password": false, "logged_in": true, "csrf": csrf}),
        )
        .with_header("Set-Cookie", &self.set_cookie(&token))
    }

    async fn login(&self, req: &Request) -> Response {
        let Some(want) = &self.password else {
            return Response::json(400, &json!({"error": "this UI has no password"}));
        };
        {
            let mut f = self.failures.lock().unwrap();
            if f.1.elapsed() > Duration::from_secs(60) {
                *f = (0, Instant::now());
            }
            if f.0 >= LOGIN_TRIES {
                return Response::json(
                    429,
                    &json!({"error": "too many wrong passwords; wait a minute"}),
                );
            }
        }
        let given = serde_json::from_slice::<Value>(&req.body)
            .ok()
            .and_then(|v| {
                v.get("password")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        if !util::ct_eq(
            util::sha256_hex(want.as_bytes()).as_bytes(),
            util::sha256_hex(given.as_bytes()).as_bytes(),
        ) {
            self.failures.lock().unwrap().0 += 1;
            tokio::time::sleep(Duration::from_millis(300)).await;
            return Response::json(403, &json!({"error": "wrong password"}));
        }
        let (token, csrf) = self.new_session();
        Response::json(
            200,
            &json!({"password": true, "logged_in": true, "csrf": csrf}),
        )
        .with_header("Set-Cookie", &self.set_cookie(&token))
    }

    async fn api(&self, req: &Request, token: &str, b: &Value) -> Result<Value, (u16, Value)> {
        let c = &self.center;
        let s = |k: &str| b.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/api/logout") => {
                self.sessions.lock().unwrap().remove(token);
                Ok(json!({}))
            }
            ("GET", "/api/overview") => Ok(json!({
                "center": {"id": c.id(), "name": c.name(), "url": c.public_url().to_string(), "pin": c.pin()},
                "nodes": c.nodes_json(),
                "alerts": c.alerts(),
                "approvals": c.center_approvals(),
                "sessions": c.sessions_json(),
            })),
            ("GET", "/api/stats") => Ok(c.stats_json()),
            ("GET", "/api/audit") => Ok(json!({"decisions": c.audit()})),
            ("POST", "/api/pair") => Ok(c.new_pairing()),
            ("POST", "/api/nodes/rename") => c.rename(&s("id"), &s("name")).map(|_| json!({})).map_err(bad),
            ("POST", "/api/nodes/remove") => c.remove(&s("id")).await.map(|_| json!({})).map_err(bad),
            ("POST", "/api/approvals/center") => {
                let a = Answer::parse(&s("answer")).ok_or_else(|| bad("the answer is once, session or deny"))?;
                if c.answer_center(&s("id"), a) {
                    Ok(json!({}))
                } else {
                    Err(bad("this approval is no longer open"))
                }
            }
            ("POST", "/api/approvals/node") => {
                let minutes = b.get("minutes").and_then(Value::as_u64);
                c.answer_node(&s("node_id"), &s("id"), &s("answer"), minutes)
                    .await
                    .map(|_| json!({}))
                    .map_err(refused)
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
                .set_node_settings(&s("id"), b.get("document").cloned().unwrap_or(Value::Null), b.get("if_version").cloned().unwrap_or(Value::Null))
                .await
                .map_err(refused),
            ("POST", "/api/audit/rule") => {
                let command = s("command");
                if command.trim().is_empty() {
                    return Err(bad("no command"));
                }
                let pattern = if b.get("wildcard").and_then(Value::as_bool) == Some(true) {
                    wildcard_of(&command)
                } else {
                    command
                };
                c.add_command_rule(&s("node_id"), &s("list"), &pattern)
                    .await
                    .map(|v| json!({"pattern": pattern, "result": v}))
                    .map_err(refused)
            }
            ("GET", "/api/tokens") => Ok(c.read(|st| {
                json!(st.harness_tokens.iter().map(|t| json!({"id": t.id, "label": t.label, "created_ms": t.created_ms})).collect::<Vec<_>>())
            })),
            ("POST", "/api/tokens/create") => {
                let label = util::clip(s("label").trim(), 60);
                let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
                let rec = TokenRecord {
                    id: nerve_transport::keys::random_token(12),
                    label: if label.is_empty() { "harness".into() } else { label },
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
                json!({"name": st.center_name, "retention_days": st.retention_days, "effects": st.center_policy.effects, "call_wait_s": c.call_wait().as_secs()})
            })),
            ("POST", "/api/center") => {
                let name = b.get("name").and_then(Value::as_str).map(|n| n.trim().to_string());
                if name.as_ref().is_some_and(|n| n.is_empty() || n.len() > 64) {
                    return Err(bad("a center name is 1 to 64 characters"));
                }
                let days = b.get("retention_days").and_then(Value::as_u64);
                if days.is_some_and(|d| !(1..=366).contains(&d)) {
                    return Err(bad("retention is 1 to 366 days"));
                }
                let effects: Option<Vec<(String, Rule)>> = match b.get("effects") {
                    None => None,
                    Some(e) => Some(parse_effects(e).map_err(bad)?),
                };
                c.update(|st| {
                    if let Some(n) = name {
                        st.center_name = n;
                    }
                    if let Some(d) = days {
                        st.retention_days = d as u32;
                    }
                    for (k, r) in effects.into_iter().flatten() {
                        st.center_policy.effects.insert(k, r);
                    }
                });
                c.changed(Change::Nodes);
                Ok(json!({}))
            }
            _ => Err((404, json!({"error": "unknown API call"}))),
        }
    }
}

const EFFECTS: [&str; 5] = ["read", "sense", "write", "actuate", "execute"];

fn parse_effects(v: &Value) -> Result<Vec<(String, Rule)>, String> {
    let m = v.as_object().ok_or("effects is an object")?;
    m.iter()
        .map(|(k, r)| {
            if !EFFECTS.contains(&k.as_str()) {
                return Err(format!("unknown effect {k}"));
            }
            let r: Rule = serde_json::from_value(r.clone())
                .map_err(|_| format!("the rule for {k} is on, ask or off"))?;
            Ok((k.clone(), r))
        })
        .collect()
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

fn with_security_headers(r: Response) -> Response {
    r.with_header("X-Frame-Options", "DENY")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("Referrer-Policy", "no-referrer")
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
            call_wait: Duration::from_secs(1),
        })
        .unwrap()
    }

    fn set_cookie(r: &Response) -> String {
        let v = &r.headers.iter().find(|(k, _)| k == "Set-Cookie").unwrap().1;
        v.split(';').next().unwrap().to_string()
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
        let ui = Ui::new(&center(d.path()), None, false);
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

    #[tokio::test]
    async fn password_login_and_throttle() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), Some("hunter2-long".into()), true);
        let h = ("Host", "center.example:7480");
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["logged_in"],
            false
        );
        assert!(r.headers.iter().all(|(k, _)| k != "Set-Cookie"));
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h], ""))
                .await
                .status,
            401
        );
        let r = ui
            .request(req(
                "POST",
                "/api/login",
                &[h],
                r#"{"password":"hunter2-long"}"#,
            ))
            .await;
        assert_eq!(r.status, 200);
        let ck = set_cookie(&r);
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "Set-Cookie" && v.contains("Secure"))
        );
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h, ("Cookie", &ck)], ""))
                .await
                .status,
            200
        );
        for _ in 0..LOGIN_TRIES {
            let r = ui
                .request(req("POST", "/api/login", &[h], r#"{"password":"nope"}"#))
                .await;
            assert_eq!(r.status, 403);
        }
        let r = ui
            .request(req(
                "POST",
                "/api/login",
                &[h],
                r#"{"password":"hunter2-long"}"#,
            ))
            .await;
        assert_eq!(r.status, 429);
    }

    #[tokio::test]
    async fn tokens_are_shown_once_and_kept_hashed() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
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
