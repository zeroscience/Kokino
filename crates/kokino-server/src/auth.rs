//! Accounts, sessions and access control.
//!
//! Sessions are random 192-bit ids in an HttpOnly, SameSite=Strict cookie
//! (Secure when served over TLS). State-changing requests must also carry
//! `x-requested-with: kokino`, which a cross-site form or image cannot send.
//! Failed logins back off per username and per client address.

use crate::state::{random_token, AppState};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use kokino_core::case::Access;
use kokino_core::time::now_iso;
use kokino_core::users::{check_password, hash_password, verify_password, Role, User, UserStore, UserView};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub const MAX_SESSION: Duration = Duration::from_secs(12 * 60 * 60);
/// Failed logins allowed before backoff starts, per username and per client
/// address. The address limit is higher because a shared workstation signs
/// everyone in from 127.0.0.1.
const FREE_PER_USER: u32 = 5;
const FREE_PER_ADDR: u32 = 20;
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

pub struct Session {
    pub username: String,
    created: Instant,
    last: Instant,
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Session>>,
    fails: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Sessions {
    pub fn create(&self, username: &str) -> String {
        let id = random_token();
        let now = Instant::now();
        let mut m = self.map.lock().unwrap();
        m.retain(|_, s| live(s, now));
        m.insert(id.clone(), Session { username: username.to_string(), created: now, last: now });
        id
    }

    /// Returns the session's username and refreshes its idle timer.
    fn touch(&self, id: &str) -> Option<String> {
        let now = Instant::now();
        let mut m = self.map.lock().unwrap();
        match m.get_mut(id) {
            Some(s) if live(s, now) => {
                s.last = now;
                Some(s.username.clone())
            }
            Some(_) => {
                m.remove(id);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) {
        self.map.lock().unwrap().remove(id);
    }

    /// Ends every session of `username` except `keep`.
    pub fn end_user(&self, username: &str, keep: Option<&str>) {
        self.map.lock().unwrap().retain(|id, s| s.username != username || Some(id.as_str()) == keep);
    }

    fn locked_for(&self, key: &str, free: u32) -> Option<Duration> {
        let f = self.fails.lock().unwrap();
        let (n, at) = *f.get(key)?;
        if n < free {
            return None;
        }
        let wait = Duration::from_secs(30u64.saturating_mul(1u64 << (n - free).min(10))).min(MAX_LOCKOUT);
        let left = wait.checked_sub(at.elapsed())?;
        Some(left)
    }

    /// Counts a failure. A counter starts over after MAX_LOCKOUT without failures.
    fn fail(&self, key: &str) {
        let mut f = self.fails.lock().unwrap();
        let e = f.entry(key.to_string()).or_insert((0, Instant::now()));
        if e.1.elapsed() > MAX_LOCKOUT {
            e.0 = 0;
        }
        e.0 += 1;
        e.1 = Instant::now();
    }

    fn clear(&self, key: &str) {
        self.fails.lock().unwrap().remove(key);
    }
}

fn live(s: &Session, now: Instant) -> bool {
    now.duration_since(s.last) < IDLE_TIMEOUT && now.duration_since(s.created) < MAX_SESSION
}

/// The authenticated user, available to handlers as an extension.
#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub username: String,
    pub display_name: String,
    pub role: Role,
    pub sid: String,
}

/// Effective access to one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseAccess {
    Reviewer,
    Examiner,
    Admin,
}

impl CaseAccess {
    pub fn can_write(self) -> bool {
        self >= CaseAccess::Examiner
    }
}

pub fn case_access(u: &CurrentUser, members: &std::collections::BTreeMap<String, Access>) -> Option<CaseAccess> {
    if u.role == Role::Admin {
        return Some(CaseAccess::Admin);
    }
    let a = match members.get(&u.username)? {
        Access::Examiner if u.role >= Role::Examiner => CaseAccess::Examiner,
        _ => CaseAccess::Reviewer,
    };
    Some(a)
}

pub fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

pub const COOKIE: &str = "kokino_sid";

fn cookie_sid(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{}=", COOKIE)).map(|s| s.to_string()))
}

fn set_cookie(st: &AppState, sid: &str, max_age: u64) -> HeaderValue {
    let secure = if st.tls { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}", COOKIE, sid, max_age, secure)).unwrap()
}

fn is_public(method: &Method, path: &str) -> bool {
    matches!((method.as_str(), path), ("GET", "/info") | ("POST", "/auth/login") | ("POST", "/auth/setup") | ("POST", "/auth/logout"))
}

/// Authentication, CSRF and authorization for every /api request.
pub async fn guard(State(st): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().trim_start_matches("/api").to_string();
    let method = req.method().clone();
    let writes = !matches!(method, Method::GET | Method::HEAD);

    if writes {
        let xrw = req.headers().get("x-requested-with").and_then(|v| v.to_str().ok());
        if xrw != Some("kokino") {
            return err(StatusCode::FORBIDDEN, "missing request header");
        }
    }
    if is_public(&method, &path) {
        return next.run(req).await;
    }

    let Some(sid) = cookie_sid(req.headers()) else { return err(StatusCode::UNAUTHORIZED, "not signed in") };
    let Some(username) = st.sessions.touch(&sid) else { return err(StatusCode::UNAUTHORIZED, "session expired") };
    let user = match st.users.get(&username) {
        Ok(Some(u)) if !u.disabled => u,
        _ => {
            st.sessions.remove(&sid);
            return err(StatusCode::UNAUTHORIZED, "account is disabled");
        }
    };
    if user.must_change_password && !matches!(path.as_str(), "/auth/me" | "/auth/password") {
        return err(StatusCode::FORBIDDEN, "password change required");
    }
    let cu = CurrentUser { username: user.username.clone(), display_name: user.display_name.clone(), role: user.role, sid };

    // Global permissions.
    let admin_only = path.starts_with("/users") || path.starts_with("/system") || path.ends_with("/members");
    let examiner_only = path == "/browse" || (path == "/cases" && writes);
    if (admin_only && cu.role != Role::Admin) || (examiner_only && cu.role < Role::Examiner) {
        return err(StatusCode::FORBIDDEN, "your role does not allow this");
    }

    // Per-case permissions. Unknown and unassigned cases look the same.
    if let Some(rest) = path.strip_prefix("/cases/") {
        let cid = rest.split('/').next().unwrap_or("");
        let access = st.case(cid).ok().and_then(|c| case_access(&cu, &c.info.members));
        let Some(access) = access else { return err(StatusCode::NOT_FOUND, "no such case") };
        let exports = path.ends_with("/export") || path.ends_with("/carve");
        // Reviewers may bookmark and tag; the handlers limit them to their own bookmarks.
        let bookmarking = rest.split('/').nth(1) == Some("bookmarks");
        if ((writes && !bookmarking) || exports) && !access.can_write() {
            return err(StatusCode::FORBIDDEN, "read-only access to this case");
        }
    }

    req.extensions_mut().insert(cu);
    next.run(req).await
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/setup", post(setup))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/password", post(change_password))
        .route("/users", get(list_users).post(create_user))
        .route("/users/retired", get(retired_users))
        .route("/users/{name}", patch(update_user).delete(delete_user))
        .route("/users/{name}/usage", get(user_usage))
        .route("/system/audit", get(system_audit))
}

pub(crate) fn sys_audit(st: &AppState, actor: &str, action: &str, detail: Value) {
    if let Err(e) = st.users.audit.append(actor, action, detail) {
        tracing::error!("system audit write failed: {e:#}");
    }
}

fn session_response(st: &AppState, user: &User) -> Response {
    let sid = st.sessions.create(&user.username);
    let mut res = Json(json!({ "user": UserView::from(user) })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, set_cookie(st, &sid, MAX_SESSION.as_secs()));
    res
}

#[derive(Deserialize)]
struct SetupBody {
    token: String,
    username: String,
    display_name: Option<String>,
    password: String,
}

/// Creates the first admin. Needs the setup token printed by `kokino serve`.
async fn setup(State(st): State<Arc<AppState>>, Json(b): Json<SetupBody>) -> Response {
    if !st.users.is_empty().unwrap_or(false) {
        return err(StatusCode::CONFLICT, "setup is already complete");
    }
    if !crate::state::ct_eq(b.token.trim().as_bytes(), st.setup_token.as_bytes()) {
        return err(StatusCode::FORBIDDEN, "wrong setup token; use the link printed by kokino serve");
    }
    let r = st.users.create(&b.username, b.display_name.as_deref().unwrap_or(""), Role::Admin, &b.password);
    match r {
        Ok(u) => {
            sys_audit(&st, &u.username, "user.setup", json!({"username": u.username, "role": u.role}));
            session_response(&st, &u)
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn login(State(st): State<Arc<AppState>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, Json(b): Json<LoginBody>) -> Response {
    let name = b.username.trim().to_ascii_lowercase();
    let (ukey, ikey) = (format!("u:{}", name), format!("ip:{}", addr.ip()));
    if let Some(left) = st.sessions.locked_for(&ukey, FREE_PER_USER).or_else(|| st.sessions.locked_for(&ikey, FREE_PER_ADDR)) {
        sys_audit(&st, &name, "auth.locked", json!({"from": addr.ip().to_string()}));
        return err(StatusCode::TOO_MANY_REQUESTS, &format!("too many failed attempts; try again in {} s", left.as_secs() + 1));
    }
    let users = st.users.clone();
    let (n2, pw) = (name.clone(), b.password);
    let found = tokio::task::spawn_blocking(move || users.authenticate(&n2, &pw)).await.ok().and_then(|r| r.ok()).flatten();
    match found {
        Some(u) => {
            st.sessions.clear(&ukey);
            let _ = st.users.update(|all| {
                if let Some(x) = all.iter_mut().find(|x| x.username == u.username) {
                    x.last_login = Some(now_iso());
                }
                Ok(())
            });
            sys_audit(&st, &u.username, "auth.login", json!({"from": addr.ip().to_string()}));
            session_response(&st, &u)
        }
        None => {
            st.sessions.fail(&ukey);
            st.sessions.fail(&ikey);
            sys_audit(&st, &name, "auth.fail", json!({"from": addr.ip().to_string()}));
            err(StatusCode::UNAUTHORIZED, "wrong username or password")
        }
    }
}

async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_sid(&headers) {
        if let Some(u) = st.sessions.touch(&sid) {
            sys_audit(&st, &u, "auth.logout", json!({}));
        }
        st.sessions.remove(&sid);
    }
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(header::SET_COOKIE, set_cookie(&st, "", 0));
    res
}

async fn me(State(st): State<Arc<AppState>>, Extension(cu): Extension<CurrentUser>) -> Response {
    match st.users.get(&cu.username) {
        Ok(Some(u)) => {
            let root = if u.role >= Role::Examiner { Some(st.root.display().to_string()) } else { None };
            Json(json!({"user": UserView::from(&u), "cases_root": root, "idle_timeout_s": IDLE_TIMEOUT.as_secs()})).into_response()
        }
        _ => err(StatusCode::UNAUTHORIZED, "not signed in"),
    }
}

#[derive(Deserialize)]
struct PasswordBody {
    current: String,
    new: String,
}

async fn change_password(State(st): State<Arc<AppState>>, Extension(cu): Extension<CurrentUser>, Json(b): Json<PasswordBody>) -> Response {
    if let Err(e) = check_password(&b.new) {
        return err(StatusCode::BAD_REQUEST, &format!("{e:#}"));
    }
    if b.new == b.current {
        return err(StatusCode::BAD_REQUEST, "the new password must be different");
    }
    let users = st.users.clone();
    let name = cu.username.clone();
    let res = tokio::task::spawn_blocking(move || {
        let hash = hash_password(&b.new)?;
        users.update(|all| {
            let u = all.iter_mut().find(|u| u.username == name).ok_or_else(|| anyhow::anyhow!("no such user"))?;
            if !verify_password(&u.password, &b.current) {
                anyhow::bail!("current password is wrong");
            }
            u.password = hash;
            u.must_change_password = false;
            Ok(())
        })
    })
    .await;
    match res {
        Ok(Ok(())) => {
            st.sessions.end_user(&cu.username, Some(&cu.sid));
            sys_audit(&st, &cu.username, "user.password", json!({"username": cu.username}));
            Json(json!({"ok": true})).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "password update failed"),
    }
}

async fn list_users(State(st): State<Arc<AppState>>) -> Response {
    match st.users.list() {
        Ok(v) => Json(json!(v.iter().map(UserView::from).collect::<Vec<_>>())).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    display_name: Option<String>,
    role: String,
    password: String,
}

/// Admin-created accounts must choose their own password at first login.
async fn create_user(State(st): State<Arc<AppState>>, Extension(cu): Extension<CurrentUser>, Json(b): Json<NewUser>) -> Response {
    let users = st.users.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<User> {
        let role = Role::parse(&b.role)?;
        let u = users.create(&b.username, b.display_name.as_deref().unwrap_or(""), role, &b.password)?;
        users.update(|all| {
            if let Some(x) = all.iter_mut().find(|x| x.username == u.username) {
                x.must_change_password = true;
            }
            Ok(())
        })?;
        Ok(u)
    })
    .await;
    match res {
        Ok(Ok(u)) => {
            sys_audit(&st, &cu.username, "user.create", json!({"username": u.username, "role": u.role, "display_name": u.display_name}));
            Json(json!(UserView::from(&u))).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "user creation failed"),
    }
}

/// Deleted accounts whose usernames stay reserved.
async fn retired_users(State(st): State<Arc<AppState>>) -> Response {
    match st.users.retired() {
        Ok(v) => Json(json!(v)).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

/// Where an account left traces, so the admin sees what deleting it means.
async fn user_usage(State(st): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let st2 = st.clone();
    let res = tokio::task::spawn_blocking(move || st2.users.usage(&st2.root, &name)).await;
    match res {
        Ok(Ok(v)) => Json(json!({"usage": v})).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "usage check failed"),
    }
}

#[derive(Deserialize)]
struct DeleteUser {
    /// The username typed again by the admin.
    confirm: String,
}

/// Deletes an account (see `UserStore::delete`) and ends its sessions.
async fn delete_user(State(st): State<Arc<AppState>>, Extension(cu): Extension<CurrentUser>, Path(name): Path<String>, Json(b): Json<DeleteUser>) -> Response {
    let name = name.to_ascii_lowercase();
    if b.confirm.trim().to_ascii_lowercase() != name {
        return err(StatusCode::BAD_REQUEST, "type the username to confirm the deletion");
    }
    let (st2, n2, me) = (st.clone(), name.clone(), cu.username.clone());
    let res = tokio::task::spawn_blocking(move || st2.users.delete(&st2.root, &n2, &me)).await;
    match res {
        Ok(Ok(d)) => {
            st.sessions.end_user(&name, None);
            Json(json!(d)).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "deletion failed"),
    }
}

#[derive(Deserialize)]
struct UserPatch {
    display_name: Option<String>,
    role: Option<String>,
    disabled: Option<bool>,
    password: Option<String>,
}

async fn update_user(State(st): State<Arc<AppState>>, Extension(cu): Extension<CurrentUser>, Path(name): Path<String>, Json(b): Json<UserPatch>) -> Response {
    let users = st.users.clone();
    let me = cu.username.clone();
    let target = name.to_ascii_lowercase();
    let t2 = target.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<(UserView, Value)> {
        let role = b.role.as_deref().map(Role::parse).transpose()?;
        let hash = match &b.password {
            Some(p) => {
                check_password(p)?;
                Some(hash_password(p)?)
            }
            None => None,
        };
        users.update(|all| {
            let i = all.iter().position(|u| u.username == t2).ok_or_else(|| anyhow::anyhow!("no such user"))?;
            let mut changes = serde_json::Map::new();
            if let Some(d) = &b.display_name {
                let d: String = d.trim().chars().filter(|c| !c.is_control()).take(64).collect();
                if !d.is_empty() {
                    all[i].display_name = d.clone();
                    changes.insert("display_name".into(), json!(d));
                }
            }
            if let Some(r) = role {
                all[i].role = r;
                changes.insert("role".into(), json!(r));
            }
            if let Some(dis) = b.disabled {
                if dis && t2 == me {
                    anyhow::bail!("you cannot disable your own account");
                }
                all[i].disabled = dis;
                changes.insert("disabled".into(), json!(dis));
            }
            if let Some(h) = hash {
                all[i].password = h;
                all[i].must_change_password = true;
                changes.insert("password_reset".into(), json!(true));
            }
            if UserStore::admin_count(all) == 0 {
                anyhow::bail!("at least one active admin must remain");
            }
            Ok((UserView::from(&all[i]), Value::Object(changes)))
        })
    })
    .await;
    match res {
        Ok(Ok((view, changes))) => {
            if view.disabled || changes.get("password_reset").is_some() {
                st.sessions.end_user(&target, None);
            }
            sys_audit(&st, &cu.username, "user.update", json!({"username": target, "changes": changes}));
            Json(json!(view)).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "update failed"),
    }
}

async fn system_audit(State(st): State<Arc<AppState>>) -> Response {
    let dir = kokino_core::state_dir(&st.root).join("system-audit.jsonl");
    match (kokino_core::audit::verify(&dir), st.users.audit.entries()) {
        (Ok(v), Ok(e)) => Json(json!({"verify": v, "entries": e})).into_response(),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "cannot read system audit log"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_per_user_and_address() {
        let s = Sessions::default();
        for _ in 0..FREE_PER_USER {
            assert!(s.locked_for("u:a", FREE_PER_USER).is_none());
            s.fail("u:a");
            s.fail("ip:127.0.0.1");
        }
        let left = s.locked_for("u:a", FREE_PER_USER).unwrap();
        assert!(left <= Duration::from_secs(30) && left > Duration::from_secs(25));
        // Another user on the same shared address is not locked out yet.
        assert!(s.locked_for("ip:127.0.0.1", FREE_PER_ADDR).is_none());
        s.clear("u:a");
        assert!(s.locked_for("u:a", FREE_PER_USER).is_none());
    }

    #[test]
    fn sessions_expire_and_end() {
        let s = Sessions::default();
        let a = s.create("alice");
        let b = s.create("alice");
        assert_eq!(s.touch(&a).as_deref(), Some("alice"));
        s.end_user("alice", Some(&b));
        assert!(s.touch(&a).is_none());
        assert!(s.touch(&b).is_some());
        // Instant cannot go back past the system's start: on a machine up for
        // less than the timeout the expiry cannot be simulated.
        let back = s.map.lock().unwrap().get(&b).unwrap().last.checked_sub(IDLE_TIMEOUT);
        if let Some(t) = back {
            s.map.lock().unwrap().get_mut(&b).unwrap().last = t;
            assert!(s.touch(&b).is_none());
        }
    }
}
