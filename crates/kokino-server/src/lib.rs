//! HTTP API and embedded browser GUI.
//!
//! By default the server binds to 127.0.0.1 only. With a non-loopback listen
//! address it always serves HTTPS. Every /api request except login and setup
//! needs a session (see `auth`). The Host header must name a loopback
//! address, an IP literal or a configured hostname, which blocks DNS
//! rebinding.

#![forbid(unsafe_code)]

mod api;
mod auth;
pub mod casereport;
mod jobs;
mod state;
mod tls;
pub mod update;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rust_embed::RustEmbed;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

pub use state::AppState;

#[derive(RustEmbed)]
#[folder = "../../ui"]
struct Ui;

/// Fingerprint of the GUI files this server serves. An open page compares it
/// with the one it loaded with and reloads after an upgrade, instead of
/// running stale scripts and styles against a new server.
pub fn ui_build() -> &'static str {
    static B: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut names: Vec<String> = Ui::iter().map(|n| n.to_string()).collect();
        names.sort();
        let mut h = Sha256::new();
        for n in names {
            h.update(n.as_bytes());
            if let Some(f) = Ui::get(&n) {
                h.update(f.metadata.sha256_hash());
            }
        }
        h.finalize().iter().take(6).map(|b| format!("{:02x}", b)).collect()
    })
}

pub enum Tls {
    Off,
    /// Generate (or reuse) a self-signed certificate under the cases root.
    SelfSigned,
    Files { cert: PathBuf, key: PathBuf },
}

pub struct ServerConfig {
    pub cases_root: PathBuf,
    pub listen: IpAddr,
    pub port: u16,
    pub tls: Tls,
    /// DNS names examiners use to reach the server (LAN mode).
    pub hostnames: Vec<String>,
}

pub struct Running {
    /// Address to use on this machine.
    pub url: String,
    /// Addresses other machines can use (LAN mode).
    pub lan_urls: Vec<String>,
    /// Addresses by --hostname; they need DNS or a hosts entry to resolve.
    pub name_urls: Vec<String>,
    /// Link that creates the first admin; present until an account exists.
    pub setup_url: Option<String>,
    pub fingerprint: Option<String>,
    pub handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

pub async fn start(cfg: ServerConfig) -> anyhow::Result<Running> {
    std::fs::create_dir_all(&cfg.cases_root)?;
    let loopback = cfg.listen.is_loopback();
    let tls = match cfg.tls {
        Tls::Off if !loopback => Tls::SelfSigned,
        t => t,
    };
    let listener = std::net::TcpListener::bind(SocketAddr::new(cfg.listen, cfg.port))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let hostnames: Vec<String> = cfg.hostnames.iter().map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
    let st = Arc::new(AppState::new(cfg.cases_root.clone(), port, !matches!(tls, Tls::Off), hostnames.clone())?);

    let app = Router::new()
        .nest("/api", api::routes().merge(auth::routes()).layer(middleware::from_fn_with_state(st.clone(), auth::guard)))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(st.clone(), host_check))
        .with_state(st.clone())
        .into_make_service_with_connect_info::<SocketAddr>();

    // Addresses that work without DNS: the local one for this machine (and
    // for setup), IP addresses for other machines. Hostnames are listed
    // separately because they only work once DNS or hosts files know them.
    let scheme = if matches!(tls, Tls::Off) { "http" } else { "https" };
    let at = |host: String| format!("{}://{}:{}/", scheme, host, port);
    let url = at(if loopback || cfg.listen.is_unspecified() { "127.0.0.1".to_string() } else { host_literal(cfg.listen) });
    let mut lan_urls = vec![];
    if cfg.listen.is_unspecified() {
        lan_urls.extend(primary_ip().map(|ip| at(host_literal(ip))));
    } else if !loopback {
        lan_urls.push(url.clone());
    }
    let name_urls = if loopback { vec![] } else { hostnames.iter().map(|h| at(h.clone())).collect() };
    let setup_url = if st.users.is_empty()? { Some(format!("{}#setup={}", url, st.setup_token)) } else { None };

    let (handle, fingerprint) = match tls {
        Tls::Off => {
            let l = tokio::net::TcpListener::from_std(listener)?;
            let h = tokio::spawn(async move {
                axum::serve(l, app)
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await?;
                Ok(())
            });
            (h, None)
        }
        t => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let (cert, key, fp) = match t {
                Tls::Files { cert, key } => (cert, key, None),
                _ => {
                    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
                    if !cfg.listen.is_unspecified() && !cfg.listen.is_loopback() {
                        names.push(cfg.listen.to_string());
                    }
                    for h in hostnames.iter().cloned().chain(machine_name()) {
                        if !names.contains(&h) {
                            names.push(h);
                        }
                    }
                    let s = tls::self_signed(&cfg.cases_root, &names)?;
                    (s.cert, s.key, Some(s.fingerprint))
                }
            };
            let rc = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await?;
            let server = axum_server::from_tcp_rustls(listener, rc);
            let sh = axum_server::Handle::new();
            let sh2 = sh.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                sh2.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            });
            let h = tokio::spawn(async move {
                server.handle(sh).serve(app).await?;
                Ok(())
            });
            (h, fp)
        }
    };
    Ok(Running { url, lan_urls, name_urls, setup_url, fingerprint, handle })
}

fn host_literal(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v) => format!("[{}]", v),
        v => v.to_string(),
    }
}

/// The address this machine uses for outbound traffic. Connecting a UDP
/// socket only selects a route; no packet is sent.
fn primary_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

fn machine_name() -> Option<String> {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().map(|s| s.to_ascii_lowercase()).filter(|s| !s.is_empty())
}

/// Accepts loopback names, IP literals (DNS rebinding needs a name) and the
/// configured hostnames, on the bound port.
fn host_ok(st: &AppState, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) if !n.ends_with(':') && (n.starts_with('[') == n.ends_with(']')) && !p.contains(']') => (n.to_string(), p.parse::<u16>().ok()),
        _ => (host.clone(), None),
    };
    let default_port = if st.tls { 443 } else { 80 };
    if port.unwrap_or(default_port) != st.port {
        return false;
    }
    let bare = name.trim_start_matches('[').trim_end_matches(']');
    name == "localhost" || bare.parse::<IpAddr>().is_ok() || st.hostnames.iter().any(|h| *h == name)
}

async fn host_check(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    // HTTP/2 (negotiated over TLS) carries the host as :authority, not Host.
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string).or_else(|| req.uri().authority().map(|a| a.to_string())).unwrap_or_default();
    if !host_ok(&st, &host) {
        return (StatusCode::FORBIDDEN, "bad host").into_response();
    }
    let api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    // HTML from the API (reports) holds text taken from evidence: no scripts
    // at all, and a sandbox so it cannot act as the signed-in examiner even if
    // something slipped past the escaping.
    let report = api && h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/html"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    if st.tls {
        h.insert("strict-transport-security", HeaderValue::from_static("max-age=31536000"));
    }
    h.insert(
        "content-security-policy",
        if report {
            HeaderValue::from_static("default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'; sandbox allow-popups")
        } else {
            HeaderValue::from_static("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'")
        },
    );
    res
}

async fn static_file(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Ui::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder().header(header::CONTENT_TYPE, mime.as_ref()).body(Body::from(f.data.into_owned())).unwrap()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rules() {
        let dir = std::env::temp_dir().join(format!("kokino-host-{}", uuid::Uuid::new_v4()));
        let st = AppState::new(dir.clone(), 7311, false, vec!["forensics.lab".into()]).unwrap();
        for ok in ["127.0.0.1:7311", "localhost:7311", "[::1]:7311", "10.0.0.5:7311", "forensics.lab:7311"] {
            assert!(host_ok(&st, ok), "{ok}");
        }
        for bad in ["evil.example:7311", "127.0.0.1:80", "localhost", "127.0.0.1.nip.io:7311", ""] {
            assert!(!host_ok(&st, bad), "{bad}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
