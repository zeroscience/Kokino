use crate::auth::{case_access, CurrentUser};
use crate::jobs::{self, JobView};
use crate::state::{AppState, HashStatus, Loaded, ORPHAN_KEY};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use kokino_analysis::{FileRow, FsAnalysis};
use kokino_core::case::{Case, EvidenceRecord, Patch};
use kokino_core::hashing::Hashes;
use kokino_core::time::{filetime_to_iso, human, human_full, now_iso};
use kokino_image::{read_at, Evidence};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

type St = State<Arc<AppState>>;
type Me = Extension<CurrentUser>;

pub struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("{:#}", self.0) }))).into_response()
    }
}

type R<T = Value> = Result<Json<T>, AppError>;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/info", get(info))
        .route("/browse", get(browse))
        .route("/cases", get(list_cases).post(create_case))
        .route("/cases/{cid}", get(get_case).patch(update_case).delete(delete_case))
        .route("/cases/{cid}/audit", get(audit))
        .route("/cases/{cid}/members", axum::routing::put(set_members))
        .route("/cases/{cid}/bookmarks", get(bookmarks_list).post(bookmark_add))
        .route("/cases/{cid}/bookmarks/report", get(bookmarks_report))
        .route("/cases/{cid}/report", post(case_report))
        .route("/cases/{cid}/reports", get(case_reports))
        .route("/cases/{cid}/reports/{name}", get(case_report_file))
        .route("/cases/{cid}/bookmarks/{id}", axum::routing::put(bookmark_edit).delete(bookmark_delete))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/by-record/{rec}", get(by_record))
        .route("/cases/{cid}/evidence", post(add_evidence))
        .route("/cases/{cid}/evidence/{eid}/ingest", post(reingest))
        .route("/cases/{cid}/evidence/{eid}/summary", get(summary))
        .route("/cases/{cid}/evidence/{eid}/report", get(report))
        .route("/cases/{cid}/evidence/{eid}/hex", get(hex))
        .route("/cases/{cid}/evidence/{eid}/search", get(search))
        .route("/cases/{cid}/evidence/{eid}/textindex", get(text_index).post(build_text_index))
        .route("/cases/{cid}/evidence/{eid}/textsearch", get(text_search))
        .route("/cases/{cid}/evidence/{eid}/carved", get(carved_list).post(carve_start))
        .route("/cases/{cid}/evidence/{eid}/carved/{id}/preview", get(carved_preview))
        .route("/cases/{cid}/evidence/{eid}/carved/{id}/export", get(carved_export))
        .route("/cases/{cid}/evidence/{eid}/carved/{id}/photo", get(carved_photo))
        .route("/cases/{cid}/evidence/{eid}/photos", get(photos_list).post(photos_start))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/image", get(file_image))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/photo", get(file_photo))
        .route("/cases/{cid}/evidence/{eid}/carve", get(carve))
        .route("/cases/{cid}/evidence/{eid}/patches", get(list_patches).post(add_patch).delete(del_patch))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/children", get(children))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/files", get(files))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}", get(file_detail))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/bytes", get(file_bytes))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/export", get(file_export))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/timeline", get(timeline))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/web", get(web))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/windows", get(windows))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/journal", get(journal))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/srum", get(srum))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/indicator/{id}", get(indicator_files))
        .route("/cases/{cid}/evidence/{eid}/binmap", get(image_binmap))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/binmap", get(file_binmap))
        .route("/cases/{cid}/evidence/{eid}/fs/{fi}/file/{idx}/strings", get(file_strings))
        .route("/cases/{cid}/evidence/{eid}/carved/{id}/binmap", get(carved_binmap))
        .route("/cases/{cid}/evidence/{eid}/carved/{id}/strings", get(carved_strings))
        .route("/hashsets", get(hashsets_list))
        .route("/system/deleted-cases", get(deleted_cases))
        .route("/system/deleted-cases/{folder}/restore", post(restore_case))
        .route("/system/hashsets", post(hashset_import))
        .route("/system/hashsets/{id}", axum::routing::patch(hashset_update).delete(hashset_delete))
        .route("/cases/{cid}/evidence/{eid}/hashes", get(hashes_list).post(hashes_start))
        .route("/jobs", get(list_jobs))
        .route("/update-check", get(update_check))
        .route("/jobs/{id}/cancel", post(cancel_job))
}

/// Asks GitHub for the latest release, only because someone clicked.
/// Recorded in the system audit log either way.
async fn update_check(State(st): St, Extension(me): Me) -> R {
    let res = tokio::task::spawn_blocking(crate::update::check).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    match res {
        Ok(u) => {
            crate::auth::sys_audit(&st, &me.username, "update.check", json!({"source": crate::update::RELEASES_API, "latest": u.latest, "newer": u.newer}));
            Ok(Json(json!(u)))
        }
        Err(e) => {
            crate::auth::sys_audit(&st, &me.username, "update.check", json!({"source": crate::update::RELEASES_API, "error": format!("{:#}", e)}));
            Err(anyhow::anyhow!("could not reach GitHub: {:#}", e).into())
        }
    }
}

/// Public: enough for the login screen, nothing about cases or the host.
async fn info(State(st): St) -> R {
    Ok(Json(json!({
        "tool": kokino_core::TOOL_NAME,
        "vendor": kokino_core::VENDOR,
        "version": kokino_core::TOOL_VERSION,
        "setup_required": st.users.is_empty()?,
        "tls": st.tls,
        "build": crate::ui_build(),
    })))
}

#[derive(Deserialize)]
struct BrowseQ {
    path: Option<String>,
}

/// Lists a local directory so the examiner can pick an image file.
async fn browse(Query(q): Query<BrowseQ>) -> R {
    let path = q.path.unwrap_or_default();
    if path.is_empty() {
        let mut roots = vec![];
        if cfg!(windows) {
            for d in b'A'..=b'Z' {
                let p = format!("{}:\\", d as char);
                if std::fs::metadata(&p).is_ok() {
                    roots.push(json!({"name": p, "path": p, "is_dir": true, "size": 0}));
                }
            }
        } else {
            roots.push(json!({"name": "/", "path": "/", "is_dir": true, "size": 0}));
        }
        if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
            let h = home.to_string_lossy().to_string();
            roots.insert(0, json!({"name": format!("Home ({})", h), "path": h, "is_dir": true, "size": 0}));
        }
        return Ok(Json(json!({"path": "", "parent": null, "entries": roots})));
    }
    let p = std::path::PathBuf::from(&path);
    let mut entries = vec![];
    for e in std::fs::read_dir(&p)?.flatten() {
        let Ok(m) = e.metadata() else { continue };
        entries.push(json!({
            "name": e.file_name().to_string_lossy(),
            "path": e.path().display().to_string(),
            "is_dir": m.is_dir(),
            "size": if m.is_dir() { 0 } else { m.len() },
        }));
    }
    entries.sort_by(|a, b| {
        b["is_dir"].as_bool().cmp(&a["is_dir"].as_bool()).then_with(|| a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase()))
    });
    let parent = p.parent().map(|x| x.display().to_string());
    Ok(Json(json!({"path": p.display().to_string(), "parent": parent, "entries": entries})))
}

async fn list_cases(State(st): St, Extension(me): Me) -> R {
    let cases: Vec<Value> = Case::list(&st.root)
        .into_iter()
        .filter_map(|c| {
            let access = case_access(&me, &c.members)?;
            let n = st.case(&c.id).map(|x| x.evidence().len()).unwrap_or(0);
            Some(json!({"info": c, "evidence_count": n, "access": access}))
        })
        .collect();
    Ok(Json(json!(cases)))
}

#[derive(Deserialize)]
struct DeleteCase {
    /// The case name, typed by the admin as confirmation.
    confirm: String,
}

/// Admins only. The case folder (analysis, index, carving results,
/// bookmarks, exports and the case's own audit log) is moved to
/// `<cases>/.kokino/deleted/`, never wiped, and the deletion is written to
/// the system audit log with the evidence list and hashes. Evidence image
/// files are not touched.
async fn delete_case(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(b): Json<DeleteCase>) -> R {
    if me.role != kokino_core::users::Role::Admin {
        return Err(anyhow::anyhow!("only an admin can delete a case").into());
    }
    let case = st.case(&cid)?;
    if b.confirm.trim() != case.info.name {
        return Err(anyhow::anyhow!("type the case name exactly to confirm").into());
    }
    let busy = st.jobs.lock().unwrap().values().any(|j| {
        let v = j.view.lock().unwrap();
        v.case == cid && v.state == "running"
    });
    if busy {
        return Err(anyhow::anyhow!("a job is still running on this case; wait for it or cancel it").into());
    }
    let evidence: Vec<Value> = case
        .evidence()
        .iter()
        .map(|e| json!({"id": e.id, "name": e.name, "path": e.path, "sha256": e.hashes.as_ref().map(|h| h.sha256.clone())}))
        .collect();
    let stamp = now_iso().replace([':', '.'], "-");
    let bin = kokino_core::state_dir(&st.root).join("deleted");
    std::fs::create_dir_all(&bin)?;
    let dest = bin.join(format!("{}_{}", case.info.id, stamp));
    // Note it in the case's own log first: that log moves with the folder.
    case.audit.append(&me.username, "case.delete", json!({"moved_to": dest.to_string_lossy()}))?;
    st.invalidate_case(&cid);
    std::fs::rename(&case.dir, &dest).map_err(|e| anyhow::anyhow!("could not move the case folder (is a file in it open?): {}", e))?;
    st.users.audit.append(
        &me.username,
        "case.delete",
        json!({"case": cid, "name": case.info.name, "lead_examiner": case.info.examiner, "evidence": evidence, "moved_to": dest.to_string_lossy()}),
    )?;
    Ok(Json(json!({"ok": true, "moved_to": dest.to_string_lossy()})))
}

/// Admins only (guard): the case folders moved to `.kokino/deleted`, newest
/// deletion first, with who deleted each and when (from its own audit log).
async fn deleted_cases(State(st): St) -> R {
    let bin = kokino_core::state_dir(&st.root).join("deleted");
    let mut out = vec![];
    for e in std::fs::read_dir(&bin).into_iter().flatten().flatten() {
        let folder = e.file_name().to_string_lossy().to_string();
        let Ok(c) = Case::open(&e.path()) else { continue };
        let del = c.audit.entries().unwrap_or_default().into_iter().rev().find(|x| x.action == "case.delete");
        let exists = st.root.join(&c.info.id).exists();
        out.push(json!({
            "folder": folder, "info": c.info, "evidence": c.evidence().len(),
            "deleted_at": del.as_ref().map(|d| d.time.clone()), "deleted_by": del.as_ref().map(|d| d.examiner.clone()),
            "path": e.path().to_string_lossy(), "id_in_use": exists,
        }));
    }
    out.sort_by(|a, b| b["deleted_at"].as_str().cmp(&a["deleted_at"].as_str()));
    Ok(Json(json!(out)))
}

/// Admins only (guard): moves a deleted case folder back into the cases
/// directory under its case id, as it was. Recorded in the case's own audit
/// log and the system audit log.
async fn restore_case(State(st): St, Extension(me): Me, Path(folder): Path<String>) -> R {
    let src = kokino_core::state_dir(&st.root).join("deleted").join(kokino_core::case::safe_id(&folder)?);
    let c = Case::open(&src).map_err(|_| anyhow::anyhow!("no deleted case {}", folder))?;
    let id = kokino_core::case::safe_id(&c.info.id)?.to_string();
    let dest = st.root.join(&id);
    if dest.exists() {
        return Err(anyhow::anyhow!("a case with id {} already exists in the cases directory", id).into());
    }
    std::fs::rename(&src, &dest).map_err(|e| anyhow::anyhow!("could not move the case folder back (is a file in it open?): {}", e))?;
    st.invalidate_case(&id);
    let c = Case::open(&dest)?;
    c.audit.append(&me.username, "case.restore", json!({"from": src.to_string_lossy()}))?;
    st.users.audit.append(&me.username, "case.restore", json!({"case": id, "name": c.info.name, "from": src.to_string_lossy()}))?;
    Ok(Json(json!({"ok": true, "id": id})))
}

#[derive(Deserialize)]
struct UpdateCase {
    name: Option<String>,
    description: Option<String>,
    /// Lead examiner (admins only): a user who is not a reviewer.
    examiner: Option<String>,
}

/// Examiners on the case and admins (write access, enforced by the guard)
/// change the name and description; only admins change the lead examiner,
/// who becomes an examiner member if not one already. The case id and
/// folder stay as they are. Each change is written to the case audit log
/// with its old and new value.
async fn update_case(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(b): Json<UpdateCase>) -> R {
    use kokino_core::case::Access;
    use kokino_core::users::Role;
    let mut c = st.case(&cid)?;
    let mut changes = serde_json::Map::new();
    if let Some(name) = b.name.as_deref().map(str::trim) {
        if name.is_empty() {
            return Err(anyhow::anyhow!("case name is required").into());
        }
        if name != c.info.name {
            changes.insert("name".into(), json!({"before": c.info.name, "after": name}));
            c.info.name = name.to_string();
        }
    }
    if let Some(desc) = b.description.as_deref().map(str::trim) {
        if desc != c.info.description {
            changes.insert("description".into(), json!({"before": c.info.description, "after": desc}));
            c.info.description = desc.to_string();
        }
    }
    if let Some(lead) = b.examiner.as_deref().map(str::trim).filter(|l| *l != c.info.examiner) {
        if me.role != Role::Admin {
            return Err(anyhow::anyhow!("only an admin can change the lead examiner").into());
        }
        let u = st.users.get(lead)?.ok_or_else(|| anyhow::anyhow!("no such user: {}", lead))?;
        if u.role == Role::Reviewer {
            return Err(anyhow::anyhow!("{} is a reviewer and cannot lead a case", u.username).into());
        }
        changes.insert("examiner".into(), json!({"before": c.info.examiner, "after": u.username}));
        if c.info.members.get(&u.username) != Some(&Access::Examiner) {
            c.info.members.insert(u.username.clone(), Access::Examiner);
            changes.insert("member_added".into(), json!(u.username));
        }
        c.info.examiner = u.username;
    }
    if changes.is_empty() {
        return Ok(Json(json!(c.info)));
    }
    c.save_info()?;
    c.audit.append(&me.username, "case.update", Value::Object(changes.clone()))?;
    let _ = st.users.audit.append(&me.username, "case.update", json!({"case": cid, "changes": changes}));
    Ok(Json(json!(c.info)))
}

#[derive(Deserialize)]
struct NewCase {
    name: String,
    description: Option<String>,
}

/// The creator becomes the case's lead examiner and first member.
async fn create_case(State(st): St, Extension(me): Me, Json(b): Json<NewCase>) -> R {
    if b.name.trim().is_empty() {
        return Err(anyhow::anyhow!("case name is required").into());
    }
    let c = Case::create(&st.root, b.name.trim(), &me.username, b.description.as_deref().unwrap_or(""))?;
    Ok(Json(json!(c.info)))
}

async fn get_case(State(st): St, Extension(me): Me, Path(cid): Path<String>) -> R {
    let c = st.case(&cid)?;
    let access = case_access(&me, &c.info.members);
    let ev: Vec<Value> = c
        .evidence()
        .into_iter()
        .map(|r| {
            let analyzed = c.analysis_path(&r.id).map(|p| p.exists()).unwrap_or(false);
            let verified = match (&r.expected, &r.hashes) {
                (Some(x), Some(h)) => Some(hash_match(x, h)),
                _ => None,
            };
            let embedded_verified = match (&r.embedded, &r.hashes) {
                (Some(x), Some(h)) => Some(hash_match(x, h)),
                _ => None,
            };
            json!({"record": r, "analyzed": analyzed, "verified": verified, "embedded_verified": embedded_verified})
        })
        .collect();
    let jobs: Vec<JobView> = st.jobs.lock().unwrap().values().map(|j| j.view.lock().unwrap().clone()).filter(|j| j.case == cid).collect();
    let audit = kokino_core::audit::verify(&c.dir.join("audit.jsonl"))?;
    Ok(Json(json!({"info": c.info, "evidence": ev, "jobs": jobs, "access": access, "audit": audit})))
}

fn hash_match(x: &Hashes, h: &Hashes) -> bool {
    (x.md5.is_empty() || x.md5.eq_ignore_ascii_case(&h.md5))
        && (x.sha1.is_empty() || x.sha1.eq_ignore_ascii_case(&h.sha1))
        && (x.sha256.is_empty() || x.sha256.eq_ignore_ascii_case(&h.sha256))
}

async fn audit(State(st): St, Path(cid): Path<String>) -> R {
    let c = st.case(&cid)?;
    let report = kokino_core::audit::verify(&c.dir.join("audit.jsonl"))?;
    Ok(Json(json!({"verify": report, "entries": c.audit.entries()?})))
}

#[derive(Deserialize)]
struct MembersBody {
    members: std::collections::BTreeMap<String, kokino_core::case::Access>,
}

/// Admin only (enforced by the guard). Reviewers can only be reviewers.
async fn set_members(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(b): Json<MembersBody>) -> R {
    use kokino_core::case::Access;
    use kokino_core::users::Role;
    let mut c = st.case(&cid)?;
    let mut members = std::collections::BTreeMap::new();
    for (name, access) in b.members {
        let u = st.users.get(&name)?.ok_or_else(|| anyhow::anyhow!("no such user: {}", name))?;
        let access = if u.role == Role::Reviewer { Access::Reviewer } else { access };
        members.insert(u.username, access);
    }
    let before = std::mem::replace(&mut c.info.members, members.clone());
    c.save_info()?;
    c.audit.append(&me.username, "case.members", json!({"before": before, "after": members}))?;
    let _ = st.users.audit.append(&me.username, "case.members", json!({"case": cid, "after": members}));
    Ok(Json(json!(members)))
}

#[derive(Deserialize)]
struct NewEvidence {
    path: String,
    name: Option<String>,
    notes: Option<String>,
    expected_md5: Option<String>,
    expected_sha1: Option<String>,
    expected_sha256: Option<String>,
}

async fn add_evidence(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(b): Json<NewEvidence>) -> R {
    let c = st.case(&cid)?;
    let ev = Evidence::open(b.path.trim())?;
    let abs = std::fs::canonicalize(&ev.path).unwrap_or(ev.path.clone());
    let abs = abs.display().to_string().trim_start_matches(r"\\?\").to_string();
    if inside_cases_dir(&st.root, std::path::Path::new(&abs)) {
        return Err(anyhow::anyhow!("files in the cases directory cannot be added as evidence: it holds the other cases, the accounts and the TLS key").into());
    }
    if c.evidence().iter().any(|r| r.path == abs) {
        return Err(anyhow::anyhow!("this image is already part of the case").into());
    }
    let clean = |s: Option<String>| s.map(|x| x.trim().to_ascii_lowercase()).unwrap_or_default();
    let expected = Hashes { md5: clean(b.expected_md5), sha1: clean(b.expected_sha1), sha256: clean(b.expected_sha256) };
    let has_expected = !(expected.md5.is_empty() && expected.sha1.is_empty() && expected.sha256.is_empty());
    let file_name = ev.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let rec = EvidenceRecord {
        id: uuid::Uuid::new_v4().simple().to_string()[..10].to_string(),
        name: b.name.filter(|n| !n.trim().is_empty()).unwrap_or(file_name),
        path: abs,
        format: ev.format_label(),
        size: ev.size,
        added: now_iso(),
        notes: b.notes.unwrap_or_default(),
        hashes: None,
        hashed_at: None,
        expected: if has_expected { Some(expected) } else { None },
        embedded: ev.ewf_info().filter(|i| i.md5.is_some() || i.sha1.is_some()).map(|i| Hashes {
            md5: i.md5.clone().unwrap_or_default(),
            sha1: i.sha1.clone().unwrap_or_default(),
            sha256: String::new(),
        }),
        acquisition: ev.ewf_info().map(serde_json::to_value).transpose()?,
    };
    c.save_evidence(&rec)?;
    c.audit.append(&me.username, "evidence.add", serde_json::to_value(&rec)?)?;
    let job = jobs::spawn_ingest(st.clone(), &me.username, cid, rec.id.clone(), true, true);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!({"record": rec, "job": view})))
}

/// `p` is inside the cases directory (symbolic links resolved, case ignored
/// on Windows).
fn inside_cases_dir(root: &std::path::Path, p: &std::path::Path) -> bool {
    let norm = |x: &std::path::Path| {
        let s = std::fs::canonicalize(x).unwrap_or_else(|_| x.to_path_buf()).display().to_string();
        let s = s.trim_start_matches(r"\\?\").replace('\\', "/");
        let s = if cfg!(windows) { s.to_lowercase() } else { s };
        s.trim_end_matches('/').to_string()
    };
    let (r, p) = (norm(root), norm(p));
    p == r || p.starts_with(&format!("{}/", r))
}

#[derive(Deserialize)]
struct IngestQ {
    rehash: Option<bool>,
}

async fn reingest(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Query(q): Query<IngestQ>) -> R {
    st.case(&cid)?.evidence_by_id(&eid)?;
    let job = jobs::spawn_ingest(st.clone(), &me.username, cid, eid, q.rehash.unwrap_or(false), true);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

/// Jobs on cases the user can see.
async fn list_jobs(State(st): St, Extension(me): Me) -> R {
    let mut v: Vec<JobView> = st.jobs.lock().unwrap().values().map(|j| j.view.lock().unwrap().clone()).collect();
    let admin = me.role == kokino_core::users::Role::Admin;
    v.retain(|j| if j.case.is_empty() { admin } else { st.case(&j.case).ok().and_then(|c| case_access(&me, &c.info.members)).is_some() });
    v.sort_by(|a, b| b.started.cmp(&a.started));
    Ok(Json(json!(v)))
}

async fn cancel_job(State(st): St, Extension(me): Me, Path(id): Path<String>) -> R {
    let job = st.jobs.lock().unwrap().get(&id).cloned();
    if let Some(j) = job {
        let cid = j.view.lock().unwrap().case.clone();
        let access = st.case(&cid).ok().and_then(|c| case_access(&me, &c.info.members));
        let allowed = if cid.is_empty() { me.role == kokino_core::users::Role::Admin } else { access.map(|a| a.can_write()).unwrap_or(false) };
        if !allowed {
            return Err(anyhow::anyhow!("you cannot cancel jobs on this case").into());
        }
        j.cancel.store(true, Ordering::Relaxed);
    }
    Ok(Json(json!({"ok": true})))
}

fn fs_of<'a>(l: &'a Loaded, fi: usize) -> anyhow::Result<&'a FsAnalysis> {
    l.analysis.filesystems.get(fi).ok_or_else(|| anyhow::anyhow!("no such filesystem"))
}

async fn summary(State(st): St, Path((cid, eid)): Path<(String, String)>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let a = &l.analysis;
    let fss: Vec<Value> = a
        .filesystems
        .iter()
        .map(|f| {
            json!({
                "volume": f.volume, "info": f.info, "indicators": f.indicators, "score": f.score,
                "stats": f.stats, "unreadable": f.unreadable, "entries": f.files.len(), "web_sources": f.web.sources,
                "time_min_iso": filetime_to_iso(f.stats.time_min), "time_max_iso": filetime_to_iso(f.stats.time_max),
            })
        })
        .collect();
    Ok(Json(json!({
        "schema": a.schema, "tool_version": a.tool_version, "analyzed_at": a.analyzed_at,
        "image_format": a.image_format, "image_size": a.image_size, "volumes": a.volumes,
        "filesystems": fss, "errors": a.errors,
    })))
}

fn times_json(t: Option<kokino_ntfs::Times>) -> Value {
    match t {
        None => Value::Null,
        Some(t) => json!({
            "created": filetime_to_iso(t.created), "modified": filetime_to_iso(t.modified),
            "accessed": filetime_to_iso(t.accessed), "mft_modified": filetime_to_iso(t.mft_modified),
            "raw": [t.created, t.modified, t.accessed, t.mft_modified],
        }),
    }
}

fn row(i: usize, f: &FileRow, l: &Loaded, fi: usize, hs: &Option<Arc<HashStatus>>) -> Value {
    let kids = l.fs[fi].children.get(&f.e.record).map(|v| v.len()).unwrap_or(0);
    let hash = hs.as_ref().map(|h| h.kind(fi, f.e.record)).unwrap_or("");
    json!({
        "idx": i, "record": f.e.record, "seq": f.e.seq, "name": f.e.name, "path": f.e.path,
        "is_dir": f.e.is_dir, "deleted": f.e.deleted, "orphan": f.e.orphan, "size": f.e.size,
        "ext": f.ext, "sig": f.sig, "sig_label": f.sig_label, "category": f.category,
        "mismatch": f.mismatch, "entropy": f.entropy, "flags": f.flags,
        "ads": f.e.ads().count(), "children": kids, "hash": hash,
        "modified": f.e.si.or(f.e.fname).map(|t| filetime_to_iso(t.modified)).unwrap_or_default(),
        "created": f.e.si.or(f.e.fname).map(|t| filetime_to_iso(t.created)).unwrap_or_default(),
        "name_only": f.e.name_only.as_ref().map(|n| n.source.as_str()),
    })
}

#[derive(Deserialize)]
struct ChildrenQ {
    dir: Option<String>,
}

async fn children(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<ChildrenQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let hs = st.hash_status(&cid, &eid);
    let f = fs_of(&l, fi)?;
    let dir = match q.dir.as_deref() {
        None | Some("") => kokino_ntfs::ROOT_RECORD,
        Some("orphans") => ORPHAN_KEY,
        Some(d) => d.parse()?,
    };
    let items: Vec<Value> = l.fs[fi].children.get(&dir).map(|v| v.iter().map(|&i| row(i as usize, &f.files[i as usize], &l, fi, &hs)).collect()).unwrap_or_default();
    let orphans = l.fs[fi].children.get(&ORPHAN_KEY).map(|v| v.len()).unwrap_or(0);
    Ok(Json(json!({"dir": if dir == ORPHAN_KEY { "orphans".to_string() } else { dir.to_string() }, "items": items, "orphans": orphans})))
}

#[derive(Deserialize)]
struct FilesQ {
    q: Option<String>,
    filter: Option<String>,
    category: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
    sort: Option<String>,
    /// Leave out files in a known-good hash set.
    hide_known: Option<bool>,
}

async fn files(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<FilesQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let hs = st.hash_status(&cid, &eid);
    let hk = |r: &FileRow| hs.as_ref().map(|h| h.kind(fi, r.e.record)).unwrap_or("");
    let hide_known = q.hide_known.unwrap_or(false);
    let f = fs_of(&l, fi)?;
    let needle = q.q.unwrap_or_default().to_lowercase();
    let filter = q.filter.unwrap_or_default();
    let cat = q.category.unwrap_or_default();
    let mut hits: Vec<usize> = f
        .files
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            (needle.is_empty() || r.e.path.to_lowercase().contains(&needle))
                && match filter.as_str() {
                    "deleted" => r.e.deleted,
                    "flagged" => !r.flags.is_empty(),
                    "mismatch" => r.mismatch,
                    "ads" => r.e.ads().next().is_some(),
                    "files" => !r.e.is_dir,
                    "notable" => hk(r) == "notable",
                    "known" => hk(r) == "known",
                    _ => true,
                }
                && !(hide_known && hk(r) == "known")
                && (cat.is_empty() || r.category.map(|c| serde_json::to_value(c).ok().and_then(|v| v.as_str().map(|s| s == cat)).unwrap_or(false)).unwrap_or(false))
        })
        .map(|(i, _)| i)
        .collect();
    match q.sort.as_deref() {
        Some("size") => hits.sort_by(|a, b| f.files[*b].e.size.cmp(&f.files[*a].e.size)),
        Some("modified") => hits.sort_by_key(|i| std::cmp::Reverse(f.files[*i].e.si.map(|t| t.modified).unwrap_or(0))),
        Some("entropy") => hits.sort_by(|a, b| f.files[*b].entropy.unwrap_or(0.0).partial_cmp(&f.files[*a].entropy.unwrap_or(0.0)).unwrap()),
        _ => {}
    }
    let total = hits.len();
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(200).min(2000);
    let items: Vec<Value> = hits.into_iter().skip(off).take(lim).map(|i| row(i, &f.files[i], &l, fi, &hs)).collect();
    Ok(Json(json!({"total": total, "offset": off, "items": items})))
}

async fn file_detail(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let hs = st.hash_status(&cid, &eid);
    let f = fs_of(&l, fi)?;
    let r = f.files.get(idx).ok_or_else(|| anyhow::anyhow!("no such file"))?;
    let hashes = hs.as_ref().and_then(|h| {
        let i = *h.by_file.get(&(fi, r.e.record))?;
        let x = &h.fh.files[i];
        Some(json!({"md5": x.hashes.md5, "sha1": x.hashes.sha1, "sha256": x.hashes.sha256, "error": x.error, "hashed_at": h.fh.hashed_at, "sets": set_hits(h, i)}))
    });
    let vol = f.volume.start;
    let indicators: Vec<Value> = f
        .indicators
        .iter()
        .filter(|i| r.flags.contains(&i.id))
        .map(|i| json!({"id": i.id, "title": i.title, "category": i.category, "explanation": i.explanation, "caveat": i.caveat, "weight": i.weight}))
        .collect();
    let events: Vec<Value> = l.fs[fi]
        .timeline
        .iter()
        .filter(|e| e.idx as usize == idx && !kokino_analysis::timeline::is_artifact(e.src))
        .map(|e| json!({"t": filetime_to_iso(e.t), "macb": e.macb, "src": e.src}))
        .collect();
    // What the change journal recorded for this file, newest first.
    let journal: Vec<Value> = f
        .windows
        .journal
        .iter()
        .flat_map(|j| j.changes.iter().rev().filter(|c| c.file == Some(idx as u32)))
        .take(500)
        .map(|c| json!({"t": filetime_to_iso(c.c.t), "first": if c.c.first > 0 { filetime_to_iso(c.c.first) } else { String::new() }, "what": c.what, "path": c.path, "old_path": c.old_path, "usn": c.c.usn}))
        .collect();
    let streams: Vec<Value> = r
        .e
        .streams
        .iter()
        .map(|s| json!({"name": s.name, "size": s.size, "resident": s.resident, "image_offset": s.first_offset.map(|o| o + vol)}))
        .collect();
    Ok(Json(json!({
        "row": row(idx, r, &l, fi, &hs),
        "fs": l.analysis.filesystems[fi].volume.fs_label,
        "dos_name": r.e.dos_name, "parent": r.e.parent, "parent_seq": r.e.parent_seq,
        "alloc_size": r.e.alloc_size, "resident": r.e.resident, "attributes": r.e.attributes,
        "attribute_names": attr_names(r.e.attributes), "hard_links": r.e.hard_links, "usn": r.e.usn,
        "reparse": r.e.has_reparse, "uniform": r.uniform, "ads_sig": r.ads_sig, "error": r.e.error,
        "si": times_json(r.e.si), "fn": times_json(r.e.fname),
        "record_image_offset": if r.e.name_only.is_some() && r.e.record_offset == 0 { None } else { Some(r.e.record_offset + vol) },
        "name_only": r.e.name_only, "journal": journal,
        "data_image_offset": r.e.data_offset().map(|o| o + vol),
        "streams": streams, "indicators": indicators, "events": events, "hashes": hashes,
        "unix": r.e.unix.as_ref().map(|u| json!({
            "inode": u.inode, "mode": format!("{:o}", u.mode), "mode_string": u.mode_string(), "uid": u.uid, "gid": u.gid,
            "deleted": filetime_to_iso(u.deleted_time), "deleted_raw": u.deleted_time,
            "inode_image_offset": u.inode_offset + vol, "journal_seq": u.journal_seq, "link_target": u.link_target,
        })),
    })))
}

/// Hash sets a file (index into the hash analysis) matched.
fn set_hits(h: &HashStatus, i: usize) -> Vec<Value> {
    h.hits
        .get(&i)
        .map(|v| v.iter().filter_map(|(s, algo)| h.fh.sets.get(*s).map(|x| json!({"id": x.id, "name": x.name, "kind": x.kind, "algo": algo}))).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- byte map and strings

/// Something to read bytes from: (size, read(offset, len)).
type ByteSrc = (u64, Box<dyn FnMut(u64, usize) -> anyhow::Result<Vec<u8>> + Send>);

fn file_src(st: &AppState, cid: &str, eid: &str, fi: usize, idx: usize) -> anyhow::Result<ByteSrc> {
    let l = st.loaded(cid, eid)?;
    let r = fs_of(&l, fi)?.files.get(idx).ok_or_else(|| anyhow::anyhow!("no such file"))?.e.clone();
    if r.is_dir {
        anyhow::bail!("a directory has no content");
    }
    Ok((r.size, Box::new(move |off, len| l.read_file(fi, &r, "", off, len))))
}

fn carved_src(st: &AppState, cid: &str, eid: &str, id: u32) -> anyhow::Result<ByteSrc> {
    let case = st.case(cid)?;
    let res = jobs::load_carved(&case, eid).ok_or_else(|| anyhow::anyhow!("this evidence has not been carved"))?;
    let f = res.files.into_iter().find(|f| f.id == id).ok_or_else(|| anyhow::anyhow!("no such carved file"))?;
    image_range(&case.evidence_by_id(eid)?, f.offset, f.len)
}

fn image_range(rec: &EvidenceRecord, start: u64, len: u64) -> anyhow::Result<ByteSrc> {
    let ev = Evidence::open(&rec.path)?;
    let mut reader = ev.reader()?;
    Ok((len, Box::new(move |off, n| {
        let n = n.min(len.saturating_sub(off) as usize);
        let mut buf = vec![0u8; n];
        let got = read_at(&mut reader, start + off, &mut buf)?;
        buf.truncate(got);
        Ok(buf)
    })))
}

#[derive(Deserialize)]
struct BinmapQ {
    cells: Option<usize>,
    offset: Option<u64>,
    len: Option<u64>,
}

/// Byte map: the data cut into a power-of-4 number of slices, each sampled
/// (up to 4 KiB at its start) and summarized by `binview::cell`. `data` is
/// base64 of 6 bytes per cell: entropy, 0x00, 0xFF, text, low, high.
fn binmap(src: ByteSrc, start: u64, cells: Option<usize>) -> anyhow::Result<Value> {
    let (size, mut read) = src;
    let n = kokino_analysis::binview::cell_count(size, cells.unwrap_or(4096));
    let per = size.div_ceil(n as u64).max(1);
    let mut data = Vec::with_capacity(n * 6);
    for i in 0..n as u64 {
        let off = i * per;
        let c = if off < size { kokino_analysis::binview::cell(&read(off, per.min(4096) as usize)?) } else { [0; 6] };
        data.extend(c);
    }
    let used = size.div_ceil(per);
    Ok(json!({"start": start, "size": size, "cells": n, "used": used, "per_cell": per, "data": kokino_analysis::photo::b64(&data)}))
}

async fn file_binmap(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>, Query(q): Query<BinmapQ>) -> R {
    Ok(Json(tokio::task::spawn_blocking(move || binmap(file_src(&st, &cid, &eid, fi, idx)?, 0, q.cells)).await??))
}

async fn carved_binmap(State(st): St, Path((cid, eid, id)): Path<(String, String, u32)>, Query(q): Query<BinmapQ>) -> R {
    Ok(Json(tokio::task::spawn_blocking(move || binmap(carved_src(&st, &cid, &eid, id)?, 0, q.cells)).await??))
}

/// Byte map of the image, or of a range of it (image offsets).
async fn image_binmap(State(st): St, Path((cid, eid)): Path<(String, String)>, Query(q): Query<BinmapQ>) -> R {
    Ok(Json(tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let rec = st.case(&cid)?.evidence_by_id(&eid)?;
        let size = Evidence::open(&rec.path)?.size;
        let start = q.offset.unwrap_or(0).min(size);
        let len = q.len.unwrap_or(size).min(size - start);
        binmap(image_range(&rec, start, len)?, start, q.cells)
    })
    .await??))
}

#[derive(Deserialize)]
struct StringsQ {
    min: Option<usize>,
    q: Option<String>,
    enc: Option<String>,
    limit: Option<usize>,
}

/// Content scanned for strings, at most.
const STRINGS_MAX: u64 = 64 << 20;

fn strings_of(src: ByteSrc, q: StringsQ) -> anyhow::Result<Value> {
    let (size, mut read) = src;
    let n = size.min(STRINGS_MAX);
    let mut d = Vec::with_capacity(n as usize);
    while (d.len() as u64) < n {
        let chunk = read(d.len() as u64, (n - d.len() as u64).min(4 << 20) as usize)?;
        if chunk.is_empty() {
            break;
        }
        d.extend(chunk);
    }
    let all = kokino_analysis::binview::strings(&d, 0, q.min.unwrap_or(5).clamp(3, 64));
    let needle = q.q.unwrap_or_default().to_lowercase();
    let enc = q.enc.unwrap_or_default();
    let hits: Vec<&kokino_analysis::binview::Str> = all
        .iter()
        .filter(|s| (needle.is_empty() || s.text.to_lowercase().contains(&needle)) && (enc.is_empty() || (enc == "utf16le") == (s.enc == "utf16le")))
        .collect();
    let lim = q.limit.unwrap_or(2000).min(20000);
    Ok(json!({"size": size, "scanned": d.len(), "total": all.len(), "matches": hits.len(), "items": hits.into_iter().take(lim).collect::<Vec<_>>()}))
}

async fn file_strings(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>, Query(q): Query<StringsQ>) -> R {
    Ok(Json(tokio::task::spawn_blocking(move || strings_of(file_src(&st, &cid, &eid, fi, idx)?, q)).await??))
}

async fn carved_strings(State(st): St, Path((cid, eid, id)): Path<(String, String, u32)>, Query(q): Query<StringsQ>) -> R {
    Ok(Json(tokio::task::spawn_blocking(move || strings_of(carved_src(&st, &cid, &eid, id)?, q)).await??))
}

// ---------------------------------------------------------------- hash sets

/// Every hash set (any signed-in user may see what files are compared with).
async fn hashsets_list(State(st): St) -> R {
    Ok(Json(json!(st.hashsets.list()?)))
}

#[derive(Deserialize)]
struct NewHashSet {
    path: String,
    name: String,
    kind: kokino_analysis::hashsets::SetKind,
    #[serde(default)]
    description: String,
}

/// Imports a hash set from a file on the server (admins; a background job).
async fn hashset_import(State(st): St, Extension(me): Me, Json(b): Json<NewHashSet>) -> R {
    let src = std::path::PathBuf::from(b.path.trim());
    if !src.is_file() {
        return Err(anyhow::anyhow!("{} is not a file on the server", src.display()).into());
    }
    let job = jobs::spawn_hashset_import(st.clone(), &me.username, src, b.name, b.kind, b.description);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

#[derive(Deserialize)]
struct HashSetPatch {
    enabled: bool,
}

async fn hashset_update(State(st): St, Extension(me): Me, Path(id): Path<String>, Json(b): Json<HashSetPatch>) -> R {
    let s = st.hashsets.set_enabled(&id, b.enabled)?;
    st.users.audit.append(&me.username, "hashset.update", json!({"id": s.id, "name": s.name, "enabled": s.enabled}))?;
    Ok(Json(json!(s)))
}

async fn hashset_delete(State(st): St, Extension(me): Me, Path(id): Path<String>) -> R {
    let s = st.hashsets.delete(&id)?;
    st.users.audit.append(&me.username, "hashset.delete", json!({"id": s.id, "name": s.name, "kind": s.kind, "source_sha256": s.source_sha256}))?;
    Ok(Json(json!(s)))
}

#[derive(Deserialize)]
struct HashRunQ {
    rehash: Option<bool>,
}

/// Hash analysis of one evidence item (hash every file, then look up the sets).
async fn hashes_start(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Query(q): Query<HashRunQ>) -> R {
    st.case(&cid)?.evidence_by_id(&eid)?;
    st.loaded(&cid, &eid)?;
    let busy = st.jobs.lock().unwrap().values().any(|j| {
        let v = j.view.lock().unwrap();
        v.case == cid && v.evidence == eid && v.state == "running"
    });
    if busy {
        return Err(anyhow::anyhow!("a job is already running on this evidence").into());
    }
    let job = jobs::spawn_filehash(st.clone(), &me.username, cid, eid, q.rehash.unwrap_or(false));
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

#[derive(Deserialize)]
struct HashesQ {
    /// notable, known, unmatched, unreadable (default notable)
    show: Option<String>,
    q: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn hashes_list(State(st): St, Path((cid, eid)): Path<(String, String)>, Query(q): Query<HashesQ>) -> R {
    let sets = st.hashsets.list()?;
    let Some(h) = st.hash_status(&cid, &eid) else {
        return Ok(Json(json!({"summary": null, "sets": sets})));
    };
    let l = st.loaded(&cid, &eid)?;
    let show = q.show.unwrap_or_else(|| "notable".into());
    let needle = q.q.unwrap_or_default().to_lowercase();
    // (file system, record) -> row index, per file system.
    let rows: Vec<std::collections::HashMap<u64, usize>> = l.analysis.filesystems.iter().map(|f| f.files.iter().enumerate().map(|(i, r)| (r.e.record, i)).collect()).collect();
    let fh = &h.fh;
    let mut items = vec![];
    for (i, x) in fh.files.iter().enumerate() {
        let keep = match show.as_str() {
            "known" => h.kind_of(i) == "known",
            "unmatched" => x.error.is_none() && h.kind_of(i).is_empty(),
            "unreadable" => x.error.is_some(),
            _ => h.kind_of(i) == "notable",
        };
        if !keep {
            continue;
        }
        let Some(r) = rows.get(x.fi).and_then(|m| m.get(&x.record)).and_then(|&idx| l.analysis.filesystems[x.fi].files.get(idx).map(|r| (idx, r))) else { continue };
        if !needle.is_empty() && !r.1.e.path.to_lowercase().contains(&needle) && !x.hashes.md5.contains(&needle) && !x.hashes.sha1.contains(&needle) && !x.hashes.sha256.contains(&needle) {
            continue;
        }
        items.push((i, x, r));
    }
    let total = items.len();
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(200).min(2000);
    let page: Vec<Value> = items
        .into_iter()
        .skip(off)
        .take(lim)
        .map(|(i, x, (idx, r))| {
            json!({"fi": x.fi, "idx": idx, "record": x.record, "name": r.e.name, "path": r.e.path, "deleted": r.e.deleted, "size": x.size,
                "md5": x.hashes.md5, "sha1": x.hashes.sha1, "sha256": x.hashes.sha256, "error": x.error, "sets": set_hits(&h, i)})
        })
        .collect();
    use kokino_analysis::hashsets::SetKind;
    Ok(Json(json!({
        "summary": {"files": fh.files.len(), "bytes": fh.bytes, "unreadable": fh.errors(), "known": fh.count(SetKind::Known), "notable": fh.count(SetKind::Notable),
            "hashed_at": fh.hashed_at, "matched_at": fh.matched_at, "sets": fh.sets, "outdated": fh.outdated(&sets)},
        "sets": sets, "total": total, "offset": off, "items": page,
    })))
}

fn attr_names(a: u32) -> Vec<&'static str> {
    const N: &[(u32, &str)] = &[
        (0x1, "ReadOnly"), (0x2, "Hidden"), (0x4, "System"), (0x20, "Archive"), (0x40, "Device"), (0x80, "Normal"),
        (0x100, "Temporary"), (0x200, "Sparse"), (0x400, "ReparsePoint"), (0x800, "Compressed"), (0x1000, "Offline"),
        (0x2000, "NotIndexed"), (0x4000, "Encrypted"),
    ];
    N.iter().filter(|(b, _)| a & b != 0).map(|(_, n)| *n).collect()
}

#[derive(Deserialize)]
struct BytesQ {
    offset: Option<u64>,
    len: Option<usize>,
    stream: Option<String>,
}

async fn file_bytes(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>, Query(q): Query<BytesQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let r = f.files.get(idx).ok_or_else(|| anyhow::anyhow!("no such file"))?;
    let stream = q.stream.unwrap_or_default();
    let size = r.e.streams.iter().find(|s| s.name == stream).map(|s| s.size).unwrap_or(0);
    let offset = q.offset.unwrap_or(0);
    let len = q.len.unwrap_or(4096).min(65536);
    let e = r.e.clone();
    let l2 = l.clone();
    let data = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> { l2.read_file(fi, &e, &stream, offset, len) })
    .await??;
    Ok(Json(json!({"offset": offset, "size": size, "data": hex::encode(&data)})))
}

/// Writes the file content to the case exports folder, records its SHA-256
/// in the audit log and returns it as a download.
async fn file_export(State(st): St, Extension(me): Me, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>, Query(q): Query<BytesQ>) -> Result<Response, AppError> {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let r = f.files.get(idx).ok_or_else(|| anyhow::anyhow!("no such file"))?.clone();
    let stream = q.stream.unwrap_or_default();
    let size = r.e.streams.iter().find(|s| s.name == stream).map(|s| s.size).ok_or_else(|| anyhow::anyhow!("no such stream"))?;
    if size > 1 << 30 {
        return Err(anyhow::anyhow!("export over 1 GiB is not supported in the GUI yet").into());
    }
    let l2 = l.clone();
    let s2 = stream.clone();
    let e = r.e.clone();
    let data = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> { l2.read_file(fi, &e, &s2, 0, size as usize) })
    .await??;
    let case = st.case(&cid)?;
    let (hashes, _) = kokino_core::hashing::hash_reader(&data[..], |_| true)?;
    let safe: String = r.e.name.chars().map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }).collect();
    let suffix = if stream.is_empty() { String::new() } else { format!("_{}", stream.replace(|c: char| !c.is_alphanumeric(), "_")) };
    let out_name = format!("{}_{}_{}{}", eid, r.e.record, safe, suffix);
    std::fs::write(case.dir.join("exports").join(&out_name), &data)?;
    case.audit.append(
        &me.username,
        "file.export",
        json!({"evidence": eid, "fs": fi, "record": r.e.record, "path": r.e.path, "stream": stream, "bytes": data.len(), "hashes": hashes, "saved_as": out_name, "deleted": r.e.deleted}),
    )?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", out_name))
        .body(Body::from(data))?)
}

#[derive(Deserialize)]
struct TimelineQ {
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    only: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

/// A timeline bound: an instant ("2026-10-29T23:00:00Z", the start of the
/// examiner's day in their zone) or a bare day, taken as stored (FAT times
/// are the device's clock). The bool says it was a bare day.
fn parse_day(s: &str) -> Option<(u64, bool)> {
    if s.len() > 10 {
        let t = chrono::DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&chrono::Utc);
        return Some((kokino_core::time::datetime_to_filetime(t), false));
    }
    let d = chrono::NaiveDate::parse_from_str(s.get(..10)?, "%Y-%m-%d").ok()?;
    Some((kokino_core::time::datetime_to_filetime(d.and_hms_opt(0, 0, 0)?.and_utc()), true))
}

async fn timeline(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<TimelineQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let needle = q.q.unwrap_or_default().to_lowercase();
    let from = q.from.as_deref().and_then(parse_day).map(|x| x.0).unwrap_or(0);
    // A bare day includes the whole day; an instant is where the range ends.
    let to = q.to.as_deref().and_then(parse_day).map(|(t, day)| if day { t + 86_400 * 10_000_000 } else { t }).unwrap_or(u64::MAX);
    let only = q.only.unwrap_or_default();
    let hits: Vec<&kokino_analysis::timeline::TimelineEvent> = l.fs[fi]
        .timeline
        .iter()
        .filter(|e| {
            if e.t < from || e.t >= to {
                return false;
            }
            if kokino_analysis::timeline::is_web(e.src) {
                let text = web_text(f, e.src, e.idx as usize).0.to_lowercase();
                return (needle.is_empty() || text.contains(&needle)) && matches!(only.as_str(), "" | "web");
            }
            if kokino_analysis::timeline::is_windows(e.src) {
                let Some(w) = kokino_analysis::timeline::system_event(&f.windows, &f.linux.timeline, e.idx as usize) else { return false };
                let hit = needle.is_empty() || w.what.to_lowercase().contains(&needle) || w.detail.to_lowercase().contains(&needle);
                return hit && matches!(only.as_str(), "" | "windows");
            }
            let r = &f.files[e.idx as usize];
            (needle.is_empty() || r.e.path.to_lowercase().contains(&needle))
                && match only.as_str() {
                    "flagged" => !r.flags.is_empty(),
                    "deleted" => r.e.deleted,
                    "si" => e.src == "SI" || e.src == "DEL",
                    "fn" => e.src == "FN",
                    "web" | "windows" => false,
                    _ => true,
                }
        })
        .collect();
    let total = hits.len();
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(300).min(3000);
    let items: Vec<Value> = hits
        .into_iter()
        .skip(off)
        .take(lim)
        .map(|e| {
            if kokino_analysis::timeline::is_web(e.src) {
                let (text, detail, size) = web_text(f, e.src, e.idx as usize);
                return json!({"t": filetime_to_iso(e.t), "macb": e.macb, "src": e.src, "idx": e.idx, "path": text, "detail": detail, "deleted": false, "flags": [], "is_dir": false, "size": size, "web": true});
            }
            if kokino_analysis::timeline::is_windows(e.src) {
                let Some(w) = kokino_analysis::timeline::system_event(&f.windows, &f.linux.timeline, e.idx as usize) else { return json!({}) };
                return json!({"t": filetime_to_iso(e.t), "macb": "", "src": e.src, "idx": e.idx, "path": w.what, "detail": w.detail, "deleted": false, "flags": [], "is_dir": false, "size": 0, "windows": true});
            }
            let r = &f.files[e.idx as usize];
            json!({"t": filetime_to_iso(e.t), "macb": e.macb, "src": e.src, "idx": e.idx, "path": r.e.path, "deleted": r.e.deleted, "flags": r.flags, "is_dir": r.e.is_dir, "size": r.e.size})
        })
        .collect();
    Ok(Json(json!({"total": total, "offset": off, "items": items})))
}

/// (main text, detail, size) for a browser timeline event.
fn web_text(f: &FsAnalysis, src: &str, i: usize) -> (String, String, u64) {
    let w = &f.web;
    let who = |s: u32| w.sources.get(s as usize).map(|x| format!("{} / {} / {}", x.browser, x.user, x.profile)).unwrap_or_default();
    match src {
        "VISIT" => w.visits.get(i).map(|v| (v.url.clone(), format!("{}: {}{}{}", who(v.src), v.how, if v.recovered { " (deleted entry, recovered)" } else { "" }, if v.title.is_empty() { String::new() } else { format!(", {}", v.title) }), 0)).unwrap_or_default(),
        "DL" => w.downloads.get(i).map(|d| (format!("{} -> {}", d.url, d.target), format!("{}: download {}", who(d.src), d.state), d.received.max(0) as u64)).unwrap_or_default(),
        "SEARCH" => w.searches.get(i).map(|s| (format!("\"{}\"", s.term), format!("{}: {} search ({})", who(s.src), s.engine, s.how), 0)).unwrap_or_default(),
        _ => Default::default(),
    }
}

/// Windows artifacts of one volume, with artifact file paths resolved.
async fn windows(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let path = |i: Option<u32>| i.and_then(|i| f.files.get(i as usize)).map(|r| r.e.path.clone());
    let files: std::collections::BTreeMap<u32, Option<String>> = f
        .windows
        .execution
        .iter()
        .map(|x| x.file)
        .chain(f.windows.access.iter().map(|x| x.file))
        .chain(f.windows.events.iter().map(|x| Some(x.file)))
        .chain(f.linux.commands.iter().map(|x| Some(x.file)))
        .chain(f.linux.logons.iter().map(|x| Some(x.file)))
        .chain(f.linux.events.iter().map(|x| Some(x.file)))
        .chain(f.linux.persistence.iter().map(|x| Some(x.file)))
        .flatten()
        .map(|i| (i, path(Some(i))))
        .collect();
    let mut linux = serde_json::to_value(&f.linux)?;
    if let Some(o) = linux.as_object_mut() {
        o.remove("timeline");
        o.remove("hits");
    }
    let mut files = files;
    if let Some(s) = &f.windows.srum {
        files.insert(s.file, path(Some(s.file)));
    }
    for b in &f.windows.shellbags {
        files.insert(b.file, path(Some(b.file)));
        if let Some(v) = b.on_volume {
            files.insert(v, path(Some(v)));
        }
    }
    // The change journal is paged separately (see `journal`); here only
    // its summary.
    let journal = f.windows.journal.as_ref().map(|j| {
        let count = |bit: u32| j.changes.iter().filter(|c| c.c.reasons & bit != 0).count();
        json!({"file": j.file, "path": path(Some(j.file)), "size": j.size, "stored": j.stored, "max": j.max, "created": j.created,
            "first": j.first, "last": j.last, "records": j.records, "dropped": j.dropped, "error": j.error, "changes": j.changes.len(),
            "created_files": count(kokino_artifacts::usn::FILE_CREATE), "deleted_files": count(kokino_artifacts::usn::FILE_DELETE), "renamed_files": count(kokino_artifacts::usn::RENAME_NEW_NAME)})
    });
    let srum_rows = f.windows.srum_rows().map(|(n, u)| json!({"network": n.len(), "usage": u.len()}));
    Ok(Json(json!({"schema": l.analysis.schema, "fs": f.volume.fs_label, "windows": f.windows.without_journal(), "journal": journal, "srum_rows": srum_rows, "linux": linux, "files": files})))
}

#[derive(Deserialize)]
struct SrumQ {
    /// "network" (default) or "usage"
    kind: Option<String>,
    /// Only this program and user (exact).
    app: Option<String>,
    user: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

/// SRUM's hourly rows, newest first, for one program or all.
async fn srum(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<SrumQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let Some((net, usage)) = f.windows.srum_rows() else { return Ok(Json(json!({"total": 0, "offset": 0, "items": []}))) };
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(300).min(3000);
    let ok = |app: &str, user: &str| q.app.as_deref().is_none_or(|a| a == app) && q.user.as_deref().is_none_or(|u| u == user);
    let iso = |t: u64| if t == 0 { String::new() } else { filetime_to_iso(t) };
    let (total, items): (usize, Vec<Value>) = if q.kind.as_deref() == Some("usage") {
        let hits: Vec<_> = usage.iter().rev().filter(|x| ok(&x.app, &x.user)).collect();
        (hits.len(), hits.into_iter().skip(off).take(lim).map(|x| { let mut v = json!(x); v["t_iso"] = json!(iso(x.t)); v }).collect())
    } else {
        let hits: Vec<_> = net.iter().rev().filter(|x| ok(&x.app, &x.user)).collect();
        (hits.len(), hits.into_iter().skip(off).take(lim).map(|x| { let mut v = json!(x); v["t_iso"] = json!(iso(x.t)); v }).collect())
    };
    Ok(Json(json!({"total": total, "offset": off, "items": items})))
}

#[derive(Deserialize)]
struct JournalQ {
    q: Option<String>,
    /// created, deleted, renamed or changed (anything else)
    kind: Option<String>,
    /// Only changes linked to this file.
    file: Option<u32>,
    offset: Option<usize>,
    limit: Option<usize>,
    /// "asc" for oldest first; newest first otherwise.
    order: Option<String>,
}

/// The change journal of a volume, filtered and paged.
async fn journal(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<JournalQ>) -> R {
    use kokino_artifacts::usn::{FILE_CREATE, FILE_DELETE, RENAME_NEW_NAME};
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let Some(j) = f.windows.journal.as_ref() else { return Ok(Json(json!({"total": 0, "offset": 0, "items": []}))) };
    let needle = q.q.unwrap_or_default().to_lowercase();
    let kind = q.kind.unwrap_or_default();
    let ok = |c: &kokino_analysis::windows::JournalChange| {
        let r = c.c.reasons;
        let k = match kind.as_str() {
            "created" => r & FILE_CREATE != 0,
            "deleted" => r & FILE_DELETE != 0,
            "renamed" => r & RENAME_NEW_NAME != 0,
            "changed" => r & (FILE_CREATE | FILE_DELETE | RENAME_NEW_NAME) == 0,
            _ => true,
        };
        k && q.file.is_none_or(|x| c.file == Some(x)) && (needle.is_empty() || c.path.to_lowercase().contains(&needle) || c.old_path.to_lowercase().contains(&needle))
    };
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(300).min(3000);
    let iso = |t: u64| if t == 0 { String::new() } else { filetime_to_iso(t) };
    let item = |c: &kokino_analysis::windows::JournalChange| {
        json!({"t": iso(c.c.t), "first": iso(c.c.first), "usn": c.c.usn, "record": c.c.record, "seq": c.c.seq, "path": c.path, "old_path": c.old_path,
            "what": c.what, "dir": c.dir, "file": c.file, "file_path": c.file.and_then(|i| f.files.get(i as usize)).map(|r| r.e.path.clone())})
    };
    let hits: Vec<&kokino_analysis::windows::JournalChange> = j.changes.iter().filter(|c| ok(c)).collect();
    let items: Vec<Value> = if q.order.as_deref() == Some("asc") {
        hits.iter().skip(off).take(lim).map(|c| item(c)).collect()
    } else {
        hits.iter().rev().skip(off).take(lim).map(|c| item(c)).collect()
    };
    Ok(Json(json!({"total": hits.len(), "offset": off, "items": items})))
}

#[derive(Deserialize)]
struct WebQ {
    kind: Option<String>,
    q: Option<String>,
    src: Option<u32>,
    offset: Option<usize>,
    limit: Option<usize>,
}

/// Browser history: profiles plus one paged list (visits, downloads or searches).
async fn web(State(st): St, Path((cid, eid, fi)): Path<(String, String, usize)>, Query(q): Query<WebQ>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let w = &f.web;
    let needle = q.q.unwrap_or_default().to_lowercase();
    let src_ok = |s: u32| q.src.map(|x| x == s).unwrap_or(true);
    let off = q.offset.unwrap_or(0);
    let lim = q.limit.unwrap_or(300).min(3000);
    let iso = |t: u64| if t == 0 { String::new() } else { filetime_to_iso(t) };
    let (total, items): (usize, Vec<Value>) = match q.kind.as_deref().unwrap_or("visits") {
        "downloads" => {
            let hits: Vec<_> = w.downloads.iter().filter(|d| src_ok(d.src) && (needle.is_empty() || format!("{} {} {}", d.url, d.target, d.referrer).to_lowercase().contains(&needle))).collect();
            (hits.len(), hits.into_iter().skip(off).take(lim).map(|d| { let mut v = json!(d); v["start_iso"] = json!(iso(d.start)); v["end_iso"] = json!(iso(d.end)); v }).collect())
        }
        "cache" => {
            let hits: Vec<_> = w.cache.iter().filter(|c| src_ok(c.src) && (needle.is_empty() || format!("{} {} {}", c.url, c.file, c.content_type).to_lowercase().contains(&needle))).collect();
            (hits.len(), hits.into_iter().skip(off).take(lim).map(|c| { let mut v = json!(c); v["t_iso"] = json!(iso(c.t)); v["modified_iso"] = json!(iso(c.modified)); v }).collect())
        }
        "searches" => {
            let hits: Vec<_> = w.searches.iter().filter(|s| src_ok(s.src) && (needle.is_empty() || format!("{} {}", s.term, s.url).to_lowercase().contains(&needle))).collect();
            (hits.len(), hits.into_iter().skip(off).take(lim).map(|s| { let mut v = json!(s); v["t_iso"] = json!(iso(s.t)); v }).collect())
        }
        _ => {
            let hits: Vec<_> = w.visits.iter().filter(|v| src_ok(v.src) && (needle.is_empty() || format!("{} {}", v.url, v.title).to_lowercase().contains(&needle))).collect();
            (hits.len(), hits.into_iter().skip(off).take(lim).map(|x| { let mut v = json!(x); v["t_iso"] = json!(iso(x.t)); v }).collect())
        }
    };
    let sources: Vec<Value> = w.sources.iter().map(|s| { let mut v = json!(s); v["oldest_iso"] = json!(iso(s.oldest)); v["newest_iso"] = json!(iso(s.newest)); v }).collect();
    Ok(Json(json!({"schema": l.analysis.schema, "sources": sources, "total": total, "offset": off, "items": items,
        "counts": {"visits": w.visits.len(), "downloads": w.downloads.len(), "searches": w.searches.len(), "cache": w.cache.len()}})))
}

async fn indicator_files(State(st): St, Path((cid, eid, fi, id)): Path<(String, String, usize, String)>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let hs = st.hash_status(&cid, &eid);
    let f = fs_of(&l, fi)?;
    let ind = f.indicators.iter().find(|i| i.id == id).ok_or_else(|| anyhow::anyhow!("no such indicator"))?;
    let by_rec: std::collections::HashMap<u64, usize> = f.files.iter().enumerate().map(|(i, r)| (r.e.record, i)).collect();
    let items: Vec<Value> = ind.records.iter().filter_map(|r| by_rec.get(r)).take(500).map(|&i| row(i, &f.files[i], &l, fi, &hs)).collect();
    Ok(Json(json!({"indicator": ind, "items": items})))
}

#[derive(Deserialize)]
struct HexQ {
    offset: Option<u64>,
    len: Option<usize>,
}

async fn hex(State(st): St, Path((cid, eid)): Path<(String, String)>, Query(q): Query<HexQ>) -> R {
    let rec = st.case(&cid)?.evidence_by_id(&eid)?;
    let ev = Evidence::open(&rec.path)?;
    let offset = q.offset.unwrap_or(0).min(ev.size.saturating_sub(1));
    let len = q.len.unwrap_or(4096).min(65536);
    let mut buf = vec![0u8; len];
    let n = read_at(&mut ev.reader()?, offset, &mut buf)?;
    buf.truncate(n);
    let patches: Vec<Patch> = st.case(&cid)?.patches(&eid)?.into_iter().filter(|p| p.offset >= offset && p.offset < offset + n as u64).collect();
    Ok(Json(json!({"offset": offset, "size": ev.size, "data": hex::encode(&buf), "patches": patches})))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    mode: Option<String>,
    from: Option<u64>,
}

/// Raw search across the image. Runs for at most ~1.5 s per call and returns
/// `next` so the GUI can continue where it stopped.
async fn search(State(st): St, Path((cid, eid)): Path<(String, String)>, Query(q): Query<SearchQ>) -> R {
    let rec = st.case(&cid)?.evidence_by_id(&eid)?;
    let ev = Evidence::open(&rec.path)?;
    let mode = q.mode.unwrap_or_else(|| "text".into());
    let mut patterns: Vec<(Vec<u8>, &str)> = vec![];
    if mode == "hex" {
        let clean: String = q.q.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        patterns.push((hex::decode(&clean)?, "hex"));
    } else {
        let lower = q.q.to_lowercase();
        patterns.push((lower.as_bytes().to_vec(), "ascii"));
        patterns.push((lower.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(), "utf16le"));
    }
    if patterns[0].0.is_empty() {
        return Err(anyhow::anyhow!("empty search").into());
    }
    let ci = mode != "hex";
    let from = q.from.unwrap_or(0);
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let maxlen = patterns.iter().map(|p| p.0.len()).max().unwrap();
        let mut r = ev.reader()?;
        let chunk = 8 << 20;
        let mut buf = vec![0u8; chunk + maxlen];
        let mut pos = from;
        let mut hits = vec![];
        let started = std::time::Instant::now();
        while pos < ev.size && hits.len() < 200 && started.elapsed().as_millis() < 1500 {
            let n = read_at(&mut r, pos, &mut buf)?;
            if n == 0 {
                break;
            }
            let hay = &buf[..n];
            for (pat, enc) in &patterns {
                if pat.len() > hay.len() {
                    continue;
                }
                let first = pat[0];
                for i in 0..=hay.len() - pat.len() {
                    if i >= chunk && pos + (n as u64) < ev.size {
                        break;
                    }
                    let b = if ci { hay[i].to_ascii_lowercase() } else { hay[i] };
                    if b != first {
                        continue;
                    }
                    let ok = hay[i..i + pat.len()].iter().zip(pat).all(|(h, p)| (if ci { h.to_ascii_lowercase() } else { *h }) == *p);
                    if ok && hits.len() < 200 {
                        let o = pos + i as u64;
                        let s = i.saturating_sub(24);
                        let e = (i + pat.len() + 24).min(hay.len());
                        hits.push(json!({"offset": o, "enc": enc, "context": hex::encode(&hay[s..e]), "context_start": pos + s as u64}));
                    }
                }
            }
            pos += chunk as u64;
        }
        hits.sort_by_key(|h| h["offset"].as_u64());
        let done = pos >= ev.size;
        Ok(json!({"hits": hits, "next": if done { Value::Null } else { json!(pos.min(ev.size)) }, "size": ev.size}))
    })
    .await??;
    Ok(Json(res))
}

// ---------------------------------------------------------------- bookmarks

async fn bookmarks_list(State(st): St, Path(cid): Path<String>) -> R {
    let case = st.case(&cid)?;
    let list = kokino_core::bookmarks::load(&case.bookmarks_path())?;
    let mut tags: std::collections::BTreeMap<String, u64> = Default::default();
    for b in &list {
        for t in &b.tags {
            *tags.entry(t.clone()).or_default() += 1;
        }
    }
    Ok(Json(json!({"bookmarks": list, "tags": tags, "suggested": kokino_core::bookmarks::SUGGESTED_TAGS})))
}

#[derive(Deserialize)]
struct NewBookmark {
    evidence: String,
    kind: String,
    key: String,
    fi: Option<usize>,
    record: Option<u64>,
    idx: Option<u64>,
    offset: Option<u64>,
    len: Option<u64>,
    carved: Option<u32>,
    region: Option<[u32; 4]>,
    #[serde(default)]
    view: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    time: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: String,
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control() || *c == '\n').take(n).collect()
}

/// Adds a bookmark, or updates tags and note when the item already has one.
/// For files and carved files the snapshot (name, path, size, hashes) comes
/// from the evidence, not from the request.
async fn bookmark_add(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(b): Json<NewBookmark>) -> R {
    let case = st.case(&cid)?;
    case.evidence_by_id(&b.evidence)?;
    if !["file", "event", "carved", "hit", "offset", "web"].contains(&b.kind.as_str()) || b.key.is_empty() || b.key.len() > 400 {
        return Err(anyhow::anyhow!("bad bookmark").into());
    }
    let tags = kokino_core::bookmarks::clean_tags(&b.tags)?;
    let now = now_iso();
    let mut bm = kokino_core::bookmarks::Bookmark {
        id: uuid::Uuid::new_v4().simple().to_string()[..12].to_string(),
        key: b.key.clone(),
        evidence: b.evidence.clone(),
        kind: b.kind.clone(),
        fi: b.fi,
        record: b.record,
        idx: b.idx,
        offset: b.offset,
        len: b.len,
        carved: b.carved,
        region: b.region.filter(|r| r[2] > 0 && r[3] > 0),
        view: clip(&b.view, 40),
        title: clip(&b.title, 300),
        detail: clip(&b.detail, 2000),
        path: clip(&b.path, 2000),
        time: clip(&b.time, 40),
        tags: tags.clone(),
        note: clip(&b.note, 4000),
        created_by: me.username.clone(),
        created_at: now.clone(),
        updated_by: me.username.clone(),
        updated_at: now,
        ..Default::default()
    };
    if b.kind == "file" {
        let (fi, rec) = (b.fi.ok_or_else(|| anyhow::anyhow!("fi required"))?, b.record.ok_or_else(|| anyhow::anyhow!("record required"))?);
        let l = st.loaded(&cid, &b.evidence)?;
        let f = fs_of(&l, fi)?;
        let (idx, r) = f.files.iter().enumerate().find(|(_, r)| r.e.record == rec).ok_or_else(|| anyhow::anyhow!("no such file"))?;
        bm.idx = Some(idx as u64);
        bm.title = r.e.name.clone();
        bm.path = r.e.path.clone();
        bm.size = Some(r.e.size);
        bm.deleted = r.e.deleted;
        bm.time = r.e.si.map(|t| filetime_to_iso(t.modified)).unwrap_or_default();
        if !r.e.is_dir && r.e.size <= 1 << 30 {
            let (l2, e, size) = (l.clone(), r.e.clone(), r.e.size as usize);
            let data = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> { l2.read_file(fi, &e, "", 0, size) })
            .await?;
            match data {
                Ok(d) => {
                    let (h, _) = kokino_core::hashing::hash_reader(&d[..], |_| true)?;
                    bm.md5 = h.md5;
                    bm.sha256 = h.sha256;
                }
                Err(e) => bm.detail = format!("content not readable: {:#}", e),
            }
        }
    } else if b.kind == "carved" {
        let res = jobs::load_carved(&case, &b.evidence).ok_or_else(|| anyhow::anyhow!("this evidence has not been carved"))?;
        let c = res.files.iter().find(|f| Some(f.id) == b.carved).ok_or_else(|| anyhow::anyhow!("no such carved file"))?;
        bm.title = format!("Carved {} #{}", c.label, c.id);
        bm.detail = c.detail.clone();
        bm.path = format!("{} at offset {}", c.region, c.offset);
        bm.offset = Some(c.offset);
        bm.len = Some(c.len);
        bm.size = Some(c.len);
        bm.md5 = c.md5.clone();
        bm.sha256 = c.sha256.clone();
    }
    let _g = st.bookmarks.lock().unwrap();
    let path = case.bookmarks_path();
    let mut list = kokino_core::bookmarks::load(&path)?;
    let access = case_access(&me, &case.info.members).ok_or_else(|| anyhow::anyhow!("no access"))?;
    let out = if let Some(existing) = list.iter_mut().find(|x| x.key == bm.key) {
        if !access.can_write() && existing.created_by != me.username {
            return Err(anyhow::anyhow!("this item is bookmarked by {}; reviewers can change only their own bookmarks", existing.created_by).into());
        }
        existing.tags = tags;
        existing.note = bm.note.clone();
        existing.updated_by = me.username.clone();
        existing.updated_at = now_iso();
        case.audit.append(&me.username, "bookmark.update", json!({"id": existing.id, "key": existing.key, "tags": existing.tags, "note": existing.note}))?;
        existing.clone()
    } else {
        case.audit.append(&me.username, "bookmark.add", json!({"id": bm.id, "evidence": bm.evidence, "kind": bm.kind, "key": bm.key, "title": bm.title, "tags": bm.tags, "note": bm.note, "sha256": bm.sha256}))?;
        list.push(bm.clone());
        bm
    };
    kokino_core::bookmarks::save(&path, &list)?;
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
struct EditBookmark {
    tags: Vec<String>,
    #[serde(default)]
    note: String,
}

fn own_or_examiner(st: &AppState, me: &CurrentUser, case: &Case, b: &kokino_core::bookmarks::Bookmark) -> anyhow::Result<()> {
    let _ = st;
    let access = case_access(me, &case.info.members).ok_or_else(|| anyhow::anyhow!("no access"))?;
    if !access.can_write() && b.created_by != me.username {
        anyhow::bail!("reviewers can change only their own bookmarks");
    }
    Ok(())
}

async fn bookmark_edit(State(st): St, Extension(me): Me, Path((cid, id)): Path<(String, String)>, Json(e): Json<EditBookmark>) -> R {
    let case = st.case(&cid)?;
    let tags = kokino_core::bookmarks::clean_tags(&e.tags)?;
    let _g = st.bookmarks.lock().unwrap();
    let path = case.bookmarks_path();
    let mut list = kokino_core::bookmarks::load(&path)?;
    let b = list.iter_mut().find(|b| b.id == id).ok_or_else(|| anyhow::anyhow!("no such bookmark"))?;
    own_or_examiner(&st, &me, &case, b)?;
    b.tags = tags;
    b.note = clip(&e.note, 4000);
    b.updated_by = me.username.clone();
    b.updated_at = now_iso();
    let out = b.clone();
    case.audit.append(&me.username, "bookmark.update", json!({"id": out.id, "key": out.key, "tags": out.tags, "note": out.note}))?;
    kokino_core::bookmarks::save(&path, &list)?;
    Ok(Json(json!(out)))
}

async fn bookmark_delete(State(st): St, Extension(me): Me, Path((cid, id)): Path<(String, String)>) -> R {
    let case = st.case(&cid)?;
    let _g = st.bookmarks.lock().unwrap();
    let path = case.bookmarks_path();
    let mut list = kokino_core::bookmarks::load(&path)?;
    let pos = list.iter().position(|b| b.id == id).ok_or_else(|| anyhow::anyhow!("no such bookmark"))?;
    own_or_examiner(&st, &me, &case, &list[pos])?;
    let b = list.remove(pos);
    case.audit.append(&me.username, "bookmark.delete", json!({"id": b.id, "key": b.key, "title": b.title, "tags": b.tags}))?;
    kokino_core::bookmarks::save(&path, &list)?;
    Ok(Json(json!({"ok": true})))
}

async fn by_record(State(st): St, Path((cid, eid, fi, rec)): Path<(String, String, usize, u64)>) -> R {
    let l = st.loaded(&cid, &eid)?;
    let f = fs_of(&l, fi)?;
    let idx = f.files.iter().position(|r| r.e.record == rec).ok_or_else(|| anyhow::anyhow!("no such record"))?;
    Ok(Json(json!({"idx": idx})))
}

#[derive(Deserialize)]
struct BmReportQ {
    tag: Option<String>,
}

/// HTML report of bookmarked items, optionally one tag only.
async fn bookmarks_report(State(st): St, Extension(me): Me, Path(cid): Path<String>, Query(q): Query<BmReportQ>) -> Result<Html<String>, AppError> {
    let case = st.case(&cid)?;
    let all = kokino_core::bookmarks::load(&case.bookmarks_path())?;
    let tag = q.tag.filter(|t| !t.is_empty());
    let list: Vec<&kokino_core::bookmarks::Bookmark> = all.iter().filter(|b| tag.as_ref().map(|t| b.tags.iter().any(|x| x.eq_ignore_ascii_case(t))).unwrap_or(true)).collect();
    let evname = |eid: &str| case.evidence_by_id(eid).map(|e| e.name).unwrap_or_else(|_| eid.to_string());
    let mut h = format!(
        "<!doctype html><html><head><meta charset=utf-8><title>Kokino bookmarks: {}</title><style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 16px;color:#1d1d1f}}h1{{margin-bottom:0}}table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}td,th{{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}}th{{background:#f4f4f6}}code{{font:12px ui-monospace,monospace;word-break:break-all}}.muted{{color:#666}}.tag{{display:inline-block;border:1px solid #bbb;border-radius:3px;padding:0 5px;margin:0 3px 3px 0;font-size:12px}}</style></head><body>",
        esc(&case.info.name)
    );
    h.push_str(&format!(
        "<h1>{}</h1><p class=muted>Bookmarked items{} &middot; {} item(s) &middot; generated {} by {} with {} {}</p>",
        esc(&case.info.name),
        tag.as_ref().map(|t| format!(" tagged <b>{}</b>", esc(t))).unwrap_or_default(),
        list.len(),
        human(&now_iso()),
        esc(&me.username),
        kokino_core::TOOL_NAME,
        kokino_core::TOOL_VERSION
    ));
    h.push_str("<table><tr><th>#</th><th>Item</th><th>Where</th><th>Time (UTC)</th><th>Hashes</th><th>Tags and note</th><th>Bookmarked</th></tr>");
    for (i, b) in list.iter().enumerate() {
        let where_ = match b.kind.as_str() {
            "file" => format!("{}<br><code>{}</code>{}", esc(&evname(&b.evidence)), esc(&b.path), if b.deleted { " <b>(deleted)</b>" } else { "" }) + &region_text(b),
            _ => format!(
                "{}<br>{}{}",
                esc(&evname(&b.evidence)),
                esc(&b.path),
                b.offset.map(|o| format!("<br>image offset {}{}", o, b.len.map(|l| format!(", {} bytes", l)).unwrap_or_default())).unwrap_or_default()
            ),
        };
        let hashes = if b.sha256.is_empty() { String::new() } else { format!("<code>MD5 {}</code><br><code>SHA-256 {}</code>", esc(&b.md5), esc(&b.sha256)) };
        h.push_str(&format!(
            "<tr><td>{}</td><td><b>{}</b> <span class=muted>({})</span><br>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}<br>{}</td><td>{}<br><span class=muted>{}</span></td></tr>",
            i + 1,
            esc(&b.title),
            esc(&b.kind),
            esc(&b.detail),
            where_,
            esc(&human_full(&b.time)),
            hashes,
            b.tags.iter().map(|t| format!("<span class=tag>{}</span>", esc(t))).collect::<Vec<_>>().join(""),
            esc(&b.note).replace('\n', "<br>"),
            esc(&b.created_by),
            esc(&human(&b.created_at))
        ));
    }
    h.push_str("</table><p class=muted>Each file's hashes were computed from the evidence when it was bookmarked. Every bookmark change is recorded in the case audit log.</p></body></html>");
    case.audit.append(&me.username, "bookmarks.report", json!({"tag": tag, "items": list.len()}))?;
    Ok(Html(h))
}

/// Court-ready case report (see `casereport`), saved in the case exports.
async fn case_report(State(st): St, Extension(me): Me, Path(cid): Path<String>, Json(o): Json<crate::casereport::ReportOptions>) -> R {
    let g = tokio::task::spawn_blocking(move || crate::casereport::generate(&st, &cid, &me.username, &me.display_name, &o)).await??;
    Ok(Json(json!(g)))
}

async fn case_reports(State(st): St, Path(cid): Path<String>) -> R {
    let case = st.case(&cid)?;
    Ok(Json(json!(tokio::task::spawn_blocking(move || crate::casereport::list(&case)).await??)))
}

/// A saved case report: HTML shown in the browser, Word downloaded.
async fn case_report_file(State(st): St, Path((cid, name)): Path<(String, String)>) -> Result<Response, AppError> {
    let case = st.case(&cid)?;
    let data = std::fs::read(crate::casereport::file_path(&case, &name)?).map_err(|_| anyhow::anyhow!("report file not found"))?;
    let b = Response::builder().header("x-content-type-options", "nosniff").header(header::CACHE_CONTROL, "no-store");
    Ok(if name.ends_with(".html") {
        b.header(header::CONTENT_TYPE, "text/html; charset=utf-8").body(Body::from(data))?
    } else {
        b.header(header::CONTENT_TYPE, "application/vnd.openxmlformats-officedocument.wordprocessingml.document").header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name)).body(Body::from(data))?
    })
}

/// "Region 120,80 200x150 px (error level view)" for picture-region bookmarks.
fn region_text(b: &kokino_core::bookmarks::Bookmark) -> String {
    match b.region {
        Some([x, y, w, h]) => format!("<br>Region {},{} {}x{} px{}", x, y, w, h, if b.view.is_empty() { String::new() } else { format!(" ({} view)", esc(&b.view)) }),
        None => String::new(),
    }
}

fn photo_rules() -> Value {
    Value::Array(kokino_analysis::photo::RULES.iter().map(|r| json!({"id": r.id, "title": r.title, "flag": r.flag, "explanation": r.explanation, "caveat": r.caveat})).collect())
}

async fn photos_list(State(st): St, Path((cid, eid)): Path<(String, String)>) -> R {
    let case = st.case(&cid)?;
    case.evidence_by_id(&eid)?;
    Ok(Json(json!({"result": jobs::load_photos(&case, &eid), "rules": photo_rules()})))
}

async fn photos_start(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>) -> R {
    st.case(&cid)?.evidence_by_id(&eid)?;
    st.loaded(&cid, &eid)?;
    let busy = st.jobs.lock().unwrap().values().any(|j| {
        let v = j.view.lock().unwrap();
        v.case == cid && v.evidence == eid && v.state == "running"
    });
    if busy {
        return Err(anyhow::anyhow!("another job is still running on this evidence").into());
    }
    let job = jobs::spawn_photos(st.clone(), &me.username, cid, eid);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

fn image_type(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(b"\xFF\xD8\xFF") {
        Some("image/jpeg")
    } else if d.starts_with(b"\x89PNG") {
        Some("image/png")
    } else if d.starts_with(b"GIF8") {
        Some("image/gif")
    } else if d.starts_with(b"BM") {
        Some("image/bmp")
    } else if d.len() > 12 && &d[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

fn file_content(st: &AppState, cid: &str, eid: &str, fi: usize, idx: usize) -> anyhow::Result<(FileRow, Vec<u8>)> {
    let l = st.loaded(cid, eid)?;
    let f = fs_of(&l, fi)?;
    let r = f.files.get(idx).ok_or_else(|| anyhow::anyhow!("no such file"))?.clone();
    if r.e.is_dir || r.e.size > kokino_analysis::photo::MAX_BYTES {
        anyhow::bail!("not a picture Kokino can open (directory or over {} MiB)", kokino_analysis::photo::MAX_BYTES >> 20);
    }
    let d = l.read_file(fi, &r.e, "", 0, r.e.size as usize)?;
    Ok((r, d))
}

/// A file's content as a picture for the viewer: raster formats only,
/// identified by content, served with nosniff.
async fn file_image(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>) -> Result<Response, AppError> {
    let (_, d) = tokio::task::spawn_blocking(move || file_content(&st, &cid, &eid, fi, idx)).await??;
    let ct = image_type(&d).ok_or_else(|| anyhow::anyhow!("the content is not a JPEG, PNG, GIF, BMP or WebP picture"))?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, ct)
        .header("x-content-type-options", "nosniff")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .body(Body::from(d))?)
}

async fn file_photo(State(st): St, Path((cid, eid, fi, idx)): Path<(String, String, usize, usize)>) -> R {
    let report = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let (r, d) = file_content(&st, &cid, &eid, fi, idx)?;
        Ok(json!(kokino_analysis::photo::analyze(&d, &r.e.path)))
    })
    .await??;
    Ok(Json(json!({"report": report, "rules": photo_rules()})))
}

async fn carved_photo(State(st): St, Path((cid, eid, id)): Path<(String, String, u32)>) -> R {
    let report = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let (_, d, _) = carved_bytes(&st, &cid, &eid, id, kokino_analysis::photo::MAX_BYTES)?;
        Ok(json!(kokino_analysis::photo::analyze(&d, "")))
    })
    .await??;
    Ok(Json(json!({"report": report, "rules": photo_rules()})))
}

async fn carved_list(State(st): St, Path((cid, eid)): Path<(String, String)>) -> R {
    let case = st.case(&cid)?;
    case.evidence_by_id(&eid)?;
    let mut v = json!(jobs::load_carved(&case, &eid));
    if let Some(recs) = v.get_mut("records").and_then(|r| r.as_array_mut()) {
        for r in recs {
            let t = r["t"].as_u64().unwrap_or(0);
            r["t_iso"] = json!(if t == 0 { String::new() } else { filetime_to_iso(t) });
        }
    }
    Ok(Json(json!({"result": v})))
}

async fn carve_start(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>) -> R {
    st.case(&cid)?.evidence_by_id(&eid)?;
    st.loaded(&cid, &eid)?;
    let busy = st.jobs.lock().unwrap().values().any(|j| {
        let v = j.view.lock().unwrap();
        v.case == cid && v.evidence == eid && v.state == "running"
    });
    if busy {
        return Err(anyhow::anyhow!("another job is still running on this evidence").into());
    }
    let job = jobs::spawn_carve(st.clone(), &me.username, cid, eid);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

fn carved_bytes(st: &AppState, cid: &str, eid: &str, id: u32, max: u64) -> anyhow::Result<(kokino_analysis::carve::Carved, Vec<u8>, Case)> {
    let case = st.case(cid)?;
    let res = jobs::load_carved(&case, eid).ok_or_else(|| anyhow::anyhow!("this evidence has not been carved"))?;
    let f = res.files.into_iter().find(|f| f.id == id).ok_or_else(|| anyhow::anyhow!("no such carved file"))?;
    if f.len > max {
        anyhow::bail!("carved file is {} bytes; larger than {}", f.len, max);
    }
    let rec = case.evidence_by_id(eid)?;
    let ev = Evidence::open(&rec.path)?;
    let mut buf = vec![0u8; f.len as usize];
    let n = read_at(&mut ev.reader()?, f.offset, &mut buf)?;
    buf.truncate(n);
    Ok((f, buf, case))
}

/// Carved pictures for the gallery. Raster formats only (never SVG or
/// HTML), served with nosniff so the browser cannot reinterpret them.
async fn carved_preview(State(st): St, Path((cid, eid, id)): Path<(String, String, u32)>) -> Result<Response, AppError> {
    let st2 = st.clone();
    let (f, buf, _) = tokio::task::spawn_blocking(move || carved_bytes(&st2, &cid, &eid, id, 32 << 20)).await??;
    let ct = match f.kind.as_str() {
        "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        _ => return Err(anyhow::anyhow!("no preview for {}", f.kind).into()),
    };
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, ct)
        .header("x-content-type-options", "nosniff")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .body(Body::from(buf))?)
}

async fn carved_export(State(st): St, Extension(me): Me, Path((cid, eid, id)): Path<(String, String, u32)>) -> Result<Response, AppError> {
    let st2 = st.clone();
    let (c2, e2) = (cid.clone(), eid.clone());
    let (f, buf, case) = tokio::task::spawn_blocking(move || carved_bytes(&st2, &c2, &e2, id, 1 << 30)).await??;
    let (hashes, _) = kokino_core::hashing::hash_reader(&buf[..], |_| true)?;
    let name = format!("{}_carved_{}_{}.{}", eid, f.id, f.offset, f.ext.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_"));
    std::fs::write(case.dir.join("exports").join(&name), &buf)?;
    case.audit.append(
        &me.username,
        "carved.export",
        json!({"evidence": eid, "carved_id": f.id, "kind": f.kind, "offset": f.offset, "bytes": buf.len(), "hashes": hashes, "matches_carve_hash": hashes.sha256 == f.sha256, "saved_as": name}),
    )?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name))
        .body(Body::from(buf))?)
}

async fn text_index(State(st): St, Path((cid, eid)): Path<(String, String)>) -> R {
    let case = st.case(&cid)?;
    case.evidence_by_id(&eid)?;
    let path = case.index_path(&eid)?;
    let stats = kokino_analysis::textindex::stats(&path);
    // An index file that stats() rejects is from an older index schema.
    let outdated = stats.is_none() && path.exists();
    let presets: Vec<Value> = kokino_analysis::textindex::PRESETS.iter().map(|p| json!({"id": p.id, "label": p.label, "pattern": p.pattern})).collect();
    Ok(Json(json!({"stats": stats, "outdated": outdated, "presets": presets})))
}

async fn build_text_index(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>) -> R {
    st.case(&cid)?.evidence_by_id(&eid)?;
    st.loaded(&cid, &eid)?;
    let busy = st.jobs.lock().unwrap().values().any(|j| {
        let v = j.view.lock().unwrap();
        v.case == cid && v.evidence == eid && v.state == "running"
    });
    if busy {
        return Err(anyhow::anyhow!("another job is still running on this evidence").into());
    }
    let job = jobs::spawn_index(st.clone(), &me.username, cid, eid);
    let view = job.view.lock().unwrap().clone();
    Ok(Json(json!(view)))
}

#[derive(Deserialize)]
struct TextSearchQ {
    q: String,
    /// keyword (default), regex or preset (q is then the preset id)
    mode: Option<String>,
    /// all (default), files, deleted, unallocated
    scope: Option<String>,
    fi: Option<usize>,
    case: Option<bool>,
    limit: Option<usize>,
}

async fn text_search(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Query(q): Query<TextSearchQ>) -> R {
    use kokino_analysis::textindex::{self, Mode, Scope};
    let case = st.case(&cid)?;
    let path = case.index_path(&eid)?;
    if textindex::stats(&path).is_none() {
        return Err(anyhow::anyhow!("this evidence has no text index yet; build it first").into());
    }
    let l = st.loaded(&cid, &eid)?;
    let mode_name = q.mode.clone().unwrap_or_else(|| "keyword".into());
    let mode = match mode_name.as_str() {
        "regex" => Mode::Regex { pattern: q.q.clone(), case_sensitive: q.case.unwrap_or(false) },
        "preset" => Mode::Preset(textindex::preset(&q.q).ok_or_else(|| anyhow::anyhow!("unknown preset"))?),
        _ => Mode::Keyword(q.q.clone()),
    };
    let scope = match q.scope.as_deref() {
        Some("files") => Scope::Files,
        Some("deleted") => Scope::Deleted,
        Some("unallocated") => Scope::Unallocated,
        _ => Scope::All,
    };
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let (fi, l2) = (q.fi, l.clone());
    let res = tokio::task::spawn_blocking(move || textindex::search(&path, &l2.analysis, &mode, scope, fi, limit, 15_000)).await??;
    let hits: Vec<Value> = res
        .hits
        .iter()
        .map(|h| {
            let f = h.fi.zip(h.file).and_then(|(fi, f)| l.analysis.filesystems.get(fi).and_then(|x| x.files.get(f)));
            json!({
                "fi": h.fi, "source": h.source, "file": h.file, "stream": h.stream, "part": h.part, "carved": h.carved, "offset": h.offset,
                "image_offset": h.image_offset, "enc": h.enc, "matched": h.matched, "before": h.before, "after": h.after,
                "path": f.map(|f| f.e.path.clone()), "deleted": f.map(|f| f.e.deleted).unwrap_or(false),
            })
        })
        .collect();
    case.audit.append(
        &me.username,
        "search.text",
        json!({"evidence": eid, "mode": mode_name, "query": q.q, "scope": q.scope.unwrap_or_else(|| "all".into()), "hits": hits.len(), "truncated": res.truncated}),
    )?;
    Ok(Json(json!({"hits": hits, "truncated": res.truncated, "chunks_scanned": res.chunks_scanned, "elapsed_ms": res.elapsed_ms})))
}

#[derive(Deserialize)]
struct CarveQ {
    offset: u64,
    len: u64,
    patched: Option<bool>,
}

/// Exports a raw byte range (optionally with the hex overlay applied) and
/// records it in the audit log. Evidence is never modified.
async fn carve(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Query(q): Query<CarveQ>) -> Result<Response, AppError> {
    if q.len == 0 || q.len > 256 << 20 {
        return Err(anyhow::anyhow!("length must be 1 byte to 256 MiB").into());
    }
    let case = st.case(&cid)?;
    let rec = case.evidence_by_id(&eid)?;
    let ev = Evidence::open(&rec.path)?;
    let mut buf = vec![0u8; q.len as usize];
    let n = read_at(&mut ev.reader()?, q.offset, &mut buf)?;
    buf.truncate(n);
    let patched = q.patched.unwrap_or(false);
    let mut applied = 0;
    if patched {
        for p in case.patches(&eid)? {
            if p.offset >= q.offset && p.offset < q.offset + n as u64 {
                buf[(p.offset - q.offset) as usize] = p.value;
                applied += 1;
            }
        }
    }
    let (hashes, _) = kokino_core::hashing::hash_reader(&buf[..], |_| true)?;
    let name = format!("{}_carve_{}_{}{}.bin", eid, q.offset, n, if patched { "_patched" } else { "" });
    std::fs::write(case.dir.join("exports").join(&name), &buf)?;
    case.audit.append(&me.username, "range.export", json!({"evidence": eid, "offset": q.offset, "bytes": n, "patched": patched, "patches_applied": applied, "hashes": hashes, "saved_as": name}))?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name))
        .body(Body::from(buf))?)
}

async fn list_patches(State(st): St, Path((cid, eid)): Path<(String, String)>) -> R {
    Ok(Json(json!(st.case(&cid)?.patches(&eid)?)))
}

#[derive(Deserialize)]
struct NewPatch {
    offset: u64,
    value: u8,
    note: Option<String>,
}

async fn add_patch(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Json(b): Json<NewPatch>) -> R {
    let case = st.case(&cid)?;
    let rec = case.evidence_by_id(&eid)?;
    let ev = Evidence::open(&rec.path)?;
    if b.offset >= ev.size {
        return Err(anyhow::anyhow!("offset beyond end of image").into());
    }
    let mut one = [0u8; 1];
    read_at(&mut ev.reader()?, b.offset, &mut one)?;
    let mut patches = case.patches(&eid)?;
    patches.retain(|p| p.offset != b.offset);
    if b.value != one[0] {
        patches.push(Patch { offset: b.offset, original: one[0], value: b.value, time: now_iso(), note: b.note.clone().unwrap_or_default() });
    }
    patches.sort_by_key(|p| p.offset);
    case.save_patches(&eid, &patches)?;
    case.audit.append(&me.username, "overlay.set", json!({"evidence": eid, "offset": b.offset, "original": one[0], "value": b.value, "note": b.note}))?;
    Ok(Json(json!(patches)))
}

#[derive(Deserialize)]
struct DelPatchQ {
    offset: Option<u64>,
}

async fn del_patch(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>, Query(q): Query<DelPatchQ>) -> R {
    let case = st.case(&cid)?;
    let mut patches = case.patches(&eid)?;
    let before = patches.len();
    match q.offset {
        Some(o) => patches.retain(|p| p.offset != o),
        None => patches.clear(),
    }
    case.save_patches(&eid, &patches)?;
    case.audit.append(&me.username, "overlay.remove", json!({"evidence": eid, "offset": q.offset, "removed": before - patches.len()}))?;
    Ok(Json(json!(patches)))
}

/// Browser profiles, all downloads and all searches; visits are counted
/// (they are listed in full in the GUI).
/// Windows artifacts: the facts a report reader needs, each with its source.
fn report_windows(h: &mut String, w: &kokino_analysis::windows::WindowsArtifacts, f: &FsAnalysis) {
    if w.is_empty() {
        return;
    }
    let t = |ft: u64| if ft == 0 { String::new() } else { filetime_to_iso(ft) };
    let src = |i: Option<u32>| i.and_then(|i| f.files.get(i as usize)).map(|r| format!("<code>{}</code>", esc(&r.e.path))).unwrap_or_default();
    let c = &w.computer;
    h.push_str("<h3>Windows system</h3><table>");
    for (k, v) in [
        ("Computer name", c.name.clone()),
        ("Windows", format!("{} {} (build {}, {})", c.os, c.version, c.build, c.edition)),
        ("Installed (UTC)", t(c.install_time)),
        ("Registered owner", c.owner.clone()),
        ("Time zone", format!("{}{}", c.time_zone, c.active_bias_minutes.map(|b| format!(" (ActiveTimeBias {} min)", b)).unwrap_or_default())),
        ("Last shutdown (UTC)", t(c.last_shutdown)),
    ] {
        if !v.trim().is_empty() {
            h.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", k, esc(&v)));
        }
    }
    h.push_str("</table>");
    let flagged: Vec<&kokino_analysis::windows::WinEvent> = w.events.iter().filter(|e| matches!(e.category.as_str(), "Log cleared" | "Account" | "Service")).collect();
    if !flagged.is_empty() {
        h.push_str("<h4>Log clearing, account and service changes</h4><table><tr><th>Time (UTC)</th><th>Event</th><th>What happened</th><th>Log file</th></tr>");
        for e in flagged {
            let bad = if e.category == "Log cleared" { " class=bad" } else { "" };
            h.push_str(&format!("<tr><td>{}</td><td>{} {}</td><td{}>{}</td><td>{}</td></tr>", t(e.time), e.event_id, esc(&e.title), bad, esc(&e.summary), src(Some(e.file))));
        }
        h.push_str("</table>");
    }
    let tools: Vec<&kokino_analysis::windows::Execution> = w.execution.iter().filter(|x| x.tool).collect();
    if !tools.is_empty() {
        h.push_str("<h4>Anti-forensic tools in execution records</h4><table><tr><th>Program</th><th>Source</th><th>Runs</th><th>Times (UTC)</th><th>Artifact</th></tr>");
        for x in tools {
            h.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&x.program), esc(&x.source), x.count.map(|n| n.to_string()).unwrap_or_default(), x.times.iter().map(|&ts| t(ts)).collect::<Vec<_>>().join("<br>"), src(x.file)
            ));
        }
        h.push_str("</table>");
    }
    if !w.usb.is_empty() {
        h.push_str("<h4>USB storage devices</h4><table><tr><th>Device</th><th>Serial</th><th>Drive</th><th>First connected (UTC)</th><th>Last connected (UTC)</th><th>Last removed (UTC)</th></tr>");
        for u in &w.usb {
            h.push_str(&format!("<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", esc(&u.name), esc(&u.serial), esc(&u.drive_letter), t(u.first_connected), t(u.last_connected), t(u.last_removed)));
        }
        h.push_str("</table>");
    }
    // Folders opened on other drives and on shares: where data went.
    let away: Vec<&kokino_analysis::windows::ShellBag> = w
        .shellbags
        .iter()
        .filter(|b| b.bag.kind != "drive" && (b.bag.path.starts_with("\\\\") || (b.bag.path.len() > 2 && b.bag.path.as_bytes()[1] == b':' && !b.bag.path.starts_with("C:"))))
        .collect();
    if !away.is_empty() {
        h.push_str("<h4>Folders opened on other drives and network shares (ShellBags)</h4><table><tr><th>Folder</th><th>User</th><th>Last opened (UTC)</th><th>Hive</th></tr>");
        for b in away.iter().take(500) {
            h.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>", esc(&b.bag.path), esc(&b.user), t(b.bag.opened), src(Some(b.file))));
        }
        h.push_str("</table>");
    }
    if let Some(j) = w.journal.as_ref().filter(|j| j.records > 0) {
        let del = j.changes.iter().filter(|c| c.c.reasons & kokino_artifacts::usn::FILE_DELETE != 0).count();
        h.push_str(&format!(
            "<h4>Change journal</h4><p>{} records from {} to {} (UTC): {} file changes, {} deletions.{}</p>",
            j.records,
            t(j.first),
            t(j.last),
            j.changes.len() as u64 + j.dropped,
            del,
            if j.dropped > 0 { format!(" The oldest {} changes were not kept.", j.dropped) } else { String::new() }
        ));
        // A rename from a real name to AAAA.AAA starts a wipe: the old name is the file's own.
        let wiped: Vec<&kokino_analysis::windows::JournalChange> = j
            .changes
            .iter()
            .filter(|c| kokino_analysis::antiforensics::sdelete_like(&c.c.name) && c.c.old.as_ref().is_some_and(|o| !kokino_analysis::antiforensics::sdelete_like(&o.0)))
            .collect();
        if !wiped.is_empty() {
            h.push_str("<table><tr><th>Wiped file (original name)</th><th>Renamed to</th><th>Time (UTC)</th></tr>");
            for c in wiped.iter().take(500) {
                h.push_str(&format!("<tr><td class=bad><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>", esc(&c.old_path), esc(&c.path), t(c.c.t)));
            }
            h.push_str("</table>");
        }
    }
    if let Some(s) = w.srum.as_ref().filter(|s| s.first > 0) {
        let top: Vec<&kokino_analysis::windows::SrumApp> = s.apps.iter().filter(|a| a.sent >= 1 << 20).take(20).collect();
        h.push_str(&format!("<h4>Network use per program (SRUM, {} to {} UTC)</h4>", t(s.first), t(s.last)));
        if top.is_empty() {
            h.push_str("<p>No program sent 1 MiB or more.</p>");
        } else {
            h.push_str("<table><tr><th>Program</th><th>User</th><th>Sent (bytes)</th><th>Received (bytes)</th><th>First (UTC)</th><th>Last (UTC)</th></tr>");
            for a in top {
                h.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", esc(&a.app), esc(&a.user), a.sent, a.received, t(a.first), t(a.last)));
            }
            h.push_str("</table>");
        }
        if s.dirty {
            h.push_str("<p class=muted>The SRUM database was not cleanly closed; the newest hours may be only in its transaction logs, which were not read.</p>");
        }
    }
    let odd: Vec<&kokino_analysis::windows::Autorun> = w.autoruns.iter().filter(|a| a.unusual).collect();
    if !odd.is_empty() {
        h.push_str("<h4>Autostart entries from unusual locations</h4><table><tr><th>Name</th><th>Command</th><th>Where</th></tr>");
        for a in odd {
            h.push_str(&format!("<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>", esc(&a.name), esc(&a.command), esc(&a.location)));
        }
        h.push_str("</table>");
    }
    let tasks: Vec<&kokino_analysis::windows::ScheduledTask> = w.tasks.iter().filter(|k| !k.microsoft || k.unusual || k.sd_removed).collect();
    if !tasks.is_empty() {
        h.push_str(&format!("<h4>Scheduled tasks ({} of {}; Windows' own left out)</h4><table><tr><th>Task</th><th>Runs</th><th>Triggers</th><th>Account</th><th>Created (UTC)</th><th>Last run (UTC)</th><th>Notes</th></tr>", tasks.len(), w.tasks.len()));
        for k in tasks {
            h.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&k.path),
                esc(&k.command()),
                esc(&k.triggers.join("; ")),
                esc(&k.user),
                t(k.created),
                t(k.last_run),
                esc(&k.notes.join("; "))
            ));
        }
        h.push_str("</table>");
    }
    h.push_str(&format!(
        "<p class=muted>{} artifact files read: {}. {} notable events of {} records.</p>",
        w.sources.len(),
        w.sources.iter().filter(|s| s.error.is_some()).count().to_string() + " unreadable",
        w.events.len(),
        w.logs.iter().map(|l| l.info.records).sum::<u64>()
    ));
}

fn report_web(h: &mut String, w: &kokino_artifacts::browser::WebActivity) {
    if w.sources.is_empty() {
        return;
    }
    let t = |ft: u64| if ft == 0 { String::new() } else { filetime_to_iso(ft) };
    let who = |s: u32| w.sources.get(s as usize).map(|x| format!("{} ({}/{})", x.browser, x.user, x.profile)).unwrap_or_default();
    h.push_str("<h3>Web activity</h3><table><tr><th>Browser</th><th>User / profile</th><th>Database</th><th>Visits</th><th>Downloads</th><th>Searches</th><th>Cached files</th><th>Period (UTC)</th><th>Notes</th></tr>");
    for s in &w.sources {
        let mut notes = vec![];
        if s.deleted {
            notes.push("<span class=bad>database file deleted</span>".to_string());
        }
        if s.error.is_none() && s.visits == 0 && s.urls == 0 && s.engine != Some(kokino_artifacts::browser::Engine::Ie) {
            notes.push("<span class=bad>history empty</span>".to_string());
        }
        if s.recovered > 0 {
            notes.push(format!("{} deleted entries recovered from inside the file", s.recovered));
        }
        if !s.note.is_empty() {
            notes.push(esc(&s.note));
        }
        if s.wal {
            notes.push("includes uncheckpointed -wal changes".to_string());
        }
        if let Some(e) = &s.error {
            notes.push(format!("<span class=bad>unreadable: {}</span>", esc(e)));
        }
        h.push_str(&format!(
            "<tr><td>{}</td><td>{} / {}</td><td><code>{}</code> (MFT {})</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}<br>{}</td><td>{}</td></tr>",
            esc(&s.browser), esc(&s.user), esc(&s.profile), esc(&s.path), s.record, s.visits, s.downloads, s.searches, s.cached, t(s.oldest), t(s.newest), notes.join("<br>")
        ));
    }
    h.push_str("</table>");
    if !w.downloads.is_empty() {
        h.push_str("<h4>Downloads</h4><table><tr><th>Started (UTC)</th><th>Browser</th><th>Saved to</th><th>Source URL</th><th>Bytes</th><th>State</th></tr>");
        for d in &w.downloads {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}{}</td></tr>",
                t(d.start), esc(&who(d.src)), esc(&d.target), esc(&d.url), d.received, esc(&d.state), if d.danger.is_empty() { String::new() } else { format!(" <span class=bad>{}</span>", esc(&d.danger)) }
            ));
        }
        h.push_str("</table>");
    }
    if !w.searches.is_empty() {
        h.push_str("<h4>Searches</h4><table><tr><th>Time (UTC)</th><th>Browser</th><th>Engine</th><th>Term</th><th>Source</th></tr>");
        for s in &w.searches {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><b>{}</b></td><td>{}</td></tr>", t(s.t), esc(&who(s.src)), esc(&s.engine), esc(&s.term), esc(&s.how)));
        }
        h.push_str("</table>");
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Self-contained HTML report: case, evidence integrity, volumes, summary,
/// indicators with the files behind them, audit chain status.
async fn report(State(st): St, Extension(me): Me, Path((cid, eid)): Path<(String, String)>) -> Result<Html<String>, AppError> {
    let case = st.case(&cid)?;
    let rec = case.evidence_by_id(&eid)?;
    let l = st.loaded(&cid, &eid)?;
    let a = &l.analysis;
    let audit = kokino_core::audit::verify(&case.dir.join("audit.jsonl"))?;
    let mut h = String::new();
    h.push_str(&format!(
        "<!doctype html><html><head><meta charset=utf-8><title>Kokino report: {}</title><style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 16px;color:#1d1d1f}}h1{{margin-bottom:0}}table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}td,th{{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}}th{{background:#f4f4f6}}code{{font:12px ui-monospace,monospace;word-break:break-all}}.muted{{color:#666}}.bad{{color:#b3261e;font-weight:600}}.ok{{color:#1b7a3a;font-weight:600}}</style></head><body>",
        esc(&case.info.name)
    ));
    h.push_str(&format!(
        "<h1>{}</h1><p class=muted>{} {}, {}, generated {} by {} ({})</p>",
        esc(&case.info.name), kokino_core::TOOL_NAME, kokino_core::TOOL_VERSION, kokino_core::VENDOR, human(&now_iso()), esc(&me.display_name), esc(&me.username)
    ));
    h.push_str(&format!(
        "<h2>Case</h2><table><tr><th>Case id</th><td>{}</td></tr><tr><th>Lead examiner</th><td>{}</td></tr><tr><th>Created</th><td>{}</td></tr><tr><th>Description</th><td>{}</td></tr><tr><th>Audit log</th><td>{} entries, chain {} (head <code>{}</code>)</td></tr></table>",
        esc(&case.info.id), esc(&case.info.examiner), esc(&human(&case.info.created)), esc(&case.info.description),
        audit.entries, if audit.ok { "<span class=ok>intact</span>" } else { "<span class=bad>BROKEN</span>" }, audit.head
    ));
    let hs = rec.hashes.clone().unwrap_or_default();
    let mut verified = match (&rec.expected, &rec.hashes) {
        (Some(x), Some(hh)) => if hash_match(x, hh) { "<span class=ok>matches acquisition hash</span>" } else { "<span class=bad>DOES NOT match acquisition hash</span>" },
        _ => "<span class=muted>no acquisition hash supplied</span>",
    }
    .to_string();
    if let (Some(x), Some(hh)) = (&rec.embedded, &rec.hashes) {
        verified.push_str(if hash_match(x, hh) { "<br><span class=ok>matches the hash stored in the image</span>" } else { "<br><span class=bad>DOES NOT match the hash stored in the image</span>" });
    }
    h.push_str(&format!(
        "<h2>Evidence</h2><table><tr><th>Name</th><td>{}</td></tr><tr><th>Path</th><td><code>{}</code></td></tr><tr><th>Format</th><td>{}</td></tr><tr><th>Size</th><td>{} bytes</td></tr><tr><th>MD5</th><td><code>{}</code></td></tr><tr><th>SHA-1</th><td><code>{}</code></td></tr><tr><th>SHA-256</th><td><code>{}</code></td></tr><tr><th>Verification</th><td>{}</td></tr><tr><th>Analyzed</th><td>{} (schema {}, Kokino {})</td></tr></table>",
        esc(&rec.name), esc(&rec.path), esc(&rec.format), rec.size, hs.md5, hs.sha1, hs.sha256, verified, esc(&human(&a.analyzed_at)), a.schema, esc(&a.tool_version)
    ));
    if let Some(acq) = rec.acquisition.as_ref() {
        h.push_str("<h2>Acquisition (recorded in the image)</h2><table>");
        if let Some(m) = acq["acquisition"].as_object() {
            for (k, v) in m {
                let v = v.as_str().unwrap_or("");
                let v = if k == "acquired" || k == "system_date" { human(v) } else { v.to_string() };
                h.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(&k.replace('_', " ")), esc(&v)));
            }
        }
        for (k, label) in [("md5", "Stored MD5"), ("sha1", "Stored SHA-1"), ("media_type", "Media type"), ("bytes_per_sector", "Bytes per sector"), ("chunk_count", "Chunks"), ("set_identifier", "Set identifier")] {
            let v = &acq[k];
            if !v.is_null() && v != "" {
                h.push_str(&format!("<tr><th>{}</th><td><code>{}</code></td></tr>", label, esc(&v.to_string().trim_matches('"').to_string())));
            }
        }
        let segs: Vec<String> = acq["segments"].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).map(esc).collect()).unwrap_or_default();
        h.push_str(&format!("<tr><th>Segments</th><td>{}<br><code>{}</code></td></tr>", segs.len(), segs.join("<br>")));
        let errs = acq["read_errors"].as_array().map(|a| a.len()).unwrap_or(0);
        h.push_str(&format!("<tr><th>Unreadable ranges</th><td>{}</td></tr></table>", if errs == 0 { "none recorded".to_string() } else { format!("<span class=bad>{} range(s), see Limitations</span>", errs) }));
    }
    h.push_str("<h2>Volumes</h2><table><tr><th>#</th><th>Start</th><th>Length</th><th>Description</th><th>Filesystem</th></tr>");
    for v in &a.volumes {
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", v.index, v.start, v.length, esc(&v.description), esc(&v.fs_label)));
    }
    h.push_str("</table>");
    for f in &a.filesystems {
        let detail = if f.volume.fs == kokino_image::FsKind::Ntfs {
            format!("NTFS {}, cluster {} bytes, {} MFT records, {} unreadable", f.info.version, f.info.cluster_size, f.info.mft_records, f.unreadable.len())
        } else {
            format!("cluster {} bytes, {} directory entries", f.info.cluster_size, f.files.len())
        };
        h.push_str(&format!(
            "<h2>{} volume {} \"{}\"</h2><p>Serial {}, {}.</p><h3>Summary</h3><ul>",
            esc(&f.volume.fs_label), f.volume.index, esc(&f.info.label), f.info.serial, detail
        ));
        for line in &f.stats.impact {
            h.push_str(&format!("<li>{}</li>", esc(line)));
        }
        h.push_str(&format!(
            "</ul><h3>Anti-forensics likelihood: {} ({:.0}%)</h3><p class=muted>Heuristic triage score (noisy-OR over indicator strengths). It indicates where to look, not what happened.</p><table><tr><th>Indicator</th><th>Count</th><th>Strength</th><th>Explanation and caveat</th></tr>",
            esc(&f.score.band), f.score.likelihood * 100.0
        ));
        let by_rec: std::collections::HashMap<u64, &FileRow> = f.files.iter().map(|r| (r.e.record, r)).collect();
        for i in &f.indicators {
            let examples: Vec<String> = i.records.iter().take(15).filter_map(|r| by_rec.get(r)).map(|r| format!("<code>{}</code> ({} {})", esc(&r.e.path), if f.volume.fs == kokino_image::FsKind::Ntfs { "MFT" } else { "entry" }, r.e.record)).collect();
            h.push_str(&format!(
                "<tr><td><b>{}</b><br><span class=muted>{}</span></td><td>{}</td><td>{:.2}</td><td>{}<br><i class=muted>{}</i><br>{}</td></tr>",
                esc(&i.title), esc(&i.category), i.count, i.strength, esc(&i.explanation), esc(&i.caveat), examples.join("<br>")
            ));
        }
        h.push_str("</table>");
        report_web(&mut h, &f.web);
        report_windows(&mut h, &f.windows, f);
    }
    if !a.errors.is_empty() {
        h.push_str("<h2>Limitations and errors</h2><ul>");
        for e in &a.errors {
            h.push_str(&format!("<li>{}</li>", esc(e)));
        }
        h.push_str("</ul>");
    }
    h.push_str("<p class=muted>All offsets are byte offsets in the logical image. Evidence was opened read-only; hex overlay edits are stored in the case and never written to evidence.</p></body></html>");
    case.audit.append(&me.username, "report.generate", json!({"evidence": eid}))?;
    Ok(Html(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_inside_the_cases_directory_is_refused() {
        let root = std::env::temp_dir().join(format!("kokino-root-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".kokino")).unwrap();
        std::fs::write(root.join(".kokino").join("users.json"), b"{}").unwrap();
        let outside = std::env::temp_dir().join(format!("kokino-outside-{}.img", std::process::id()));
        std::fs::write(&outside, b"x").unwrap();
        assert!(inside_cases_dir(&root, &root.join(".kokino").join("users.json")));
        assert!(inside_cases_dir(&root, &root.join(".kokino").join("..").join(".kokino").join("users.json")));
        assert!(inside_cases_dir(&root, &root));
        assert!(!inside_cases_dir(&root, &outside));
        // A sibling whose name starts like the root is not inside it.
        let sib = std::path::PathBuf::from(format!("{}-other", root.display()));
        assert!(!inside_cases_dir(&root, &sib));
        if cfg!(windows) {
            let upper = std::path::PathBuf::from(root.join(".kokino").join("users.json").display().to_string().to_uppercase());
            assert!(inside_cases_dir(&root, &upper));
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }
}
