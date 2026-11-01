//! Examiner accounts: roles, Argon2id password hashes and the system audit log.
//!
//! Accounts live in `<cases root>/.kokino/users.json`. Logins, account changes
//! and case assignments are written to `<cases root>/.kokino/system-audit.jsonl`,
//! which is hash-chained like the per-case audit logs.

use crate::audit::AuditLog;
use crate::case::{read_json, write_json};
use crate::time::now_iso;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only access to assigned cases (peer review, QA).
    Reviewer,
    /// Works assigned cases: evidence, analysis, overlay edits, exports.
    Examiner,
    /// Manages accounts and case assignments; full access to every case.
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> anyhow::Result<Role> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "examiner" => Ok(Role::Examiner),
            "reviewer" => Ok(Role::Reviewer),
            _ => anyhow::bail!("role must be admin, examiner or reviewer"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub display_name: String,
    pub role: Role,
    /// PHC string (Argon2id). Never sent to the GUI.
    pub password: String,
    pub created: String,
    #[serde(default)]
    pub disabled: bool,
    /// Set by an admin reset; the user must choose a new password at next login.
    #[serde(default)]
    pub must_change_password: bool,
    #[serde(default)]
    pub last_login: Option<String>,
}

/// The parts of a user that are safe to show.
#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub username: String,
    pub display_name: String,
    pub role: Role,
    pub created: String,
    pub disabled: bool,
    pub must_change_password: bool,
    pub last_login: Option<String>,
}

impl From<&User> for UserView {
    fn from(u: &User) -> Self {
        UserView {
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            role: u.role,
            created: u.created.clone(),
            disabled: u.disabled,
            must_change_password: u.must_change_password,
            last_login: u.last_login.clone(),
        }
    }
}

/// A deleted account that had been used. Its username stays reserved so
/// every audit entry, bookmark and record naming it keeps pointing at one
/// person; nothing else about the account is kept (no password hash, no
/// display name).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retired {
    pub username: String,
    pub role: Role,
    pub created: String,
    pub deleted: String,
    pub deleted_by: String,
}

/// What `UserStore::delete` did.
#[derive(Debug, Clone, Serialize)]
pub struct Deleted {
    pub username: String,
    /// Never used: removed without a trace in the account list.
    pub purged: bool,
    /// Why the account counts as used (empty when purged).
    pub usage: Vec<String>,
    /// Cases it was removed from as a member.
    pub cases: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UsersFile {
    users: Vec<User>,
    #[serde(default)]
    retired: Vec<Retired>,
}

pub struct UserStore {
    path: PathBuf,
    lock: Mutex<()>,
    pub audit: AuditLog,
}

impl UserStore {
    pub fn open(cases_root: &Path) -> anyhow::Result<UserStore> {
        let dir = crate::state_dir(cases_root);
        std::fs::create_dir_all(&dir)?;
        Ok(UserStore { path: dir.join("users.json"), lock: Mutex::new(()), audit: AuditLog::open(dir.join("system-audit.jsonl"))? })
    }

    fn load(&self) -> anyhow::Result<UsersFile> {
        if !self.path.exists() {
            return Ok(UsersFile::default());
        }
        read_json(&self.path)
    }

    pub fn list(&self) -> anyhow::Result<Vec<User>> {
        Ok(self.load()?.users)
    }

    pub fn retired(&self) -> anyhow::Result<Vec<Retired>> {
        Ok(self.load()?.retired)
    }

    pub fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.load()?.users.is_empty())
    }

    pub fn get(&self, username: &str) -> anyhow::Result<Option<User>> {
        let key = username.to_ascii_lowercase();
        Ok(self.load()?.users.into_iter().find(|u| u.username == key))
    }

    /// Read-modify-write under the store lock.
    pub fn update<T>(&self, f: impl FnOnce(&mut Vec<User>) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let _g = self.lock.lock().unwrap();
        let mut file = self.load()?;
        let out = f(&mut file.users)?;
        write_json(&self.path, &file)?;
        Ok(out)
    }

    /// Where an account left traces in this installation: sign-ins, entries
    /// it wrote in the system audit log or any case audit log, bookmarks it
    /// made or changed. Any of these makes it "used". Being assigned to a
    /// case is not use (an admin does that).
    pub fn usage(&self, cases_root: &Path, username: &str) -> anyhow::Result<Vec<String>> {
        let name = username.to_ascii_lowercase();
        let mut out = vec![];
        if let Some(u) = self.get(&name)? {
            if let Some(t) = &u.last_login {
                out.push(format!("signed in (last {})", t));
            }
        }
        let own = self.audit.entries()?.iter().filter(|e| e.examiner == name).count();
        if own > 0 {
            out.push(format!("{} entr{} written by this account in the system audit log", own, if own == 1 { "y" } else { "ies" }));
        }
        for info in crate::case::Case::list(cases_root) {
            let Ok(case) = crate::case::Case::open(&cases_root.join(&info.id)) else { continue };
            let n = case.audit.entries().map(|v| v.iter().filter(|e| e.examiner == name).count()).unwrap_or(0);
            if n > 0 {
                out.push(format!("{} entr{} in the audit log of case \"{}\"", n, if n == 1 { "y" } else { "ies" }, info.name));
            }
            let b = crate::bookmarks::load(&case.bookmarks_path()).unwrap_or_default().iter().filter(|b| b.created_by == name || b.updated_by == name).count();
            if b > 0 {
                out.push(format!("{} bookmark{} in case \"{}\"", b, if b == 1 { "" } else { "s" }, info.name));
            }
        }
        Ok(out)
    }

    /// Deletes an account. An account that was never used (see `usage`)
    /// is removed completely; a used one keeps only a `Retired` record that
    /// reserves its username. Either way its password hash and display
    /// name are gone, it is removed from every case it was a member of
    /// (with an entry in that case's audit log), and the deletion is
    /// written to the system audit log. Refuses to delete `actor`'s own
    /// account and the last active admin.
    pub fn delete(&self, cases_root: &Path, username: &str, actor: &str) -> anyhow::Result<Deleted> {
        let name = username.to_ascii_lowercase();
        if name == actor.to_ascii_lowercase() {
            anyhow::bail!("you cannot delete your own account");
        }
        let usage = self.usage(cases_root, &name)?;
        let purged = usage.is_empty();
        self.update_file(|file| {
            let i = file.users.iter().position(|u| u.username == name).ok_or_else(|| anyhow::anyhow!("no such user"))?;
            let u = file.users.remove(i);
            if UserStore::admin_count(&file.users) == 0 {
                anyhow::bail!("at least one active admin must remain");
            }
            if !purged {
                file.retired.push(Retired { username: u.username, role: u.role, created: u.created, deleted: now_iso(), deleted_by: actor.to_string() });
            }
            Ok(())
        })?;
        let mut cases = vec![];
        for info in crate::case::Case::list(cases_root) {
            if !info.members.contains_key(&name) {
                continue;
            }
            let Ok(mut case) = crate::case::Case::open(&cases_root.join(&info.id)) else { continue };
            case.info.members.remove(&name);
            case.save_info()?;
            case.audit.append(actor, "case.member_removed", serde_json::json!({"username": name, "reason": "account deleted"}))?;
            cases.push(info.name);
        }
        self.audit.append(actor, "user.delete", serde_json::json!({"username": name, "purged": purged, "usage": usage, "cases": cases}))?;
        Ok(Deleted { username: name, purged, usage, cases })
    }

    fn update_file<T>(&self, f: impl FnOnce(&mut UsersFile) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let _g = self.lock.lock().unwrap();
        let mut file = self.load()?;
        let out = f(&mut file)?;
        write_json(&self.path, &file)?;
        Ok(out)
    }

    pub fn create(&self, username: &str, display_name: &str, role: Role, password: &str) -> anyhow::Result<User> {
        let username = valid_username(username)?;
        if self.load()?.retired.iter().any(|r| r.username == username) {
            anyhow::bail!("{} belonged to a deleted account and stays reserved, so audit records naming it keep meaning one person; choose another username", username);
        }
        check_password(password)?;
        let user = User {
            username: username.clone(),
            display_name: clean_display(display_name, &username),
            role,
            password: hash_password(password)?,
            created: now_iso(),
            disabled: false,
            must_change_password: false,
            last_login: None,
        };
        let u = user.clone();
        self.update(move |users| {
            if users.iter().any(|x| x.username == username) {
                anyhow::bail!("user {} already exists", username);
            }
            users.push(u);
            Ok(())
        })?;
        Ok(user)
    }

    /// Verifies credentials. Runs a hash even for unknown users so response
    /// time does not reveal which usernames exist.
    pub fn authenticate(&self, username: &str, password: &str) -> anyhow::Result<Option<User>> {
        match self.get(username)? {
            Some(u) if !u.disabled => Ok(if verify_password(&u.password, password) { Some(u) } else { None }),
            _ => {
                let _ = verify_password(dummy_hash(), password);
                Ok(None)
            }
        }
    }

    pub fn admin_count(users: &[User]) -> usize {
        users.iter().filter(|u| u.role == Role::Admin && !u.disabled).count()
    }
}

pub fn valid_username(s: &str) -> anyhow::Result<String> {
    let s = s.trim().to_ascii_lowercase();
    if s.len() < 2 || s.len() > 32 || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
        anyhow::bail!("username must be 2-32 characters: letters, digits, '.', '-' or '_'");
    }
    Ok(s)
}

fn clean_display(s: &str, fallback: &str) -> String {
    let s: String = s.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    if s.is_empty() { fallback.to_string() } else { s }
}

pub fn check_password(p: &str) -> anyhow::Result<()> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        anyhow::bail!("password must be at least {} characters", MIN_PASSWORD_LEN);
    }
    if p.len() > 1024 {
        anyhow::bail!("password is too long");
    }
    Ok(())
}

pub fn hash_password(p: &str) -> anyhow::Result<String> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Argon2::default().hash_password(p.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("{e}"))?.to_string())
}

pub fn verify_password(phc: &str, p: &str) -> bool {
    PasswordHash::new(phc).map(|h| Argon2::default().verify_password(p.as_bytes(), &h).is_ok()).unwrap_or(false)
}

fn dummy_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| hash_password("kokino-dummy-password").unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_authenticate() {
        let dir = std::env::temp_dir().join(format!("kokino-users-{}", uuid::Uuid::new_v4()));
        let s = UserStore::open(&dir).unwrap();
        assert!(s.is_empty().unwrap());
        assert!(s.create("Alice", "Alice A.", Role::Admin, "short").is_err());
        s.create("Alice", "Alice A.", Role::Admin, "correct horse battery").unwrap();
        assert!(s.create("alice", "", Role::Examiner, "correct horse battery").is_err());
        assert!(s.authenticate("ALICE", "correct horse battery").unwrap().is_some());
        assert!(s.authenticate("alice", "wrong password!!").unwrap().is_none());
        assert!(s.authenticate("bob", "correct horse battery").unwrap().is_none());
        assert!(!std::fs::read_to_string(dir.join(".kokino/users.json")).unwrap().contains("correct horse"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_purges_unused_and_reserves_used() {
        let dir = std::env::temp_dir().join(format!("kokino-users-{}", uuid::Uuid::new_v4()));
        let s = UserStore::open(&dir).unwrap();
        let pw = "correct horse battery";
        s.create("alice", "Alice", Role::Admin, pw).unwrap();
        s.create("typo", "Typo", Role::Examiner, pw).unwrap();
        s.create("carol", "Carol C.", Role::Examiner, pw).unwrap();
        s.create("dave", "Dave", Role::Reviewer, pw).unwrap();
        // carol works a case; dave is only assigned to it.
        let mut c = crate::case::Case::create(&dir, "Lab case", "carol", "").unwrap();
        c.info.members.insert("dave".into(), crate::case::Access::Reviewer);
        c.save_info().unwrap();

        assert!(s.delete(&dir, "alice", "alice").unwrap_err().to_string().contains("your own"));
        assert!(s.delete(&dir, "nobody", "alice").is_err());

        let d = s.delete(&dir, "typo", "alice").unwrap();
        assert!(d.purged && d.usage.is_empty() && d.cases.is_empty());
        let d = s.delete(&dir, "dave", "alice").unwrap();
        assert!(d.purged, "assignment alone is not use: {:?}", d.usage);
        assert_eq!(d.cases, ["Lab case"]);
        let d = s.delete(&dir, "carol", "alice").unwrap();
        assert!(!d.purged && d.usage.iter().any(|u| u.contains("Lab case")), "{:?}", d);

        let c = crate::case::Case::open(&c.dir).unwrap();
        assert!(c.info.members.is_empty());
        assert_eq!(c.audit.entries().unwrap().iter().filter(|e| e.action == "case.member_removed").count(), 2);
        let users: Vec<String> = s.list().unwrap().into_iter().map(|u| u.username).collect();
        assert_eq!(users, ["alice"]);
        let r = s.retired().unwrap();
        assert_eq!(r.iter().map(|x| x.username.as_str()).collect::<Vec<_>>(), ["carol"]);
        // No credential or name survives; the username stays reserved.
        let raw = std::fs::read_to_string(dir.join(".kokino/users.json")).unwrap();
        assert!(!raw.contains("Carol C."));
        assert_eq!(raw.matches("$argon2").count(), 1, "only alice's hash remains");
        assert!(s.create("carol", "", Role::Examiner, pw).unwrap_err().to_string().contains("reserved"));
        s.create("typo", "", Role::Examiner, pw).unwrap();
        assert_eq!(s.audit.entries().unwrap().iter().filter(|e| e.action == "user.delete").count(), 3);

        // The last active admin stays.
        s.create("bob", "Bob", Role::Admin, pw).unwrap();
        s.delete(&dir, "bob", "alice").unwrap();
        s.create("eve", "Eve", Role::Admin, pw).unwrap();
        s.update(|all| {
            all.iter_mut().find(|u| u.username == "eve").unwrap().disabled = true;
            Ok(())
        })
        .unwrap();
        assert!(s.delete(&dir, "alice", "eve").unwrap_err().to_string().contains("active admin"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
