//! macOS file systems: HFS+ (`hfs`) and APFS (`apfs`), with the
//! transparent compression both use (`decmpfs`).

#![forbid(unsafe_code)]

pub mod decmpfs;
pub mod apfs;
pub mod hfs;
