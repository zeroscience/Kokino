//! Artifact parsers. Each works on bytes the caller read from the evidence,
//! so the parsers never see or touch the image itself.

#![forbid(unsafe_code)]

pub mod bin;
pub mod browser;
pub mod cfb;
pub mod ese;
pub mod evt;
pub mod evtx;
pub mod fsevents;
pub mod iecache;
pub mod jumplist;
pub mod lnk;
pub mod plist;
pub mod prefetch;
pub mod reglog;
pub mod registry;
pub mod shellbags;
pub mod sqlite;
pub mod task;
pub mod usn;
pub mod xpress;
