//! Dashboard front-end. Three flat files served verbatim from the admin port.
//! Kept in-source so the binary is self-contained — no external static dir.

pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
pub const DASHBOARD_CSS:  &str = include_str!("dashboard.css");
pub const DASHBOARD_JS:   &str = include_str!("dashboard.js");
