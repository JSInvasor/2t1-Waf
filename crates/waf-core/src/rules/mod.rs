//! Detection rules. Each submodule exports a `scan` function that returns
//! `Some(Hit)` on a positive match. Scans are intentionally conservative for
//! benign payloads — false positives are very expensive on a public WAF.

pub mod sqli;
pub mod xss;
pub mod traversal;
pub mod cmdi;
pub mod lfi;
pub mod ua;

use crate::request::RequestCtx;
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone)]
pub struct Hit {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub matched_field: &'static str,
    pub matched_excerpt: String,
}

/// All scannable text fragments from a request, normalized once.
pub struct Surface {
    pub uri: String,
    pub query_decoded: String,
    pub path_decoded: String,
    pub headers_concat: String,
    pub body_preview: String,
    pub user_agent: String,
}

impl Surface {
    pub fn from(ctx: &RequestCtx) -> Self {
        let path_decoded = decode(&ctx.path);
        let query_decoded = decode(&ctx.query);
        let headers_concat = ctx.headers.iter()
            .filter(|(k, _)| !is_skip_header(k))
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let body_preview = String::from_utf8_lossy(&ctx.body_preview).to_string();
        Self {
            uri: ctx.uri.clone(),
            query_decoded,
            path_decoded,
            headers_concat,
            body_preview,
            user_agent: ctx.user_agent.clone(),
        }
    }
}

fn decode(s: &str) -> String {
    // Single percent-decode pass; defending against double-encoding by also
    // searching the raw form is the caller's job.
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

fn is_skip_header(name: &str) -> bool {
    matches!(name,
        "cookie" | "authorization" | "content-length" | "content-type"
        | "host" | "user-agent" | "accept" | "accept-encoding" | "accept-language"
        | "connection" | "upgrade" | "keep-alive" | "te" | "transfer-encoding"
    )
}

/// Truncate to a short excerpt safe to log.
pub(crate) fn excerpt(s: &str) -> String {
    let trimmed: String = s.chars().take(96).collect();
    trimmed.replace(['\r', '\n'], " ")
}
