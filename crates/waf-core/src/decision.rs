//! The output of the WAF engine for a given request.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Forward to the upstream unmodified.
    Allow,
    /// Serve a JS challenge page; on success the client gets a clearance cookie.
    Challenge,
    /// Reject with HTTP 429 (rate limit) or 403 (block).
    Block,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionReason {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub score: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub action: Action,
    pub status: u16,
    pub score: u32,
    pub reasons: Vec<DecisionReason>,
    /// Logical request id used to correlate logs.
    pub request_id: String,
}

impl Decision {
    pub fn allow(request_id: String) -> Self {
        Self { action: Action::Allow, status: 200, score: 0, reasons: vec![], request_id }
    }

    pub fn block(request_id: String, status: u16, reason: DecisionReason) -> Self {
        Self {
            action: Action::Block,
            status,
            score: reason.score,
            reasons: vec![reason],
            request_id,
        }
    }

    pub fn challenge(request_id: String, score: u32, reasons: Vec<DecisionReason>) -> Self {
        Self { action: Action::Challenge, status: 403, score, reasons, request_id }
    }

    pub fn add_reason(&mut self, r: DecisionReason) {
        self.score = self.score.saturating_add(r.score);
        self.reasons.push(r);
    }
}
