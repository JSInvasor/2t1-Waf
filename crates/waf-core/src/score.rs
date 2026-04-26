//! Bot/anomaly scoring helpers. Individual signals contribute weighted points
//! that the engine sums into a single score per request.

pub const SCORE_RL_HIT:        u32 = 30;
pub const SCORE_BAD_METHOD:    u32 = 100;
pub const SCORE_OVERSIZE_URI:  u32 = 100;
pub const SCORE_OVERSIZE_HEAD: u32 = 100;
pub const SCORE_OVERSIZE_BODY: u32 = 100;
pub const SCORE_DENY_REPUTATION: u32 = 100;
pub const SCORE_GEO_BLOCKED:   u32 = 100;
pub const SCORE_GEO_SUSPICIOUS: u32 = 15;

pub const SCORE_SQLI_HIGH:     u32 = 80;
pub const SCORE_XSS_HIGH:      u32 = 80;
pub const SCORE_TRAVERSAL:     u32 = 70;
pub const SCORE_CMDI:          u32 = 80;
pub const SCORE_LFI:           u32 = 70;

pub const SCORE_BAD_UA:        u32 = 60;
pub const SCORE_MISSING_UA:    u32 = 10;
pub const SCORE_MISSING_HOST:  u32 = 100;
pub const SCORE_SUSPICIOUS_HEADER: u32 = 25;
pub const SCORE_HEADERLESS:    u32 = 20;
