//! 2t1-Waf core: protocol-agnostic L7 WAF engine.
//!
//! The proxy crate (`waf-proxy`) wires this engine into Pingora; nothing in
//! here depends on Pingora so the rules can be reused, fuzzed, and unit tested
//! in isolation.

pub mod config;
pub mod connections;
pub mod decision;
pub mod events;
pub mod ratelimit;
pub mod reputation;
pub mod rules;
pub mod runtime;
pub mod score;
pub mod challenge;
pub mod metrics;
pub mod request;
pub mod engine;

pub use config::Config;
pub use decision::{Action, Decision, DecisionReason};
pub use engine::Engine;
pub use request::RequestCtx;
pub use runtime::Runtime;
