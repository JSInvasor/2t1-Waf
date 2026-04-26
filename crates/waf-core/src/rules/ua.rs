//! User-Agent based heuristics. Aho-Corasick over a configurable substring list
//! gives O(n) scanning regardless of how many tokens we add.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

pub struct UaScanner {
    ac: Option<AhoCorasick>,
}

impl UaScanner {
    pub fn new(substrings: &[String]) -> anyhow::Result<Self> {
        if substrings.is_empty() {
            return Ok(Self { ac: None });
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(substrings)
            .map_err(|e| anyhow::anyhow!("ua scanner build: {e}"))?;
        Ok(Self { ac: Some(ac) })
    }

    pub fn is_suspicious(&self, ua: &str) -> bool {
        match &self.ac {
            Some(ac) => ac.is_match(ua),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_substring() {
        let s = UaScanner::new(&["sqlmap".into(), "nikto".into()]).unwrap();
        assert!(s.is_suspicious("Mozilla/5.0 sqlmap/1.6"));
        assert!(s.is_suspicious("Nikto/2.1.6"));
        assert!(!s.is_suspicious("Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605"));
    }
}
