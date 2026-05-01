//! Persistent event store. The proxy thread *must not* block on disk,
//! so we drop events into an unbounded mpsc channel and a dedicated
//! tokio task drains it, batching INSERTs every second.
//!
//! On overload the channel grows; if it grows past `MAX_QUEUE`, new
//! events are silently dropped (stamping a `dropped` counter the
//! dashboard surfaces). This is by design: storage backpressure must
//! never cascade into request handling.
//!
//! Schema is intentionally flat: timestamp + a denormalised JSON blob
//! of the Event, keyed by ts_ms with an index. This keeps the writer
//! cheap and the reader simple. SQLite WAL mode is enabled so the
//! dashboard can read while the writer is appending.

use crate::events::Event;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

const FLUSH_EVERY_MS:  u64 = 1_000;
const FLUSH_BATCH:     usize = 512;
const MAX_QUEUE:       usize = 16_384;

#[derive(Default)]
pub struct StorageStats {
    pub written: AtomicU64,
    pub dropped: AtomicU64,
}

#[derive(Clone)]
pub struct Sink {
    tx: mpsc::UnboundedSender<Event>,
    stats: Arc<StorageStats>,
    /// Local counter of how many events have been queued; serves as a
    /// rough proxy for queue depth without locking the channel.
    queued: Arc<AtomicU64>,
    drained: Arc<AtomicU64>,
}

impl Sink {
    pub fn submit(&self, ev: Event) {
        let queued = self.queued.load(Ordering::Relaxed);
        let drained = self.drained.load(Ordering::Relaxed);
        if queued.saturating_sub(drained) > MAX_QUEUE as u64 {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.queued.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(ev).is_err() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn stats(&self) -> &StorageStats { &self.stats }
}

pub struct Storage {
    pub sink: Sink,
    /// Path the writer task is committing into; reader uses it to open
    /// short-lived read connections.
    pub path: std::path::PathBuf,
    pub stats: Arc<StorageStats>,
}

impl Storage {
    /// Open (creating if missing) the SQLite file, run the schema, and
    /// spawn the writer task. Returns immediately.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
        {
            let conn = Connection::open(&path)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            conn.execute_batch(SCHEMA)?;
        }

        let (tx, rx) = mpsc::unbounded_channel::<Event>();
        let stats = Arc::new(StorageStats::default());
        let queued = Arc::new(AtomicU64::new(0));
        let drained = Arc::new(AtomicU64::new(0));

        let sink = Sink { tx, stats: stats.clone(), queued: queued.clone(), drained: drained.clone() };

        let writer_path = path.clone();
        let writer_stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_loop(rx, drained, writer_path, writer_stats).await {
                tracing::error!(%e, "storage writer task exited");
            }
        });

        Ok(Self { sink, path, stats })
    }

    /// Query events in [since_ms, until_ms] up to `limit`, newest-first.
    /// Runs on the calling tokio task using spawn_blocking so the proxy
    /// runtime never blocks on the file.
    pub async fn query(&self, since_ms: u64, until_ms: u64, limit: usize)
        -> anyhow::Result<Vec<Event>>
    {
        let path = self.path.clone();
        let limit = limit.min(5000);
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Event>> {
            let conn = Connection::open(&path)?;
            conn.pragma_update(None, "query_only", "ON")?;
            let mut stmt = conn.prepare_cached(
                "SELECT body FROM events
                 WHERE ts_ms >= ?1 AND ts_ms <= ?2
                 ORDER BY ts_ms DESC LIMIT ?3"
            )?;
            let rows = stmt.query_map(params![since_ms as i64, until_ms as i64, limit as i64], |r| {
                let s: String = r.get(0)?;
                Ok(s)
            })?;
            let mut out = Vec::with_capacity(limit);
            for r in rows {
                if let Ok(json) = r {
                    if let Ok(ev) = serde_json::from_str::<Event>(&json) {
                        out.push(ev);
                    }
                }
            }
            Ok(out)
        }).await?
    }

    /// Aggregate counts per second for charting. Returns up to `bucket_s`
    /// bucket entries (allowed/challenge/block/tarpit per second).
    pub async fn series(&self, since_ms: u64, until_ms: u64) -> anyhow::Result<Vec<TimeBucket>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<TimeBucket>> {
            let conn = Connection::open(&path)?;
            conn.pragma_update(None, "query_only", "ON")?;
            let mut stmt = conn.prepare_cached(
                "SELECT (ts_ms / 1000) AS sec, action, COUNT(*) FROM events
                 WHERE ts_ms >= ?1 AND ts_ms <= ?2
                 GROUP BY sec, action ORDER BY sec ASC"
            )?;
            let rows = stmt.query_map(params![since_ms as i64, until_ms as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?;
            let mut out: Vec<TimeBucket> = Vec::new();
            for row in rows {
                let (sec, action, count) = row?;
                let sec_u = sec as u64;
                if let Some(b) = out.last_mut().filter(|b| b.sec == sec_u) {
                    b.add(&action, count as u32);
                } else {
                    let mut b = TimeBucket { sec: sec_u, ..Default::default() };
                    b.add(&action, count as u32);
                    out.push(b);
                }
            }
            Ok(out)
        }).await?
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct TimeBucket {
    pub sec: u64,
    pub allowed: u32,
    pub challenged: u32,
    pub blocked: u32,
    pub tarpit: u32,
}
impl TimeBucket {
    fn add(&mut self, action: &str, n: u32) {
        match action {
            "allow"     => self.allowed    = self.allowed.saturating_add(n),
            "challenge" => self.challenged = self.challenged.saturating_add(n),
            "block"     => self.blocked    = self.blocked.saturating_add(n),
            "tarpit"    => self.tarpit     = self.tarpit.saturating_add(n),
            _ => {}
        }
    }
}

async fn writer_loop(
    mut rx: mpsc::UnboundedReceiver<Event>,
    drained: Arc<AtomicU64>,
    path: std::path::PathBuf,
    stats: Arc<StorageStats>,
) -> anyhow::Result<()> {
    let mut conn = Connection::open(&path)?;
    let mut tick = interval(Duration::from_millis(FLUSH_EVERY_MS));
    let mut buf: Vec<Event> = Vec::with_capacity(FLUSH_BATCH);

    // Periodic retention sweep: keep last 24h on disk.
    let mut retention_tick = interval(Duration::from_secs(900));

    loop {
        tokio::select! {
            biased;
            _ = retention_tick.tick() => {
                let cutoff = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64).unwrap_or(0))
                    .saturating_sub(24 * 3600 * 1000);
                let _ = conn.execute("DELETE FROM events WHERE ts_ms < ?1", params![cutoff]);
                let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
            }
            _ = tick.tick() => {
                if !buf.is_empty() { flush(&mut conn, &mut buf, &stats, &drained)?; }
            }
            ev = rx.recv() => {
                let Some(ev) = ev else { break; };
                buf.push(ev);
                if buf.len() >= FLUSH_BATCH {
                    flush(&mut conn, &mut buf, &stats, &drained)?;
                }
            }
        }
    }
    if !buf.is_empty() { flush(&mut conn, &mut buf, &stats, &drained)?; }
    Ok(())
}

fn flush(conn: &mut Connection, buf: &mut Vec<Event>, stats: &StorageStats, drained: &Arc<AtomicU64>)
    -> anyhow::Result<()>
{
    let n = buf.len();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO events (ts_ms, ip, action, status, score, rule_id, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )?;
        for ev in buf.drain(..) {
            let body = serde_json::to_string(&ev).unwrap_or_default();
            let action = match ev.action {
                crate::Action::Allow     => "allow",
                crate::Action::Challenge => "challenge",
                crate::Action::Block     => "block",
                crate::Action::Tarpit    => "tarpit",
            };
            let _ = stmt.execute(params![
                ev.ts_ms as i64, ev.ip, action,
                ev.status as i64, ev.score as i64,
                ev.rule_id, body,
            ]);
        }
    }
    tx.commit()?;
    stats.written.fetch_add(n as u64, Ordering::Relaxed);
    drained.fetch_add(n as u64, Ordering::Relaxed);
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms   INTEGER NOT NULL,
    ip      TEXT,
    action  TEXT NOT NULL,
    status  INTEGER,
    score   INTEGER,
    rule_id TEXT,
    body    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts_ms);
CREATE INDEX IF NOT EXISTS events_action_ts ON events(action, ts_ms);
CREATE INDEX IF NOT EXISTS events_ip_ts ON events(ip, ts_ms);
";
