//! Tiny ProxyHttp impl that 301-redirects every request to https on the
//! configured port. Used when the operator binds both 80 and 443 and wants
//! clear-text traffic forced to TLS.

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

pub struct HttpsRedirect {
    port: u16,
}

impl HttpsRedirect {
    pub fn new(port: u16) -> Self { Self { port } }
}

#[async_trait]
impl ProxyHttp for HttpsRedirect {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ()) -> Result<bool> {
        let host = session.req_header()
            .headers.get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(':').next().unwrap_or(s).to_string())
            .unwrap_or_default();
        let uri = session.req_header().uri.path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let location = if self.port == 443 {
            format!("https://{host}{uri}")
        } else {
            format!("https://{host}:{}{uri}", self.port)
        };

        let mut resp = match ResponseHeader::build(301, Some(4)) {
            Ok(r) => r, Err(_) => return Ok(true),
        };
        let _ = resp.insert_header("location", location.as_str());
        let _ = resp.insert_header("content-length", "0");
        let _ = resp.insert_header("x-waf", "2t1");
        let _ = session.write_response_header(Box::new(resp), false).await;
        let _ = session.write_response_body(Some(Bytes::new()), true).await;
        Ok(true)
    }

    async fn upstream_peer(&self, _s: &mut Session, _c: &mut ()) -> Result<Box<HttpPeer>> {
        // Never reached because request_filter always returns Ok(true).
        Err(pingora_core::Error::new_str("unreachable"))
    }
}
