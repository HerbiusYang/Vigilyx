//! request Trace ID

//! HTTP request 1 1 trace ID, request log.


//! 1. client For `X-Request-Id` request
//! 2., UUID v4
//! 3. Create tracing span, log Contains `trace_id` field
//! 4. response `X-Request-Id`, / log

use axum::{
    http::{HeaderValue, Request, Response},
    middleware::Next,
};
use tracing::Instrument;
use uuid::Uuid;

/// Request name ()
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Trace ID

/// , Road (public + authentication + internal)log
/// 1 trace_id span.

/// `tracing::Instrument` `span.enter()`:
/// - `span.enter()` guard `.await` span
/// - `Instrument` Future poll / span,async Security
pub async fn trace_id_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response<axum::body::Body> {
   // Step 1: Extractclient trace ID New
    let trace_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

   // Step 2: CreateContains trace_id tracing span
    let span = tracing::info_span!(
        "request",
        trace_id = %trace_id,
        method = %req.method(),
        uri = %req.uri().path(),
    );

   // Step 3: span handler (async Security)
    let mut response = next.run(req).instrument(span).await;

   // Step 4: response (/ log)
    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, val);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_header_name_is_lowercase() {
       // header name HTTP/2 ()
        assert_eq!(REQUEST_ID_HEADER, REQUEST_ID_HEADER.to_ascii_lowercase());
    }

    #[test]
    fn test_uuid_v4_format() {
       // verify trace_id UUID v4 format
        let id = Uuid::new_v4().to_string();
        assert_eq!(id.len(), 36); // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert!(Uuid::parse_str(&id).is_ok());
    }
}
