//! Day 15 Error Classification & Safe Diagnostics Test Suite.
//!
//! Validates:
//! 1. Deterministic `ParserErrorKind` classification across all 6 error categories
//! 2. Sensitive data redaction (JWTs, API keys, Authorization headers, query params, control chars)
//! 3. Multibyte UTF-8 panic-free truncation in diagnostic previews
//! 4. Bounded diagnostic ring buffer (`max_diagnostics`) and accurate `error_counts`
//! 5. Recovery after malformed traffic and `Record` schema preservation

use api_sentinel_parser::{
    classify_error_message, parse_http_request, parse_http_request_with_limits,
    parse_http_response, parse_http_response_with_limits, redact_sensitive_preview, HttpParser,
    ParserErrorKind, ParserLimits, StreamReassembler, TrafficDirection,
};

// =========================================================================
// 1. Deterministic Error Classification
// =========================================================================

#[test]
fn test_error_kind_classification_for_requests_and_responses() {
    let limits = ParserLimits::new()
        .with_max_header_size(256)
        .with_max_body_size(64)
        .with_max_headers_count(4)
        .with_max_line_length(64);

    // 1. IncompleteData
    let incomplete_req = parse_http_request(b"GET /partial HTTP/1.1\r\nHost: a.com\r\n", 1.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert_eq!(incomplete_req.error_kind(), Some(ParserErrorKind::IncompleteData));

    let incomplete_resp = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", 1.0);
    assert_eq!(incomplete_resp.error_kind(), Some(ParserErrorKind::IncompleteData));

    // 2. MalformedStartLine
    let bad_method = parse_http_request(b"BADMETHOD /api HTTP/1.1\r\n\r\n", 1.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert_eq!(bad_method.error_kind(), Some(ParserErrorKind::MalformedStartLine));

    let bad_status = parse_http_response(b"HTTP/1.1 999 Invalid\r\n\r\n", 1.0);
    assert_eq!(bad_status.error_kind(), Some(ParserErrorKind::MalformedStartLine));

    // 3. InvalidHeader
    let missing_colon = parse_http_request(b"GET / HTTP/1.1\r\nBrokenHeader\r\n\r\n", 1.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert_eq!(missing_colon.error_kind(), Some(ParserErrorKind::InvalidHeader));

    let ws_before_colon = parse_http_response(b"HTTP/1.1 200 OK\r\nServer : Nginx\r\n\r\n", 1.0);
    assert_eq!(ws_before_colon.error_kind(), Some(ParserErrorKind::InvalidHeader));

    // 4. FramingOrBodyError
    let conflict_cl = parse_http_request(
        b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello",
        1.0, "1.1.1.1", 1, "2.2.2.2", 80,
    );
    assert_eq!(conflict_cl.error_kind(), Some(ParserErrorKind::FramingOrBodyError));

    let bad_chunk = parse_http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n",
        1.0,
    );
    assert_eq!(bad_chunk.error_kind(), Some(ParserErrorKind::FramingOrBodyError));

    // 5. LimitViolation
    let too_many_headers = parse_http_request_with_limits(
        b"GET / HTTP/1.1\r\nH1: 1\r\nH2: 2\r\nH3: 3\r\nH4: 4\r\nH5: 5\r\n\r\n",
        1.0, "1.1.1.1", 1, "2.2.2.2", 80, &limits,
    );
    assert_eq!(too_many_headers.error_kind(), Some(ParserErrorKind::LimitViolation));

    let oversized_body = parse_http_response_with_limits(
        b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n",
        1.0, &limits,
    );
    assert_eq!(oversized_body.error_kind(), Some(ParserErrorKind::LimitViolation));

    // 6. Valid message -> None
    let valid_req = parse_http_request(b"GET /ok HTTP/1.1\r\nHost: ok.com\r\n\r\n", 1.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert_eq!(valid_req.error_kind(), None);
}

// =========================================================================
// 2. Sensitive Data Redaction & Log Injection Defense
// =========================================================================

#[test]
fn test_sensitive_credentials_never_leaked_in_errors_or_diagnostics() {
    let secret_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWNyZXRfdXNlciJ9.sig_xyz";
    let secret_key = "app_sec_998877665544332211";

    // Case A: Malformed Authorization header missing colon
    let malformed_auth_req = format!(
        "GET /api/data HTTP/1.1\r\nAuthorization Bearer {}\r\n\r\n",
        secret_jwt
    );
    let res1 = parse_http_request(
        malformed_auth_req.as_bytes(),
        10.0, "10.0.0.1", 5000, "10.0.0.2", 80,
    );
    let err1 = res1.error.expect("Should return error");
    assert!(!err1.contains(secret_jwt), "JWT must NEVER appear in error message");
    assert!(!err1.contains("eyJhbG"), "JWT prefix must NEVER appear in error message");
    assert!(err1.contains("REDACTED"));

    // Case B: Malformed X-API-Key header missing colon
    let malformed_key_req = format!(
        "GET /api/data HTTP/1.1\r\nX-API-Key {}\r\n\r\n",
        secret_key
    );
    let res2 = parse_http_request(
        malformed_key_req.as_bytes(),
        10.0, "10.0.0.1", 5000, "10.0.0.2", 80,
    );
    let err2 = res2.error.expect("Should return error");
    assert!(!err2.contains(secret_key), "API key must NEVER appear in error message");
    assert!(err2.contains("REDACTED"));

    // Case C: Malformed request line with sensitive query param
    let malformed_query = b"BADMETH /login?token=super_secret_token_123 HTTP/1.1\r\n\r\n";
    let res3 = parse_http_request(malformed_query, 10.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    let err3 = res3.error.expect("Should return error");
    assert!(!err3.contains("super_secret_token_123"), "Query token must be redacted");
    assert!(err3.contains("[REDACTED_QUERY]"));

    // Case D: Control character stripping & multibyte UTF-8 safety
    let emoji_raw = "🔒🔒🔒\r\nInjectedLogLine: fake_entry\x00";
    let safe = redact_sensitive_preview(emoji_raw, 12);
    assert!(!safe.contains('\r'));
    assert!(!safe.contains('\n'));
    assert!(!safe.contains('\0'));
    assert!(safe.ends_with("..."));
}

// =========================================================================
// 3. Bounded Diagnostics & Reassembler Error Tracking
// =========================================================================

#[test]
fn test_bounded_diagnostics_and_error_counts() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.5:44444->10.0.0.1:80";

    // Feed 200 malformed request fragments (exceeds DEFAULT_MAX_DIAGNOSTICS = 128)
    for i in 0..200 {
        let bad_payload = format!("INVALID_METHOD_{} /bad HTTP/1.1\r\n\r\n", i);
        let recs = reassembler.feed_raw(
            conn_id,
            100.0 + (i as f64) * 0.01,
            TrafficDirection::Ingress,
            bad_payload.as_bytes(),
        );
        assert!(recs.is_empty());
    }

    // Ring buffer must remain strictly bounded at 128
    let diags = reassembler.diagnostics();
    assert_eq!(diags.len(), 128);
    assert_eq!(reassembler.total_errors(), 200);
    assert_eq!(reassembler.error_count(ParserErrorKind::MalformedStartLine), 200);

    // Feed an orphan response -> classified as ReassemblyFailure
    let orphan_recs = reassembler.feed_raw(
        conn_id,
        200.0,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    assert_eq!(orphan_recs.len(), 1);
    assert!(orphan_recs[0].is_orphan());
    assert_eq!(reassembler.error_count(ParserErrorKind::ReassemblyFailure), 1);

    // Clear diagnostics resets buffer and counts
    reassembler.clear_diagnostics();
    assert!(reassembler.diagnostics().is_empty());
    assert_eq!(reassembler.total_errors(), 0);
}

// =========================================================================
// 4. Recovery After Malformed Traffic Preserving Record Contract
// =========================================================================

#[test]
fn test_recovery_after_malformed_traffic_and_record_preservation() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.1.77:51000->10.0.0.1:8080";

    // 1. Send malformed header with sensitive token
    let bad_req = b"GET /bad HTTP/1.1\r\nAuthorization Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.s\r\n\r\n";
    let r1 = reassembler.feed_raw(conn_id, 10.0, TrafficDirection::Ingress, bad_req);
    assert!(r1.is_empty());
    assert_eq!(reassembler.error_count(ParserErrorKind::InvalidHeader), 1);

    // Verify diagnostic did not leak the JWT
    let diags = reassembler.diagnostics();
    assert_eq!(diags.len(), 1);
    assert!(!diags[0].message.contains("eyJhbG"));

    // 2. Send valid request and response on the same connection
    let valid_req = b"POST /api/orders HTTP/1.1\r\nHost: shop.local\r\nX-User-Id: user_77\r\nContent-Length: 10\r\n\r\n{\"id\":100}";
    reassembler.feed_raw(conn_id, 20.0, TrafficDirection::Ingress, valid_req);

    let valid_resp = b"HTTP/1.1 201 Created\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
    let records = reassembler.feed_raw(conn_id, 20.012, TrafficDirection::Egress, valid_resp);

    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.user, "user_77");
    assert_eq!(rec.method, "POST");
    assert_eq!(rec.path, "/api/orders");
    assert_eq!(rec.status, 201);
    assert!((rec.latency_ms - 12.0).abs() < 0.1);
    assert!(rec.to_json().is_ok());
}

#[test]
fn test_classify_error_message_helper_coverage() {
    assert_eq!(
        classify_error_message("Header count exceeds maximum allowed limit 100"),
        ParserErrorKind::LimitViolation
    );
    assert_eq!(
        classify_error_message("Conflicting duplicate Content-Length headers: 5 vs 10"),
        ParserErrorKind::FramingOrBodyError
    );
    assert_eq!(
        classify_error_message("Whitespace disallowed between header name and colon"),
        ParserErrorKind::InvalidHeader
    );
    assert_eq!(
        classify_error_message("Invalid HTTP version in request line: HTTP/X"),
        ParserErrorKind::MalformedStartLine
    );
    assert_eq!(
        classify_error_message("Orphan response received"),
        ParserErrorKind::ReassemblyFailure
    );
}
