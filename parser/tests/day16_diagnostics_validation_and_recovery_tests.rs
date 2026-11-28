//! Day 16: Parser Diagnostics Validation & Recovery Hardening Test Suite.
//!
//! Validates:
//! 1. Comprehensive and deterministic `ParserErrorKind` classification across all edge-case strings.
//! 2. Exhaustive credential redaction (JWTs, API keys, Cookies, passwords, query strings, CRLF injection).
//! 3. Multibyte UTF-8 boundary safety preventing slicing panics on arbitrary international input.
//! 4. Configurable diagnostic ring buffer capacity, FIFO eviction, and accurate counter retention.
//! 5. Robust stream recovery after malformed ingress and egress traffic.
//! 6. Downstream `Record` contract preservation and memory stability under malformed traffic floods.

use api_sentinel_parser::{
    classify_error_message, parse_http_request, parse_http_request_with_limits,
    parse_http_response, parse_http_response_with_limits, redact_sensitive_preview, HttpParser,
    ParserErrorKind, ParserLimits, StreamReassembler, TrafficDirection,
};

// =========================================================================
// 1. Comprehensive & Deterministic Error Classification
// =========================================================================

#[test]
fn test_day16_deterministic_classification_all_categories() {
    // IncompleteData
    assert_eq!(
        classify_error_message("Unexpected EOF while reading body"),
        ParserErrorKind::IncompleteData
    );
    assert_eq!(
        classify_error_message("Waiting for additional TCP fragments"),
        ParserErrorKind::IncompleteData
    );
    assert_eq!(
        classify_error_message("Partial HTTP message received"),
        ParserErrorKind::IncompleteData
    );
    assert_eq!(
        classify_error_message("Truncated chunk data stream"),
        ParserErrorKind::IncompleteData
    );

    // LimitViolation
    assert_eq!(
        classify_error_message("Header size 70000 exceeds maximum allowed limit 65536"),
        ParserErrorKind::LimitViolation
    );
    assert_eq!(
        classify_error_message("Pending request queue overflow; limit reached"),
        ParserErrorKind::LimitViolation
    );
    assert_eq!(
        classify_error_message("Line length limit exceeded"),
        ParserErrorKind::LimitViolation
    );

    // FramingOrBodyError
    assert_eq!(
        classify_error_message("Conflicting Content-Length headers in request"),
        ParserErrorKind::FramingOrBodyError
    );
    assert_eq!(
        classify_error_message("Invalid chunk size hex format"),
        ParserErrorKind::FramingOrBodyError
    );
    assert_eq!(
        classify_error_message("Malformed Transfer-Encoding chunked framing"),
        ParserErrorKind::FramingOrBodyError
    );
    assert_eq!(
        classify_error_message("Error decoding response body content"),
        ParserErrorKind::FramingOrBodyError
    );

    // InvalidHeader
    assert_eq!(
        classify_error_message("Missing colon delimiter in HTTP header"),
        ParserErrorKind::InvalidHeader
    );
    assert_eq!(
        classify_error_message("Whitespace disallowed between header name and colon"),
        ParserErrorKind::InvalidHeader
    );
    assert_eq!(
        classify_error_message("Bare CR character in header line disallowed"),
        ParserErrorKind::InvalidHeader
    );

    // MalformedStartLine
    assert_eq!(
        classify_error_message("Invalid HTTP method in request line"),
        ParserErrorKind::MalformedStartLine
    );
    assert_eq!(
        classify_error_message("Unsupported HTTP version: HTTP/2.0"),
        ParserErrorKind::MalformedStartLine
    );
    assert_eq!(
        classify_error_message("Invalid status code in response status line"),
        ParserErrorKind::MalformedStartLine
    );
    assert_eq!(
        classify_error_message("Malformed URI target in request line"),
        ParserErrorKind::MalformedStartLine
    );
    assert_eq!(
        classify_error_message("Malformed start line format"),
        ParserErrorKind::MalformedStartLine
    );

    // ReassemblyFailure & Fallback
    assert_eq!(
        classify_error_message("Orphan response received with status 404"),
        ParserErrorKind::ReassemblyFailure
    );
    assert_eq!(
        classify_error_message("Stream reassembly synchronization failed"),
        ParserErrorKind::ReassemblyFailure
    );
    assert_eq!(
        classify_error_message("Unknown network driver error"),
        ParserErrorKind::ReassemblyFailure
    );
    assert_eq!(
        classify_error_message(""),
        ParserErrorKind::ReassemblyFailure
    );
}

// =========================================================================
// 2. Sensitive Data Redaction & Zero Credentials Leakage
// =========================================================================

#[test]
fn test_day16_redaction_exhaustive_credential_types() {
    let mock_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzk5OSJ9.fake_sig_12345";
    let mock_api_key = "app_sec_prod_998877665544332211";

    // 1. Bearer token in mixed casing and with whitespace
    let input1 = format!("Authorization: Bearer {}", mock_jwt);
    let redacted1 = redact_sensitive_preview(&input1, 100);
    assert!(!redacted1.contains(mock_jwt));
    assert!(redacted1.contains("[REDACTED:authorization]"));

    // 2. API Key header
    let input2 = format!("X-API-Key: {}", mock_api_key);
    let redacted2 = redact_sensitive_preview(&input2, 100);
    assert!(!redacted2.contains(mock_api_key));
    assert!(redacted2.contains("[REDACTED:x-api-key]"));

    // 3. Cookie header
    let input3 = "Cookie: session_id=sess_998877; token=tok_abc123; user=alice";
    let redacted3 = redact_sensitive_preview(input3, 100);
    assert!(!redacted3.contains("sess_998877"));
    assert!(redacted3.contains("[REDACTED:cookie]"));

    // 4. Password / secret in body or header preview
    let input4 = "POST /login password=super_secret_master_password_42";
    let redacted4 = redact_sensitive_preview(input4, 100);
    assert!(!redacted4.contains("super_secret_master_password_42"));
    assert!(redacted4.contains("[REDACTED:password]"));

    // 5. Query string tokens in URL
    let input5 = "GET /api/v1/users?token=super_secret_token&client_id=100 HTTP/1.1";
    let redacted5 = redact_sensitive_preview(input5, 100);
    assert!(!redacted5.contains("super_secret_token"));
    assert!(redacted5.contains("?[REDACTED_QUERY]"));
    assert!(redacted5.contains("/api/v1/users?[REDACTED_QUERY]"));

    // 6. Standalone JWT in preview
    let input6 = format!("Encountered unexpected token payload: {}", mock_jwt);
    let redacted6 = redact_sensitive_preview(&input6, 100);
    assert!(!redacted6.contains(mock_jwt));
    assert!(redacted6.contains("[REDACTED_JWT]"));
}

#[test]
fn test_day16_redaction_crlf_log_injection_defense() {
    let injection_attempt = "GET /normal HTTP/1.1\r\nINJECTED_HEADER: evil\r\n\x00\x1b[31mFAKE LOG ENTRY";
    let sanitized = redact_sensitive_preview(injection_attempt, 120);

    assert!(!sanitized.contains('\r'), "Carriage return must be stripped");
    assert!(!sanitized.contains('\n'), "Newline must be stripped");
    assert!(!sanitized.contains('\0'), "Null byte must be stripped");
    assert!(!sanitized.contains('\x1b'), "Escape character must be stripped");
    assert!(sanitized.contains("GET /normal HTTP/1.1"));
}

#[test]
fn test_day16_redaction_multibyte_utf8_boundary_safety() {
    // Emojis (4-byte UTF-8) and East Asian characters (3-byte UTF-8)
    let complex_utf8 = "🚨⚠️🛡️ ユーザー認証エラー: 日本語テキストテスト";

    // Truncating at various arbitrary lengths must NEVER panic
    for max_len in 0..30 {
        let preview = redact_sensitive_preview(complex_utf8, max_len);
        if max_len == 0 {
            assert!(preview.is_empty());
        } else {
            assert!(preview.chars().count() <= max_len + 3); // Account for trailing "..."
        }
    }
}

// =========================================================================
// 3. Ring Buffer Capacity, FIFO Eviction & Counter Precision
// =========================================================================

#[test]
fn test_day16_diagnostic_ring_buffer_fifo_eviction() {
    // Initialize reassembler with small ring buffer capacity = 5
    let mut reassembler = StreamReassembler::new().with_max_diagnostics(5);
    let conn_id = "192.168.1.100:50000->10.0.0.1:8080";

    // Feed 20 malformed requests with indexed errors
    for i in 0..20 {
        let bad_req = format!("BAD_METHOD_{} /path HTTP/1.1\r\n\r\n", i);
        reassembler.feed_raw(
            conn_id,
            100.0 + (i as f64),
            TrafficDirection::Ingress,
            bad_req.as_bytes(),
        );
    }

    // 1. Ring buffer size must remain capped at exactly 5
    let diags = reassembler.diagnostics();
    assert_eq!(diags.len(), 5);

    // 2. FIFO eviction: entries must be the latest 5 (indices 15..20)
    for (idx, entry) in diags.iter().enumerate() {
        let expected_method_num = 15 + idx;
        assert!(
            entry.message.contains(&format!("BAD_METHOD_{}", expected_method_num)),
            "Expected diagnostic message to contain BAD_METHOD_{}, got: {}",
            expected_method_num,
            entry.message
        );
    }

    // 3. Total error counts must retain the complete count (20)
    assert_eq!(reassembler.total_errors(), 20);
    assert_eq!(
        reassembler.error_count(ParserErrorKind::MalformedStartLine),
        20
    );

    // 4. Dynamic downsizing: reduce capacity to 3 -> oldest 2 must be evicted immediately
    reassembler.set_max_diagnostics(3);
    assert_eq!(reassembler.diagnostics().len(), 3);
    assert!(reassembler.diagnostics()[0].message.contains("BAD_METHOD_17"));

    // 5. Clear diagnostics resets buffer and counts cleanly
    reassembler.clear_diagnostics();
    assert_eq!(reassembler.diagnostics().len(), 0);
    assert_eq!(reassembler.total_errors(), 0);
    assert_eq!(
        reassembler.error_count(ParserErrorKind::MalformedStartLine),
        0
    );
}

// =========================================================================
// 4. Stream Recovery After Malformed Traffic
// =========================================================================

#[test]
fn test_day16_ingress_stream_recovery_after_garbage() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.1.50:49152->10.0.1.1:80";

    // 1. Send completely corrupted garbage line on ingress
    let garbage = b"GARBAGE_LINE_WITHOUT_HTTP_METHOD_OR_STRUCTURE\r\n";
    let recs1 = reassembler.feed_raw(conn_id, 1.0, TrafficDirection::Ingress, garbage);
    assert!(recs1.is_empty());
    assert_eq!(reassembler.total_errors(), 1);

    // 2. Send valid HTTP GET request immediately on the same connection
    let valid_req = b"GET /api/v1/status HTTP/1.1\r\nHost: sentinel.internal\r\nX-User-Id: operator_1\r\n\r\n";
    let recs2 = reassembler.feed_raw(conn_id, 1.1, TrafficDirection::Ingress, valid_req);
    assert!(recs2.is_empty(), "Waiting for response");

    // 3. Send valid HTTP 200 response on egress
    let valid_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
    let recs3 = reassembler.feed_raw(conn_id, 1.15, TrafficDirection::Egress, valid_resp);

    assert_eq!(recs3.len(), 1, "Should successfully emit recovered record");
    let rec = &recs3[0];
    assert_eq!(rec.user, "operator_1");
    assert_eq!(rec.method, "GET");
    assert_eq!(rec.path, "/api/v1/status");
    assert_eq!(rec.status, 200);
    assert!((rec.latency_ms - 50.0).abs() < 1.0);
    assert_eq!(rec.src_ip, "10.0.1.50");
}

#[test]
fn test_day16_egress_stream_recovery_after_malformed_response() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.2.75:52000->10.0.2.1:8080";

    // 1. Enqueue two valid pending requests
    let req1 = b"GET /first HTTP/1.1\r\nHost: a.com\r\n\r\n";
    let req2 = b"GET /second HTTP/1.1\r\nHost: a.com\r\n\r\n";
    reassembler.feed_raw(conn_id, 10.0, TrafficDirection::Ingress, req1);
    reassembler.feed_raw(conn_id, 10.1, TrafficDirection::Ingress, req2);
    assert_eq!(reassembler.total_pending_requests(), 2);

    // 2. Send malformed response bytes on egress
    let bad_resp = b"HTTP/1.1 9999 InvalidStatus\r\n\r\n";
    let recs_bad = reassembler.feed_raw(conn_id, 10.2, TrafficDirection::Egress, bad_resp);
    assert!(recs_bad.is_empty());
    assert_eq!(reassembler.error_count(ParserErrorKind::MalformedStartLine), 1);

    // 3. Send valid response for the first pending request
    let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nr1";
    let recs_ok1 = reassembler.feed_raw(conn_id, 10.25, TrafficDirection::Egress, resp1);
    assert_eq!(recs_ok1.len(), 1);
    assert_eq!(recs_ok1[0].path, "/first");
    assert_eq!(recs_ok1[0].status, 200);

    // 4. Send valid response for the second pending request
    let resp2 = b"HTTP/1.1 204 No Content\r\n\r\n";
    let recs_ok2 = reassembler.feed_raw(conn_id, 10.3, TrafficDirection::Egress, resp2);
    assert_eq!(recs_ok2.len(), 1);
    assert_eq!(recs_ok2[0].path, "/second");
    assert_eq!(recs_ok2[0].status, 204);
}

// =========================================================================
// 5. Memory Boundedness Under Malformed Flood
// =========================================================================

#[test]
fn test_day16_malformed_flood_memory_bounds() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.10.5:60000->10.0.0.1:80";

    // Flood with 500 malformed requests with oversized lines and header errors
    for i in 0..500 {
        let payload = format!("BAD_LINE_{}: {}\r\n", i, "X".repeat(100));
        reassembler.feed_raw(
            conn_id,
            1000.0 + (i as f64) * 0.001,
            TrafficDirection::Ingress,
            payload.as_bytes(),
        );
    }

    // Ingress buffer must be drained via line skipping; no unbounded memory growth
    let diags = reassembler.diagnostics();
    assert_eq!(diags.len(), 128); // Capped at default 128
    assert_eq!(reassembler.total_errors(), 500);

    // Send valid request and response to verify stream still recovers completely
    let req = b"GET /health HTTP/1.1\r\nHost: sentinel.internal\r\n\r\n";
    reassembler.feed_raw(conn_id, 2000.0, TrafficDirection::Ingress, req);

    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let final_recs = reassembler.feed_raw(conn_id, 2000.005, TrafficDirection::Egress, resp);

    assert_eq!(final_recs.len(), 1);
    assert_eq!(final_recs[0].path, "/health");
    assert_eq!(final_recs[0].status, 200);
    assert!(final_recs[0].to_json().is_ok());
}
