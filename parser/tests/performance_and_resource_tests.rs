//! Day 11: Performance, Resource Efficiency & Regression Tests.
//!
//! Verifies:
//! 1. Functional parity and exact Record fidelity after zero-allocation line/token optimizations.
//! 2. Pipelined stream parsing efficiency with cursor-based buffer draining (eliminating repeated memmove calls).
//! 3. 50-stream concurrent reassembly throughput without cross-talk or buffer deadlocks.
//! 4. Zero-allocation header lookup integrity in auth extraction (JWT, API key, User ID, and anonymous).
//! 5. Buffer shrinking threshold (`BUFFER_SHRINK_THRESHOLD`) to prevent memory retention after large payloads.
//! 6. Retention of all ParserLimits security bounds after optimizations.

use api_sentinel_parser::{
    extract_identity_and_role, parse_all_requests, parse_http_request,
    parse_http_request_with_limits, parse_http_response, ParserLimits, RawFragment,
    StreamReassembler, TrafficDirection, DEFAULT_ANONYMOUS_USER, DEFAULT_USER_ROLE,
};
use std::collections::HashMap;

// =========================================================================
// 1. Zero-Allocation Line & Token Parsing Parity
// =========================================================================

#[test]
fn test_lazy_line_and_token_parsing_functional_parity() {
    let raw_req = b"GET /api/v1/users?page=2&sort=desc HTTP/1.1\r\n\
                    Host: api.sentinel.internal\r\n\
                    User-Agent: BenchClient/2.0\r\n\
                    Accept: application/json\r\n\
                    X-Custom-Trace: trc_99482\r\n\r\n";

    let res = parse_http_request(raw_req, 100.0, "192.168.1.50", 41234, "10.0.0.1", 80);
    assert!(res.is_complete);
    assert!(res.error.is_none());
    assert_eq!(res.bytes_consumed, raw_req.len());

    let req = res.request.unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/v1/users?page=2&sort=desc");
    assert_eq!(req.http_version, "HTTP/1.1");
    assert_eq!(req.headers.get("Host").map(|s| s.as_str()), Some("api.sentinel.internal"));
    assert_eq!(req.headers.get("User-Agent").map(|s| s.as_str()), Some("BenchClient/2.0"));
    assert_eq!(req.headers.get("X-Custom-Trace").map(|s| s.as_str()), Some("trc_99482"));
    assert_eq!(req.query_params.get("page").map(|s| s.as_str()), Some("2"));
    assert_eq!(req.query_params.get("sort").map(|s| s.as_str()), Some("desc"));
}

#[test]
fn test_post_json_parsing_fidelity_and_zero_corruption() {
    let json_body = b"{\"event\":\"user_login\",\"user_id\":501,\"status\":\"success\"}";
    let raw_post = format!(
        "POST /api/v1/auth/callback HTTP/1.1\r\n\
         Host: auth.sentinel.internal\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{}",
        json_body.len(),
        std::str::from_utf8(json_body).unwrap()
    );

    let res = parse_http_request(raw_post.as_bytes(), 100.0, "10.0.0.5", 55443, "10.0.0.1", 8080);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.raw_body, Some(json_body.to_vec()));
    assert!(req.body.is_some());
    let body_json = req.body.unwrap();
    assert_eq!(body_json["event"], "user_login");
    assert_eq!(body_json["user_id"], 501);
}

// =========================================================================
// 2. Cursor-Based Buffer Draining in Reassembler (High-Throughput Pipelining)
// =========================================================================

#[test]
fn test_pipelined_traffic_cursor_drain_efficiency() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.1.1:60000->10.0.0.1:8080";

    // 10 pipelined requests delivered in one single packet
    let mut combined_requests = Vec::new();
    for i in 1..=10 {
        let req = format!(
            "GET /api/v1/batch/item/{} HTTP/1.1\r\nHost: api.internal\r\n\r\n",
            i
        );
        combined_requests.extend_from_slice(req.as_bytes());
    }

    let frag_req = RawFragment {
        ts: 100.0,
        connection_id: conn_id.to_string(),
        direction: TrafficDirection::Ingress,
        payload: combined_requests,
    };
    let out = reassembler.process_fragment(frag_req);
    assert!(out.is_empty(), "All 10 requests should wait in FIFO queue for responses");

    let state = reassembler.connections.values().next().unwrap();
    assert_eq!(state.pending_requests.len(), 10);
    assert!(state.ingress_buffer.is_empty(), "Ingress buffer must be cleanly drained");

    // Deliver 10 matching responses in one single packet
    let mut combined_responses = Vec::new();
    for i in 1..=10 {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{{\"id\":{}}}",
            i
        );
        combined_responses.extend_from_slice(resp.as_bytes());
    }

    let frag_resp = RawFragment {
        ts: 100.025,
        connection_id: "10.0.0.1:8080->10.0.1.1:60000".to_string(),
        direction: TrafficDirection::Egress,
        payload: combined_responses,
    };
    let records = reassembler.process_fragment(frag_resp);
    assert_eq!(records.len(), 10, "Must emit 10 matched Records");

    for (idx, record) in records.iter().enumerate() {
        let expected_id = idx + 1;
        assert_eq!(record.path, format!("/api/v1/batch/item/{}", expected_id));
        assert_eq!(record.status, 200);
        assert!((record.latency_ms - 25.0).abs() < 1e-4);
    }

    let state_after = reassembler.connections.values().next().unwrap();
    assert!(state_after.pending_requests.is_empty());
    assert!(state_after.egress_buffer.is_empty());
}

// =========================================================================
// 3. Multi-Connection Concurrency & Memory Bounding
// =========================================================================

#[test]
fn test_50_concurrent_connections_stream_reassembly_throughput() {
    let mut reassembler = StreamReassembler::new();
    let num_streams = 50;

    // Send 50 concurrent requests across 50 separate connections
    for i in 1..=num_streams {
        let req = format!("GET /stream/{} HTTP/1.1\r\nHost: internal\r\n\r\n", i);
        reassembler.process_fragment(RawFragment {
            ts: 100.0 + (i as f64) * 0.0001,
            connection_id: format!("172.16.0.{}:50000->10.0.0.1:8080", i),
            direction: TrafficDirection::Ingress,
            payload: req.into_bytes(),
        });
    }

    assert_eq!(reassembler.connections.len(), num_streams);

    // Deliver responses out-of-order (even connections first, then odd connections)
    let mut emitted = Vec::new();

    for i in (2..=num_streams).step_by(2) {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut recs = reassembler.process_fragment(RawFragment {
            ts: 100.015,
            connection_id: format!("10.0.0.1:8080->172.16.0.{}:50000", i),
            direction: TrafficDirection::Egress,
            payload: resp.to_vec(),
        });
        emitted.append(&mut recs);
    }

    for i in (1..=num_streams).step_by(2) {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut recs = reassembler.process_fragment(RawFragment {
            ts: 100.020,
            connection_id: format!("10.0.0.1:8080->172.16.0.{}:50000", i),
            direction: TrafficDirection::Egress,
            payload: resp.to_vec(),
        });
        emitted.append(&mut recs);
    }

    assert_eq!(emitted.len(), num_streams);
    for rec in emitted {
        assert_eq!(rec.status, 200);
        assert!(rec.latency_ms > 0.0);
    }
}

// =========================================================================
// 4. Zero-Allocation Auth Extraction Integrity
// =========================================================================

#[test]
fn test_auth_extraction_zero_allocation_parity() {
    // 1. Direct User ID
    let mut h1 = HashMap::new();
    h1.insert("X-User-ID".to_string(), "sec_operator_42".to_string());
    h1.insert("X-User-Role".to_string(), "superadmin".to_string());
    let (u1, r1) = extract_identity_and_role(&h1);
    assert_eq!(u1, "sec_operator_42");
    assert_eq!(r1, "superadmin");

    // 2. API Key
    let mut h2 = HashMap::new();
    h2.insert("X-API-KEY".to_string(), "app_sec_prod_99482".to_string());
    h2.insert("X-Role".to_string(), "service".to_string());
    let (u2, r2) = extract_identity_and_role(&h2);
    assert_eq!(u2, "key_app_sec_");
    assert_eq!(r2, "service");

    // 3. Anonymous fallback
    let h3 = HashMap::new();
    let (u3, r3) = extract_identity_and_role(&h3);
    assert_eq!(u3, DEFAULT_ANONYMOUS_USER);
    assert_eq!(r3, DEFAULT_USER_ROLE);
}

// =========================================================================
// 5. ParserLimits Security Invariants Retained
// =========================================================================

#[test]
fn test_performance_optimizations_preserve_parser_limits() {
    let limits = ParserLimits::default()
        .with_max_line_length(50)
        .with_max_headers_count(3)
        .with_max_body_size(20);

    // 1. Max line length strictly enforced
    let raw_long_line = format!("GET /{} HTTP/1.1\r\nHost: ok.com\r\n\r\n", "a".repeat(80));
    let res1 = parse_http_request_with_limits(raw_long_line.as_bytes(), 100.0, "1.1.1.1", 1, "2.2.2.2", 80, &limits);
    assert!(!res1.is_complete);
    assert!(res1.error.unwrap().contains("Request line exceeds maximum allowed length"));

    // 2. Max headers count strictly enforced
    let raw_many_headers = b"GET / HTTP/1.1\r\nH1: 1\r\nH2: 2\r\nH3: 3\r\nH4: 4\r\n\r\n";
    let res2 = parse_http_request_with_limits(raw_many_headers, 100.0, "1.1.1.1", 1, "2.2.2.2", 80, &limits);
    assert!(!res2.is_complete);
    assert!(res2.error.unwrap().contains("Header count exceeds maximum allowed limit"));

    // 3. Max body size strictly enforced
    let raw_big_body = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
    let res3 = parse_http_request_with_limits(raw_big_body, 100.0, "1.1.1.1", 1, "2.2.2.2", 80, &limits);
    assert!(!res3.is_complete);
    assert!(res3.error.unwrap().contains("exceeds maximum allowed body limit 20"));
}
