//! Day 13 Public API Integration Test Suite.
//!
//! Verifies the parser entirely through its documented public interface (`api_sentinel_parser::*`).
//! Does NOT import any internal private module paths or unexported structs.
//!
//! Validates:
//! 1. End-to-end stream ingestion via `HttpParser` trait (`feed_raw`, `feed_fragment`)
//! 2. Downstream consumer clarity: distinguishing anonymous users, orphan responses, malformed traffic, and valid transactions
//! 3. `Record` schema and JSON contract forward/backward compatibility
//! 4. Connection lifecycle management (`active_connections`, `clean_idle_connections`, `reset`)
//! 5. Bounded configuration via `ParserLimits`
//! 6. Stateless request/response public parsing functions

use api_sentinel_parser::{
    canonical_connection_key, decode_jwt_payload, extract_identity_and_role, parse_endpoints,
    parse_http_request, parse_http_response, ConnectionKey, HttpParser, ParserLimits, RawFragment,
    Record, StreamReassembler, TrafficDirection, DEFAULT_ANONYMOUS_USER, DEFAULT_USER_ROLE,
};
use std::collections::HashMap;

// =========================================================================
// 1. End-to-End Ingestion via Public HttpParser Trait
// =========================================================================

#[test]
fn test_public_api_end_to_end_stream_ingestion() {
    let mut parser = StreamReassembler::new();
    let conn_id = "192.168.1.50:49152->10.0.0.1:8080";

    // Valid JWT: {"sub":"svc_order_processor","role":"service"}
    // header b64: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    // payload b64: eyJzdWIiOiJzdmNfb3JkZXJfcHJvY2Vzc29yIiwicm9sZSI6InNlcnZpY2UifQ
    let jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmNfb3JkZXJfcHJvY2Vzc29yIiwicm9sZSI6InNlcnZpY2UifQ.mock_sig";

    let req_payload = format!(
        "POST /api/v1/orders HTTP/1.1\r\n\
         Host: orders.internal.net\r\n\
         Authorization: Bearer {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 26\r\n\r\n\
         {{\"item_id\":101,\"qty\":5}}",
        jwt_token
    );

    // 1. Ingest request via public HttpParser::feed_raw
    let req_records = parser.feed_raw(
        conn_id,
        1700000000.0,
        TrafficDirection::Ingress,
        req_payload.as_bytes(),
    );
    assert!(
        req_records.is_empty(),
        "In-flight request yields no records until response"
    );

    // Check active connections through public API
    let active = parser.active_connections();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0], canonical_connection_key(conn_id));

    // 2. Ingest response via public HttpParser::feed_fragment
    let resp_payload = b"HTTP/1.1 201 Created\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: 22\r\n\r\n\
                         {\"order_id\":\"ord_999\"}";

    let frag = RawFragment::new(
        conn_id,
        1700000000.025,
        TrafficDirection::Egress,
        resp_payload.to_vec(),
    );

    let resp_records = parser.feed_fragment(&frag);
    assert_eq!(
        resp_records.len(),
        1,
        "Matched transaction produces exactly one Record"
    );

    let rec = &resp_records[0];
    assert_eq!(rec.method, "POST");
    assert_eq!(rec.path, "/api/v1/orders");
    assert_eq!(rec.status, 201);
    assert!(rec.ok());
    assert!(!rec.is_anonymous());
    assert!(!rec.is_orphan());
    assert_eq!(rec.user, "svc_order_processor");
    assert_eq!(rec.role, "service");
    assert_eq!(rec.src_ip, "192.168.1.50");
    assert!((rec.latency_ms - 25.0).abs() < 0.1);

    // Bodies
    assert!(rec.has_request_body());
    assert!(rec.has_response_body());
    assert_eq!(rec.req_body.as_ref().unwrap()["qty"], 5);
    assert_eq!(rec.resp_body.as_ref().unwrap()["order_id"], "ord_999");
}

// =========================================================================
// 2. Downstream Consumer Ambiguity Resolution
// =========================================================================

#[test]
fn test_downstream_distinguishes_anonymous_identity() {
    let mut parser = StreamReassembler::new();
    let conn_id = "10.0.0.5:1234->10.0.0.1:80";

    // Unauthenticated GET request
    parser.feed_raw(
        conn_id,
        100.0,
        TrafficDirection::Ingress,
        b"GET /public/info HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    let records = parser.feed_raw(
        conn_id,
        100.005,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
    );

    assert_eq!(records.len(), 1);
    let rec = &records[0];

    // Downstream consumers can check either method
    assert!(rec.is_anonymous());
    assert_eq!(rec.user, DEFAULT_ANONYMOUS_USER);
    assert_eq!(rec.role, DEFAULT_USER_ROLE);
    assert!(!rec.is_orphan());
}

#[test]
fn test_downstream_distinguishes_orphan_mid_session_responses() {
    let mut parser = StreamReassembler::new();
    let conn_id = "10.0.0.9:5555->10.0.0.1:443";

    // Mid-session capture: response arrives without seeing prior request
    let records = parser.feed_raw(
        conn_id,
        200.0,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"seen\":true}",
    );

    assert_eq!(records.len(), 1);
    let rec = &records[0];

    // Downstream consumers can immediately identify orphan responses
    assert!(rec.is_orphan());
    assert_eq!(rec.method, "UNKNOWN");
    assert_eq!(rec.path, "");
    assert_eq!(rec.latency_ms, 0.0);
    assert_eq!(rec.status, 200);
    assert_eq!(parser.unmatched_responses_count, 1);
}

#[test]
fn test_downstream_malformed_traffic_handling() {
    let mut parser = StreamReassembler::new();
    let conn_id = "10.0.0.10:9000->10.0.0.1:80";

    // Pure binary garbage
    let bad_records = parser.feed_raw(
        conn_id,
        300.0,
        TrafficDirection::Ingress,
        b"\xff\xfe\x00\x01\x02\x03GARBAGE_WITHOUT_HTTP_DELIMITER",
    );
    assert!(
        bad_records.is_empty(),
        "Malformed garbage yields no records"
    );

    // Connection remains operational: subsequent valid transaction succeeds
    parser.feed_raw(
        conn_id,
        301.0,
        TrafficDirection::Ingress,
        b"GET /health HTTP/1.1\r\nHost: local\r\n\r\n",
    );

    let ok_records = parser.feed_raw(
        conn_id,
        301.002,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );

    assert_eq!(ok_records.len(), 1);
    assert_eq!(ok_records[0].path, "/health");
    assert_eq!(ok_records[0].status, 200);
}

// =========================================================================
// 3. Record Schema & Serialization Contract (Backward & Forward Compatibility)
// =========================================================================

#[test]
fn test_record_json_schema_and_serialization_contract() {
    let mut rec = Record::new(1700000000.5, "usr_bob", "PUT", "/api/profile", 200);
    rec.src_ip = "192.168.1.10".to_string();
    rec.role = "admin".to_string();
    rec.latency_ms = 12.34;
    rec.req_body = Some(serde_json::json!({"email": "bob@corp.net"}));
    rec.resp_body = Some(serde_json::json!({"updated": true}));

    // Serialize to compact JSON
    let json_str = rec.to_json().expect("Serialize Record to JSON");

    // Verify expected keys exist in raw JSON string
    assert!(json_str.contains("\"ts\":1700000000.5"));
    assert!(json_str.contains("\"user\":\"usr_bob\""));
    assert!(json_str.contains("\"role\":\"admin\""));
    assert!(json_str.contains("\"method\":\"PUT\""));
    assert!(json_str.contains("\"path\":\"/api/profile\""));
    assert!(json_str.contains("\"status\":200"));
    assert!(json_str.contains("\"latency_ms\":12.34"));
    assert!(json_str.contains("\"src_ip\":\"192.168.1.10\""));

    // Roundtrip deserialization
    let restored = Record::from_json(&json_str).expect("Deserialize Record from JSON");
    assert_eq!(rec, restored);

    // Forward compatibility: unknown fields added by future modules are safely ignored
    let json_with_future_fields = r#"{
        "ts": 1700000000.5,
        "user": "usr_bob",
        "role": "admin",
        "method": "PUT",
        "path": "/api/profile",
        "status": 200,
        "latency_ms": 12.34,
        "src_ip": "192.168.1.10",
        "future_anomaly_score": 0.95,
        "future_ml_tags": ["suspicious_ip", "idor_attempt"]
    }"#;

    let future_rec = Record::from_json(json_with_future_fields)
        .expect("Record::from_json ignores unknown future fields gracefully");
    assert_eq!(future_rec.user, "usr_bob");
    assert_eq!(future_rec.status, 200);
}

// =========================================================================
// 4. Connection Lifecycle & Cleanup via Public API
// =========================================================================

#[test]
fn test_public_api_connection_lifecycle_and_cleanup() {
    let mut parser = StreamReassembler::with_timeout(10.0);

    let conn_1 = "10.0.0.1:1000->10.0.0.2:80";
    let conn_2 = "10.0.0.3:2000->10.0.0.4:80";

    // Feed in-flight request for both connections at ts = 50.0
    parser.feed_raw(
        conn_1,
        50.0,
        TrafficDirection::Ingress,
        b"GET /1 HTTP/1.1\r\n\r\n",
    );
    parser.feed_raw(
        conn_2,
        50.0,
        TrafficDirection::Ingress,
        b"GET /2 HTTP/1.1\r\n\r\n",
    );

    let active_before = parser.active_connections();
    assert_eq!(active_before.len(), 2);

    // Keep conn_1 alive at ts = 58.0
    parser.feed_raw(conn_1, 58.0, TrafficDirection::Ingress, b"");

    // Clean idle connections at ts = 62.0 (timeout = 10.0)
    // conn_2 inactive duration: 62.0 - 50.0 = 12.0s > 10.0s -> evicted
    // conn_1 inactive duration: 62.0 - 58.0 = 4.0s <= 10.0s -> retained
    let evicted = parser.clean_idle_connections(62.0);
    assert_eq!(evicted, 1);

    // Reset conn_1 explicitly
    parser.reset(Some(conn_1));
    assert!(parser.active_connections().is_empty());

    // Reset all
    parser.reset(None);
    assert_eq!(parser.connections.len(), 0);
}

// =========================================================================
// 5. Configurable ParserLimits via Public Builder
// =========================================================================

#[test]
fn test_public_api_parser_limits_builder() {
    let custom_limits = ParserLimits::new()
        .with_max_header_size(256)
        .with_max_body_size(128)
        .with_max_chunk_size(128)
        .with_max_headers_count(5)
        .with_max_line_length(64);

    let mut parser = StreamReassembler::with_config(30.0, custom_limits);

    // Body exceeding custom limit of 128 bytes
    let big_body = "x".repeat(200);
    let req = format!(
        "POST /api/big HTTP/1.1\r\nContent-Length: 200\r\n\r\n{}",
        big_body
    );

    let records = parser.feed_raw(
        "10.0.0.1:1000->10.0.0.2:80",
        1.0,
        TrafficDirection::Ingress,
        req.as_bytes(),
    );
    assert!(records.is_empty(), "Oversized body rejected safely");
}

// =========================================================================
// 6. Public Stateless Parsers & Auth Utilities
// =========================================================================

#[test]
fn test_public_stateless_request_and_response_parsers() {
    // Stateless request parsing
    let req_bytes = b"GET /v2/items?category=books&limit=10 HTTP/1.1\r\nHost: store.io\r\n\r\n";
    let req_res = parse_http_request(req_bytes, 100.0, "127.0.0.1", 8080, "127.0.0.1", 80);
    assert!(req_res.is_complete);
    assert!(req_res.error.is_none());

    let parsed_req = req_res.request.expect("Parsed request");
    assert_eq!(parsed_req.method, "GET");
    assert_eq!(parsed_req.base_path(), "/v2/items");
    assert_eq!(parsed_req.get_query_param("category"), Some("books"));
    assert_eq!(parsed_req.get_query_param("limit"), Some("10"));

    // Stateless response parsing
    let resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"available\":true}";
    let resp_res = parse_http_response(resp_bytes, 100.010);
    assert!(resp_res.is_complete);
    assert!(resp_res.error.is_none());

    let parsed_resp = resp_res.response.expect("Parsed response");
    assert_eq!(parsed_resp.status, 200);
    assert_eq!(parsed_resp.status_text, "OK");
    assert_eq!(parsed_resp.body.as_ref().unwrap()["available"], true);
}

#[test]
fn test_public_auth_helpers() {
    // Valid JWT payload extraction
    let payload =
        decode_jwt_payload("header.eyJzdWIiOiJ1c3JfZXhwb3J0ZWQiLCJyb2xlIjoiYWRtaW4ifQ.sig");
    assert!(payload.is_some());
    let claims = payload.unwrap();
    assert_eq!(claims["sub"], "usr_exported");
    assert_eq!(claims["role"], "admin");

    // Endpoint parsing helper
    let (src_ip, src_port, dst_ip, dst_port) = parse_endpoints("10.0.0.1:8080->192.168.1.1:443");
    assert_eq!(src_ip, "10.0.0.1");
    assert_eq!(src_port, 8080);
    assert_eq!(dst_ip, "192.168.1.1");
    assert_eq!(dst_port, 443);

    // Canonical bidirectional key helper
    let k1 = canonical_connection_key("10.0.0.1:80->10.0.0.2:90");
    let k2 = canonical_connection_key("10.0.0.2:90->10.0.0.1:80");
    assert_eq!(k1, k2);
}
