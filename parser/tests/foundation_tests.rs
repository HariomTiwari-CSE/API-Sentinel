//! Unit tests for the API-Sentinel Rust HTTP Parser foundation, data contracts, Day 3 response parsing, and Day 4 hardening.

use std::collections::HashMap;
use std::str::FromStr;
use api_sentinel_parser::{
    decode_chunked_body, decode_chunked_body_with_limits, decode_url_component,
    extract_identity_and_role, parse_all_requests, parse_all_responses, parse_http_request,
    parse_http_request_with_limits, parse_http_response, parse_http_response_with_limits,
    parse_query_params, parse_uri_query, ConnectionKey, ConnectionState, HttpParser,
    ParsedHTTPRequest, ParsedHTTPResponse, ParserLimits, RawFragment, Record, StreamReassembler,
    TrafficDirection,
};

#[test]
fn test_record_instantiation_defaults() {
    let record = Record::new(1731312000.0, "user_42", "GET", "/api/orders/1002", 200);
    assert_eq!(record.ts, 1731312000.0);
    assert_eq!(record.user, "user_42");
    assert_eq!(record.method, "GET");
    assert_eq!(record.path, "/api/orders/1002");
    assert_eq!(record.status, 200);
    assert_eq!(record.req_body, None);
    assert_eq!(record.resp_body, None);
    assert_eq!(record.latency_ms, 0.0);
    assert_eq!(record.src_ip, "");
    assert_eq!(record.role, "user");
    assert!(record.ok());
}

#[test]
fn test_record_ok_status_variations() {
    assert!(Record::new(1.0, "u", "GET", "/", 200).ok());
    assert!(Record::new(1.0, "u", "POST", "/", 201).ok());
    assert!(Record::new(1.0, "u", "DELETE", "/", 204).ok());

    assert!(!Record::new(1.0, "u", "GET", "/", 301).ok());
    assert!(!Record::new(1.0, "u", "GET", "/", 400).ok());
    assert!(!Record::new(1.0, "u", "GET", "/", 401).ok());
    assert!(!Record::new(1.0, "u", "GET", "/", 403).ok());
    assert!(!Record::new(1.0, "u", "GET", "/", 404).ok());
    assert!(!Record::new(1.0, "u", "GET", "/", 500).ok());
}

#[test]
fn test_record_serialization_roundtrip() {
    let mut record = Record::new(1731312000.1, "user_55", "POST", "/api/auth/login", 200);
    record.req_body = Some(serde_json::json!({"username": "alice"}));
    record.resp_body = Some(serde_json::json!({"token": "xyz789"}));
    record.latency_ms = 15.6;
    record.src_ip = "192.168.1.50".to_string();
    record.role = "admin".to_string();

    let json_str = record.to_json().expect("Failed to serialize Record to JSON");
    let deserialized: Record = Record::from_json(&json_str).expect("Failed to deserialize Record from JSON");

    assert_eq!(deserialized, record);
    assert_eq!(deserialized.role, "admin");
    assert_eq!(deserialized.latency_ms, 15.6);
}

#[test]
fn test_traffic_direction_normalization() {
    assert_eq!(TrafficDirection::from_str("ingress").unwrap(), TrafficDirection::Ingress);
    assert_eq!(TrafficDirection::from_str("REQUEST").unwrap(), TrafficDirection::Ingress);
    assert_eq!(TrafficDirection::from_str("in").unwrap(), TrafficDirection::Ingress);

    assert_eq!(TrafficDirection::from_str("egress").unwrap(), TrafficDirection::Egress);
    assert_eq!(TrafficDirection::from_str("RESPONSE").unwrap(), TrafficDirection::Egress);
    assert_eq!(TrafficDirection::from_str("out").unwrap(), TrafficDirection::Egress);

    assert!(TrafficDirection::from_str("invalid_dir").is_err());
}

#[test]
fn test_connection_key_identifiers() {
    let key = ConnectionKey::new("10.0.0.5", 45000, "10.0.0.1", 8080);
    assert_eq!(key.connection_id(), "10.0.0.5:45000->10.0.0.1:8080");
    assert_eq!(key.reverse_id(), "10.0.0.1:8080->10.0.0.5:45000");

    let key_reversed = ConnectionKey::new("10.0.0.1", 8080, "10.0.0.5", 45000);
    assert_eq!(key.bidirectional_id(), key_reversed.bidirectional_id());
}

#[test]
fn test_raw_fragment_creation() {
    let fragment = RawFragment {
        connection_id: "conn_1".to_string(),
        ts: 1731312000.0,
        direction: TrafficDirection::Ingress,
        payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
    };
    assert_eq!(fragment.connection_id, "conn_1");
    assert_eq!(fragment.direction, TrafficDirection::Ingress);
    assert!(fragment.payload.starts_with(b"GET"));
}

#[test]
fn test_auth_extract_from_jwt_bearer() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiAidXNlcl83NzciLCAicm9sZSI6ICJzZWN1cml0eV9hZG1pbiIsICJleHAiOiAxOTk5OTk5OTk5fQ.mocksignature";
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "user_777");
    assert_eq!(role, "security_admin");
}

#[test]
fn test_auth_extract_from_api_key_headers() {
    let mut headers = HashMap::new();
    headers.insert("X-API-Key".to_string(), "live_apikey_secret_9999".to_string());

    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "key_live_api");
    assert_eq!(role, "user");
}

#[test]
fn test_auth_extract_from_user_id_headers() {
    let mut headers = HashMap::new();
    headers.insert("X-User-ID".to_string(), "admin_master".to_string());
    headers.insert("X-User-Role".to_string(), "superadmin".to_string());

    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "admin_master");
    assert_eq!(role, "superadmin");
}

#[test]
fn test_auth_anonymous_fallback() {
    let mut headers = HashMap::new();
    headers.insert("Host".to_string(), "api.example.com".to_string());

    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "anonymous");
    assert_eq!(role, "user");
}

#[test]
fn test_connection_state_buffering_and_latency() {
    let mut state = ConnectionState::new("conn_abc", 100.0);
    state.append_ingress(b"GET /api/test ", 100.0);
    state.append_ingress(b"HTTP/1.1\r\n\r\n", 100.1);
    assert_eq!(state.ingress_buffer, b"GET /api/test HTTP/1.1\r\n\r\n");
    assert_eq!(state.last_activity, 100.1);

    state.append_egress(b"HTTP/1.1 200 OK\r\n\r\n", 100.15);
    assert_eq!(state.egress_buffer, b"HTTP/1.1 200 OK\r\n\r\n");
    assert_eq!(state.last_activity, 100.15);

    let req = ParsedHTTPRequest {
        ts: 100.0,
        method: "GET".to_string(),
        path: "/test".to_string(),
        ..Default::default()
    };
    let resp = ParsedHTTPResponse {
        ts: 100.025,
        status: 200,
        ..Default::default()
    };

    let latency = state.calculate_latency_ms(&req, &resp);
    assert_eq!(latency, 25.0);

    state.clear();
    assert!(state.ingress_buffer.is_empty());
    assert!(state.egress_buffer.is_empty());
}

#[test]
fn test_parse_simple_get_request() {
    let raw = b"GET /api/orders/1002 HTTP/1.1\r\nHost: api.crapi.local\r\nUser-Agent: test\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "10.0.0.5", 54321, "10.0.0.1", 8080);
    assert!(res.is_complete);
    let req = res.request.expect("Expected parsed request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/orders/1002");
    assert_eq!(req.http_version, "HTTP/1.1");
    assert_eq!(req.headers.get("Host").unwrap(), "api.crapi.local");
    assert_eq!(req.body, None);
    assert_eq!(res.bytes_consumed, raw.len());
}

#[test]
fn test_parse_post_request_with_json_body() {
    let body = r#"{"item_id": 1002, "quantity": 1}"#;
    let raw = format!(
        "POST /api/orders HTTP/1.1\r\nHost: api.crapi.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let res = parse_http_request(raw.as_bytes(), 100.0, "10.0.0.5", 54321, "10.0.0.1", 8080);
    assert!(res.is_complete);
    let req = res.request.expect("Expected parsed request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/orders");
    assert!(req.body.is_some());
    let body_json = req.body.unwrap();
    assert_eq!(body_json["item_id"], 1002);
}

#[test]
fn test_parse_pipelined_requests() {
    let req1 = "GET /first HTTP/1.1\r\nHost: test\r\n\r\n";
    let req2 = "GET /second HTTP/1.1\r\nHost: test\r\n\r\n";
    let combined = format!("{}{}", req1, req2);

    let requests = parse_all_requests(combined.as_bytes(), 100.0, "10.0.0.5", 54321, "10.0.0.1", 8080);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/first");
    assert_eq!(requests[1].path, "/second");
}

// ---------------------------------------------------------
// Day 3 Response Parsing & Request-Response Matching Tests
// ---------------------------------------------------------

#[test]
fn test_parse_simple_response_200_ok() {
    let body = r#"{"order_id": 1002, "status": "shipped"}"#;
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nServer: nginx\r\n\r\n{}",
        body.len(),
        body
    );

    let res = parse_http_response(raw.as_bytes(), 100.05);
    assert!(res.is_complete);
    assert_eq!(res.bytes_consumed, raw.len());
    let resp = res.response.expect("Expected parsed response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.status_text, "OK");
    assert_eq!(resp.http_version, "HTTP/1.1");
    assert_eq!(resp.headers.get("Server").unwrap(), "nginx");
    assert!(resp.body.is_some());
    assert_eq!(resp.body.unwrap()["status"], "shipped");
}

#[test]
fn test_parse_response_status_codes_matrix() {
    let cases = vec![
        ("HTTP/1.1 200 OK\r\n\r\n", 200, "OK"),
        ("HTTP/1.1 201 Created\r\n\r\n", 201, "Created"),
        ("HTTP/1.1 204 No Content\r\n\r\n", 204, "No Content"),
        ("HTTP/1.1 301 Moved Permanently\r\n\r\n", 301, "Moved Permanently"),
        ("HTTP/1.1 304 Not Modified\r\n\r\n", 304, "Not Modified"),
        ("HTTP/1.1 400 Bad Request\r\n\r\n", 400, "Bad Request"),
        ("HTTP/1.1 401 Unauthorized\r\n\r\n", 401, "Unauthorized"),
        ("HTTP/1.1 403 Forbidden\r\n\r\n", 403, "Forbidden"),
        ("HTTP/1.1 404 Not Found\r\n\r\n", 404, "Not Found"),
        ("HTTP/1.1 500 Internal Server Error\r\n\r\n", 500, "Internal Server Error"),
    ];

    for (raw, exp_code, exp_text) in cases {
        let res = parse_http_response(raw.as_bytes(), 100.0);
        assert!(res.is_complete, "Failed for {}", exp_code);
        let resp = res.response.unwrap();
        assert_eq!(resp.status, exp_code);
        assert_eq!(resp.status_text, exp_text);
    }
}

#[test]
fn test_parse_response_204_no_content_semantics() {
    let raw = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
    let res = parse_http_response(raw, 100.0);
    assert!(res.is_complete);
    assert_eq!(res.bytes_consumed, raw.len());
    let resp = res.response.unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(resp.body, None);
}

#[test]
fn test_parse_response_chunked_body() {
    let chunk1 = b"Hello ";
    let chunk2 = b"World!";
    let raw = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        chunk1.len(),
        std::str::from_utf8(chunk1).unwrap(),
        chunk2.len(),
        std::str::from_utf8(chunk2).unwrap()
    );

    let res = parse_http_response(raw.as_bytes(), 100.0);
    assert!(res.is_complete);
    let resp = res.response.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, Some(serde_json::Value::String("Hello World!".to_string())));
}

#[test]
fn test_parse_response_partial_waits_for_data() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort body";
    let res = parse_http_response(raw, 100.0);
    assert!(!res.is_complete);
    assert_eq!(res.bytes_consumed, 0);
    assert!(res.response.is_none());
}

#[test]
fn test_parse_response_malformed_and_empty() {
    let empty_res = parse_http_response(b"", 100.0);
    assert!(!empty_res.is_complete);
    assert!(empty_res.response.is_none());

    let garbage = b"INVALID_GARBAGE_PAYLOAD\r\nHeader: value\r\n\r\n";
    let garb_res = parse_http_response(garbage, 100.0);
    assert!(!garb_res.is_complete);
    assert!(garb_res.error.is_some());
}

#[test]
fn test_stream_reassembler_matching_and_latency() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.5:45000->10.0.0.1:8080";

    let req_raw = b"GET /api/orders/1002 HTTP/1.1\r\nHost: api.crapi.local\r\n\r\n";
    let recs_in = reassembler.feed_raw(conn_id, 100.000, TrafficDirection::Ingress, req_raw);
    assert!(recs_in.is_empty());

    let resp_body = r#"{"id": 1002, "item": "Keyboard"}"#;
    let resp_raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        resp_body.len(),
        resp_body
    );
    let recs_out = reassembler.feed_raw(conn_id, 100.025, TrafficDirection::Egress, resp_raw.as_bytes());

    assert_eq!(recs_out.len(), 1);
    let record = &recs_out[0];
    assert_eq!(record.method, "GET");
    assert_eq!(record.path, "/api/orders/1002");
    assert_eq!(record.status, 200);
    assert_eq!(record.latency_ms, 25.0);
    assert_eq!(record.src_ip, "10.0.0.5");
    assert!(record.ok());
    assert_eq!(record.resp_body.as_ref().unwrap()["item"], "Keyboard");
}

#[test]
fn test_stream_reassembler_pipelined_matching() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.1.10:50000->192.168.1.1:443";

    let req1 = b"GET /item/1 HTTP/1.1\r\nHost: test\r\n\r\n";
    let req2 = b"GET /item/2 HTTP/1.1\r\nHost: test\r\n\r\n";
    reassembler.feed_raw(conn_id, 10.0, TrafficDirection::Ingress, req1);
    reassembler.feed_raw(conn_id, 10.01, TrafficDirection::Ingress, req2);

    let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfirst1";
    let resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsecond2";

    let records1 = reassembler.feed_raw(conn_id, 10.03, TrafficDirection::Egress, resp1);
    assert_eq!(records1.len(), 1);
    assert_eq!(records1[0].path, "/item/1");
    assert_eq!(records1[0].latency_ms, 30.0);

    let records2 = reassembler.feed_raw(conn_id, 10.06, TrafficDirection::Egress, resp2);
    assert_eq!(records2.len(), 1);
    assert_eq!(records2[0].path, "/item/2");
    assert_eq!(records2[0].latency_ms, 50.0);
}

#[test]
fn test_stream_reassembler_auth_and_record_conformance() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.10.10.5:33000->10.10.10.1:80";

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiAidXNlcl85OSIsICJyb2xlIjogImFkbWluIn0.signature";
    let req = format!(
        "POST /api/admin/delete HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n",
        token
    );
    reassembler.feed_raw(conn_id, 50.0, TrafficDirection::Ingress, req.as_bytes());

    let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
    let records = reassembler.feed_raw(conn_id, 50.012, TrafficDirection::Egress, resp);

    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.user, "user_99");
    assert_eq!(rec.role, "admin");
    assert_eq!(rec.method, "POST");
    assert_eq!(rec.path, "/api/admin/delete");
    assert_eq!(rec.status, 204);
    assert_eq!(rec.latency_ms, 12.0);
}

// ---------------------------------------------------------
// Day 4 Hardening, Limits, Timeouts & Edge Case Tests
// ---------------------------------------------------------

#[test]
fn test_chunk_extension_parsing_and_parameters() {
    let raw = b"5;ext=value;flag\r\nHello\r\n0\r\n\r\n";
    let (body, consumed, complete, err) = decode_chunked_body(raw);
    assert!(complete);
    assert!(err.is_none());
    assert_eq!(body.unwrap(), b"Hello");
    assert_eq!(consumed, raw.len());
}

#[test]
fn test_chunk_extension_rejects_control_characters() {
    let raw = b"5;ext=\x01bad\r\nHello\r\n0\r\n\r\n";
    let (_body, _consumed, _complete, err) = decode_chunked_body(raw);
    assert!(err.is_some());
    assert!(err.unwrap().contains("control character"));
}

#[test]
fn test_chunk_size_rejects_invalid_hex_and_signs() {
    // Leading plus
    let (b1, _, _, e1) = decode_chunked_body(b"+5\r\nHello\r\n0\r\n\r\n");
    assert!(b1.is_none());
    assert!(e1.is_some());

    // 0x prefix
    let (b2, _, _, e2) = decode_chunked_body(b"0x5\r\nHello\r\n0\r\n\r\n");
    assert!(b2.is_none());
    assert!(e2.is_some());

    // Non-hex
    let (b3, _, _, e3) = decode_chunked_body(b"ZZ\r\nHello\r\n0\r\n\r\n");
    assert!(b3.is_none());
    assert!(e3.is_some());
}

#[test]
fn test_invalid_bare_cr_rejected() {
    let raw = b"GET /api/test HTTP/1.1\rHost: crapi.local\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "10.0.0.1", 50000, "10.0.0.2", 80);
    assert!(!res.is_complete);
    assert!(res.error.is_some());
}

#[test]
fn test_parser_limits_max_header_size_enforced() {
    let limits = ParserLimits::default().with_max_header_size(100);
    let mut large_headers = "GET / HTTP/1.1\r\n".to_string();
    for i in 0..10 {
        large_headers.push_str(&format!("X-Header-{}: value-very-long-payload\r\n", i));
    }
    large_headers.push_str("\r\n");

    let res = parse_http_request_with_limits(
        large_headers.as_bytes(),
        100.0,
        "10.0.0.1",
        1234,
        "10.0.0.2",
        80,
        &limits,
    );
    assert!(!res.is_complete);
    assert!(res.error.is_some());
    assert!(res.error.unwrap().contains("exceeds maximum allowed limit"));
}

#[test]
fn test_parser_limits_max_body_size_enforced() {
    let limits = ParserLimits::default().with_max_body_size(50);
    let raw = b"POST /upload HTTP/1.1\r\nContent-Length: 500\r\n\r\n";
    let res = parse_http_request_with_limits(raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res.is_complete);
    assert!(res.error.is_some());
    assert!(res.error.unwrap().contains("exceeds maximum allowed body limit"));
}

#[test]
fn test_parser_limits_max_headers_count_enforced() {
    let limits = ParserLimits::default().with_max_headers_count(3);
    let raw = b"GET / HTTP/1.1\r\nH1: 1\r\nH2: 2\r\nH3: 3\r\nH4: 4\r\n\r\n";
    let res = parse_http_request_with_limits(raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res.is_complete);
    assert!(res.error.is_some());
    assert!(res.error.unwrap().contains("Header count exceeds maximum"));
}

#[test]
fn test_parser_limits_max_chunk_size_enforced() {
    let limits = ParserLimits::default().with_max_chunk_size(10);
    let raw = b"20\r\n12345678901234567890123456789012\r\n0\r\n\r\n";
    let (_, _, complete, err) = decode_chunked_body_with_limits(raw, &limits);
    assert!(!complete);
    assert!(err.is_some());
    assert!(err.unwrap().contains("Chunk size 32 exceeds limit 10"));
}

#[test]
fn test_stream_reassembler_idle_timeout_cleanup() {
    let mut reassembler = StreamReassembler::with_timeout(30.0);
    let conn1 = "10.0.0.1:1000->10.0.0.2:80";
    let conn2 = "10.0.0.3:2000->10.0.0.2:80";

    // Activity on conn1 at ts = 100.0
    reassembler.feed_raw(conn1, 100.0, TrafficDirection::Ingress, b"GET /partial ");
    // Activity on conn2 at ts = 120.0
    reassembler.feed_raw(conn2, 120.0, TrafficDirection::Ingress, b"GET /other ");

    assert_eq!(reassembler.active_connections().len(), 2);

    // Sweep at ts = 140.0: conn1 elapsed is 40s (>30s), conn2 elapsed is 20s (<=30s)
    let evicted = reassembler.sweep_idle_connections(140.0);
    assert_eq!(evicted, 1);
    assert_eq!(reassembler.active_connections().len(), 1);
}

#[test]
fn test_stream_reassembler_orphan_response_safe_emission() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.1.50:60000->192.168.1.1:8080";

    // Only response arrives without any prior request fragment
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"ok\": \"alone\"}";
    let records = reassembler.feed_raw(conn_id, 200.05, TrafficDirection::Egress, resp);

    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.method, "UNKNOWN");
    assert_eq!(rec.path, "");
    assert_eq!(rec.status, 200);
    assert_eq!(rec.latency_ms, 0.0);
    assert_eq!(rec.user, "anonymous");
    assert_eq!(rec.role, "user");
    assert_eq!(rec.resp_body.as_ref().unwrap()["ok"], "alone");
    assert_eq!(reassembler.unmatched_responses_count, 1);
}

#[test]
fn test_stream_reassembler_recovers_after_malformed_traffic() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "172.16.0.5:40000->172.16.0.1:80";

    // Feed malformed garbage line
    let garbage = b"GARBAGE_NOISE_WITHOUT_HTTP_METHOD\r\n";
    reassembler.feed_raw(conn_id, 300.0, TrafficDirection::Ingress, garbage);

    // Feed valid request on the same stream
    let valid_req = b"GET /api/recovered HTTP/1.1\r\nHost: test.local\r\n\r\n";
    reassembler.feed_raw(conn_id, 300.01, TrafficDirection::Ingress, valid_req);

    // Feed response
    let valid_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let records = reassembler.feed_raw(conn_id, 300.03, TrafficDirection::Egress, valid_resp);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, "/api/recovered");
    assert_eq!(records[0].status, 200);
}

// ---------------------------------------------------------
// Day 5 Query Parameter Parsing & URL Decoding Tests
// ---------------------------------------------------------

#[test]
fn test_query_param_basic_extraction() {
    let raw = b"GET /api/orders?status=active&limit=10 HTTP/1.1\r\nHost: api.crapi.local\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "10.0.0.1", 50000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();

    // Raw URI preserved
    assert_eq!(req.path, "/api/orders?status=active&limit=10");
    assert_eq!(req.raw_path, "/api/orders?status=active&limit=10");
    assert_eq!(req.base_path(), "/api/orders");

    // Query parameters extracted
    assert_eq!(req.get_query_param("status"), Some("active"));
    assert_eq!(req.get_query_param("limit"), Some("10"));
    assert_eq!(req.get_query_param("nonexistent"), None);
}

#[test]
fn test_query_param_plus_handling() {
    let raw = b"GET /search?query=hello+world&author=jane+doe HTTP/1.1\r\nHost: test\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "10.0.0.1", 50000, "10.0.0.2", 80);
    let req = res.request.unwrap();

    assert_eq!(req.get_query_param("query"), Some("hello world"));
    assert_eq!(req.get_query_param("author"), Some("jane doe"));
}

#[test]
fn test_query_param_percent_encoding() {
    let raw = b"GET /api/v1/user?email=alice%40example.com&tag=%23security&slash=%2Fa%2Fb HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    let req = res.request.unwrap();

    assert_eq!(req.get_query_param("email"), Some("alice@example.com"));
    assert_eq!(req.get_query_param("tag"), Some("#security"));
    assert_eq!(req.get_query_param("slash"), Some("/a/b"));
}

#[test]
fn test_query_param_repeated_keys_without_loss() {
    let raw = b"GET /filter?id=101&id=102&id=103&role=admin&role=auditor HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    let req = res.request.unwrap();

    let ids = req.get_query_params("id").unwrap();
    assert_eq!(ids, &vec!["101".to_string(), "102".to_string(), "103".to_string()]);

    let roles = req.get_query_params("role").unwrap();
    assert_eq!(roles, &vec!["admin".to_string(), "auditor".to_string()]);

    // get_query_param returns first value
    assert_eq!(req.get_query_param("id"), Some("101"));
}

#[test]
fn test_query_param_empty_and_missing_values() {
    let raw = b"GET /search?flag&empty=&valid=yes&&&also= HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    let req = res.request.unwrap();

    assert_eq!(req.get_query_param("flag"), Some(""));
    assert_eq!(req.get_query_param("empty"), Some(""));
    assert_eq!(req.get_query_param("valid"), Some("yes"));
    assert_eq!(req.get_query_param("also"), Some(""));
}

#[test]
fn test_query_param_malformed_percent_encoding_safe() {
    // Malformed sequences: %2 (incomplete), %ZZ (invalid hex), % (lone percent at end)
    let raw = b"GET /api?broken=%2&invalid=%ZZ&tail=% HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();

    // Handled safely without panicking or failing
    assert_eq!(req.get_query_param("broken"), Some("%2"));
    assert_eq!(req.get_query_param("invalid"), Some("%ZZ"));
    assert_eq!(req.get_query_param("tail"), Some("%"));
}

#[test]
fn test_query_param_empty_and_no_parameters() {
    // No query string
    let res1 = parse_http_request(b"GET /api/users HTTP/1.1\r\n\r\n", 100.0, "1.1.1.1", 1, "2.2.2.2", 2);
    let req1 = res1.request.unwrap();
    assert!(req1.query_params.is_empty());
    assert_eq!(req1.base_path(), "/api/users");

    // Empty query question mark
    let res2 = parse_http_request(b"GET /api/users? HTTP/1.1\r\n\r\n", 100.0, "1.1.1.1", 1, "2.2.2.2", 2);
    let req2 = res2.request.unwrap();
    assert!(req2.query_params.is_empty());
    assert_eq!(req2.base_path(), "/api/users");
}

#[test]
fn test_query_param_uri_with_fragment() {
    let raw = b"GET /docs/guide?section=intro&page=1#top HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 2);
    let req = res.request.unwrap();

    assert_eq!(req.base_path(), "/docs/guide");
    assert_eq!(req.get_query_param("section"), Some("intro"));
    assert_eq!(req.get_query_param("page"), Some("1"));
}

#[test]
fn test_query_param_utf8_percent_encoding() {
    // UTF-8 encoded emoji (%F0%9F%94%A5 -> 🔥)
    let raw = b"GET /search?q=%F0%9F%94%A5 HTTP/1.1\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 2);
    let req = res.request.unwrap();

    assert_eq!(req.get_query_param("q"), Some("🔥"));
}

#[test]
fn test_query_param_preserves_raw_uri_and_record_schema() {
    let mut reassembler = StreamReassembler::new();
    let conn = "10.0.0.1:5000->10.0.0.2:80";

    // Request with query params
    let req_bytes = b"GET /api/items?cat=tech&sort=asc HTTP/1.1\r\n\r\n";
    reassembler.feed_raw(conn, 10.0, TrafficDirection::Ingress, req_bytes);

    // Response
    let resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let records = reassembler.feed_raw(conn, 10.015, TrafficDirection::Egress, resp_bytes);

    assert_eq!(records.len(), 1);
    let rec = &records[0];

    // Record preserves the raw URI path
    assert_eq!(rec.path, "/api/items?cat=tech&sort=asc");
    assert_eq!(rec.status, 200);
    assert_eq!(rec.latency_ms, 15.0);
}

