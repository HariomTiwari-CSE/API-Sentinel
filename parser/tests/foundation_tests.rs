//! Unit tests for the API-Sentinel Rust HTTP Parser foundation, data contracts, and Day 3 response parsing.

use std::collections::HashMap;
use std::str::FromStr;
use api_sentinel_parser::{
    extract_identity_and_role, parse_all_requests, parse_all_responses, parse_http_request,
    parse_http_response, ConnectionKey, ConnectionState, HttpParser, ParsedHTTPRequest,
    ParsedHTTPResponse, RawFragment, Record, StreamReassembler, TrafficDirection,
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
    // 204 must not consume body bytes even if extra payload follows or content-length is zero
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
    // Empty
    let empty_res = parse_http_response(b"", 100.0);
    assert!(!empty_res.is_complete);
    assert!(empty_res.response.is_none());

    // Non-HTTP garbage
    let garbage = b"INVALID_GARBAGE_PAYLOAD\r\nHeader: value\r\n\r\n";
    let garb_res = parse_http_response(garbage, 100.0);
    assert!(!garb_res.is_complete);
    assert!(garb_res.error.is_some());
}

#[test]
fn test_stream_reassembler_matching_and_latency() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.5:45000->10.0.0.1:8080";

    // 1. Ingress Request at ts = 100.000
    let req_raw = b"GET /api/orders/1002 HTTP/1.1\r\nHost: api.crapi.local\r\n\r\n";
    let recs_in = reassembler.feed_raw(conn_id, 100.000, TrafficDirection::Ingress, req_raw);
    assert!(recs_in.is_empty(), "Requests should be queued pending response");

    // 2. Egress Response at ts = 100.025 (25ms latency)
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

    // Send 2 pipelined requests
    let req1 = b"GET /item/1 HTTP/1.1\r\nHost: test\r\n\r\n";
    let req2 = b"GET /item/2 HTTP/1.1\r\nHost: test\r\n\r\n";
    reassembler.feed_raw(conn_id, 10.0, TrafficDirection::Ingress, req1);
    reassembler.feed_raw(conn_id, 10.01, TrafficDirection::Ingress, req2);

    // Send 2 responses
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

    // Request with JWT Bearer Token
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiAidXNlcl85OSIsICJyb2xlIjogImFkbWluIn0.signature";
    let req = format!(
        "POST /api/admin/delete HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n",
        token
    );
    reassembler.feed_raw(conn_id, 50.0, TrafficDirection::Ingress, req.as_bytes());

    // Response
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
