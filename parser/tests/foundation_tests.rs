//! Unit tests for the API-Sentinel Rust HTTP Parser foundation and data contracts.

use std::collections::HashMap;
use std::str::FromStr;
use api_sentinel_parser::{
    extract_identity_and_role, parse_all_requests, parse_http_request, ConnectionKey,
    ConnectionState, HttpParser, ParsedHTTPRequest, ParsedHTTPResponse, RawFragment, Record,
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
    assert_eq!(fragment.direction, TrafficDirection.Ingress);
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

struct DummyParser {
    records: Vec<Record>,
}

impl HttpParser for DummyParser {
    fn feed_fragment(&mut self, _fragment: &RawFragment) -> Vec<Record> {
        self.records.clone()
    }

    fn reset(&mut self, _connection_id: Option<&str>) {}

    fn active_connections(&self) -> Vec<String> {
        vec!["conn_dummy".to_string()]
    }
}

#[test]
fn test_dummy_parser_trait() {
    let mut parser = DummyParser { records: Vec::new() };
    let records = parser.feed_raw("test_conn", 1731312000.0, TrafficDirection::Ingress, b"GET / HTTP/1.1\r\n\r\n");
    assert!(records.is_empty());
    assert_eq!(parser.active_connections(), vec!["conn_dummy".to_string()]);
}
