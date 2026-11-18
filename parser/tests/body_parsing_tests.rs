//! Unit and Integration Tests for Day 7: Advanced HTTP Request and Response Body Parsing.
//!
//! Verifies:
//! 1. JSON parsing: nested objects, arrays, null values, booleans, numbers, and strings.
//! 2. Malformed JSON handling: safe fallback to raw string without panicking.
//! 3. Content-Type support: application/json, application/problem+json, application/vnd.api+json.
//! 4. Form-urlencoded parsing: conversion to JSON Object, percent decoding, '+' to space, repeated keys.
//! 5. Plain text, HTML, and arbitrary text content preservation.
//! 6. Heuristic JSON detection for untyped or text/plain payloads.
//! 7. Non-UTF-8 / binary payload handling with safe lossy conversion.
//! 8. Empty and whitespace-only body handling (safely mapped to None).
//! 9. Enforcement of `ParserLimits::max_body_size` on requests, responses, and decoders.
//! 10. Raw body byte preservation via `raw_body_bytes()` on requests and responses.
//! 11. Schema compatibility with downstream `Record` serialization.
//! 12. End-to-end `StreamReassembler` transaction matching with parsed bodies.

use std::collections::HashMap;
use api_sentinel_parser::{
    decode_body_content, decode_body_content_with_limits, parse_form_urlencoded,
    parse_http_request, parse_http_request_with_limits, parse_http_response,
    parse_http_response_with_limits, ConnectionKey, ParserLimits, RawFragment, Record,
    StreamReassembler, TrafficDirection,
};

#[test]
fn test_json_body_nested_objects_and_arrays() {
    let payload = br#"POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 132

{"user": {"id": 101, "metadata": {"roles": ["admin", "analyst"], "verified": true}}, "score": 99.5, "extra": null, "name": "Alice"}"#;

    let res = parse_http_request(payload, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.expect("Expected parsed request");

    let body = req.body.expect("Expected body to be Some");
    assert!(body.is_object());
    assert_eq!(body["user"]["id"], 101);
    assert_eq!(body["user"]["metadata"]["roles"][0], "admin");
    assert_eq!(body["user"]["metadata"]["roles"][1], "analyst");
    assert_eq!(body["user"]["metadata"]["verified"], true);
    assert_eq!(body["score"], 99.5);
    assert!(body["extra"].is_null());
    assert_eq!(body["name"], "Alice");

    // Check raw_body_bytes
    assert!(req.raw_body_bytes().is_some());
    assert!(req.raw_body_bytes().unwrap().starts_with(b"{\"user\":"));
}

#[test]
fn test_json_body_primitives_null_bool_numbers() {
    let limits = ParserLimits::default();

    // 1. JSON null
    let val_null = decode_body_content_with_limits(b"null", "application/json", &limits);
    assert_eq!(val_null, Some(serde_json::Value::Null));

    // 2. JSON booleans
    let val_true = decode_body_content_with_limits(b"true", "application/json", &limits);
    assert_eq!(val_true, Some(serde_json::Value::Bool(true)));

    let val_false = decode_body_content_with_limits(b"false", "application/json", &limits);
    assert_eq!(val_false, Some(serde_json::Value::Bool(false)));

    // 3. JSON numbers
    let val_int = decode_body_content_with_limits(b"42", "application/json", &limits);
    assert_eq!(val_int, Some(serde_json::json!(42)));

    let val_float = decode_body_content_with_limits(b"-3.14159", "application/json", &limits);
    assert_eq!(val_float, Some(serde_json::json!(-3.14159)));

    // 4. JSON string
    let val_str = decode_body_content_with_limits(b"\"scalar-token-string\"", "application/json", &limits);
    assert_eq!(val_str, Some(serde_json::Value::String("scalar-token-string".to_string())));
}

#[test]
fn test_json_body_malformed_fallback_to_string() {
    let malformed = br#"POST /api/v1/orders HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 35

{"order_id": 998, "items": [1, 2, "#;

    let res = parse_http_request(malformed, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.expect("Expected request");

    // Must not panic, must preserve the exact raw string
    let body = req.body.expect("Expected body");
    assert!(body.is_string());
    assert_eq!(body.as_str().unwrap(), "{\"order_id\": 998, \"items\": [1, 2, ");
}

#[test]
fn test_json_vendor_and_problem_types() {
    let payload = br#"HTTP/1.1 400 Bad Request
Content-Type: application/problem+json; charset=utf-8
Content-Length: 79

{"type": "https://example.com/probs/bad-id", "title": "Invalid ID parameter"}"#;

    let res = parse_http_response(payload, 100.5);
    assert!(res.is_complete);
    let resp = res.response.expect("Expected response");

    let body = resp.body.expect("Expected body");
    assert!(body.is_object());
    assert_eq!(body["type"], "https://example.com/probs/bad-id");
    assert_eq!(body["title"], "Invalid ID parameter");

    // Vendor-specific JSON
    let vendor_payload = br#"HTTP/1.1 200 OK
Content-Type: application/vnd.api+json
Content-Length: 46

{"data": {"type": "articles", "id": "1001"}}"#;

    let v_res = parse_http_response(vendor_payload, 100.6);
    assert!(v_res.is_complete);
    let v_resp = v_res.response.expect("Expected response");
    assert_eq!(v_resp.body.unwrap()["data"]["id"], "1001");
}

#[test]
fn test_form_urlencoded_single_and_repeated_keys() {
    let payload = br#"POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 70

username=secadmin&role=auditor&role=operator&active=true&empty_val=&flag"#;

    let res = parse_http_request(payload, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.expect("Expected request");

    let body = req.body.expect("Expected body");
    assert!(body.is_object());
    assert_eq!(body["username"], "secadmin");
    assert_eq!(body["active"], "true");
    assert_eq!(body["empty_val"], "");
    assert_eq!(body["flag"], "");

    // Repeated keys must be represented as an array
    let roles = body["role"].as_array().expect("Expected role to be array");
    assert_eq!(roles.len(), 2);
    assert_eq!(roles[0], "auditor");
    assert_eq!(roles[1], "operator");
}

#[test]
fn test_form_urlencoded_percent_decoding_and_plus() {
    let form_str = "query=api+sentinel%20scanner&redirect_url=https%3A%2F%2Fexample.com%2Fcb%3Fv%3D1&user=john%2Bdoe";
    let val = parse_form_urlencoded(form_str);

    assert!(val.is_object());
    assert_eq!(val["query"], "api sentinel scanner");
    assert_eq!(val["redirect_url"], "https://example.com/cb?v=1");
    assert_eq!(val["user"], "john+doe");
}

#[test]
fn test_plain_text_and_html_body_preservation() {
    // 1. Plain text
    let text_req = br#"POST /logs HTTP/1.1
Host: example.com
Content-Type: text/plain; charset=utf-8
Content-Length: 32

Log line 1: system normal status"#;

    let res = parse_http_request(text_req, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert_eq!(
        req.body,
        Some(serde_json::Value::String("Log line 1: system normal status".to_string()))
    );

    // 2. HTML text
    let html_resp = br#"HTTP/1.1 404 Not Found
Content-Type: text/html
Content-Length: 38

<html><body>Page Not Found</body></html>"#;

    let resp_res = parse_http_response(html_resp, 100.1);
    assert!(resp_res.is_complete);
    let resp = resp_res.response.unwrap();
    assert_eq!(
        resp.body,
        Some(serde_json::Value::String("<html><body>Page Not Found</body></html>".to_string()))
    );
}

#[test]
fn test_untyped_heuristic_json_detection() {
    // Missing Content-Type header but body is JSON object
    let untyped_req = br#"POST /data HTTP/1.1
Host: example.com
Content-Length: 26

{"implicit": "json_value"}"#;

    let res = parse_http_request(untyped_req, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert!(req.body.is_some());
    assert_eq!(req.body.unwrap()["implicit"], "json_value");

    // Missing Content-Type header but body is JSON array
    let untyped_arr = br#"POST /batch HTTP/1.1
Host: example.com
Content-Length: 12

[10, 20, 30]"#;

    let arr_res = parse_http_request(untyped_arr, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(arr_res.is_complete);
    let arr_req = arr_res.request.unwrap();
    assert_eq!(arr_req.body.unwrap()[1], 20);
}

#[test]
fn test_invalid_utf8_binary_payloads_safety() {
    let binary_body: &[u8] = &[0x55, 0x73, 0x65, 0x72, 0xFF, 0xFE, 0x44, 0x61, 0x74, 0x61]; // "User\xFF\xFEData"
    let val = decode_body_content(binary_body, "application/octet-stream");

    assert!(val.is_some());
    let str_val = val.unwrap();
    assert!(str_val.is_string());
    let s = str_val.as_str().unwrap();
    assert!(s.contains("User"));
    assert!(s.contains("Data"));
    assert!(s.contains('\u{FFFD}')); // Lossy replacement character
}

#[test]
fn test_empty_and_whitespace_bodies() {
    // 1. Zero bytes
    assert_eq!(decode_body_content(&[], "application/json"), None);

    // 2. Whitespace only
    assert_eq!(decode_body_content(b"   \r\n\t  ", "application/json"), None);
    assert_eq!(decode_body_content(b" \n ", "text/plain"), None);

    // 3. HTTP Request with Content-Length: 0
    let req_zero = br#"POST /ping HTTP/1.1
Host: example.com
Content-Length: 0

"#;
    let res = parse_http_request(req_zero, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert_eq!(req.body, None);
    assert_eq!(req.raw_body_bytes(), None);
}

#[test]
fn test_parser_limits_max_body_size_enforcement() {
    let tight_limits = ParserLimits::default().with_max_body_size(64);

    // Request exceeding max_body_size
    let huge_req = br#"POST /upload HTTP/1.1
Host: example.com
Content-Length: 128

12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"#;

    let res = parse_http_request_with_limits(huge_req, 100.0, "10.0.0.1", 5000, "10.0.0.2", 80, &tight_limits);
    assert!(!res.is_complete);
    assert!(res.request.is_none());
    assert!(res.error.unwrap().contains("exceeds maximum allowed body limit 64"));

    // Response exceeding max_body_size
    let huge_resp = br#"HTTP/1.1 200 OK
Content-Length: 128

12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"#;

    let r_res = parse_http_response_with_limits(huge_resp, 100.0, &tight_limits);
    assert!(!r_res.is_complete);
    assert!(r_res.response.is_none());
    assert!(r_res.error.unwrap().contains("exceeds maximum allowed body limit 64"));

    // Direct decode_body_content_with_limits capping
    let raw = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let decoded = decode_body_content_with_limits(raw, "text/plain", &tight_limits);
    assert!(decoded.is_some());
    let s = decoded.unwrap();
    assert_eq!(s.as_str().unwrap().len(), 64);
}

#[test]
fn test_record_compatibility_with_downstream() {
    let mut record = Record::new(100.0, "alice", "POST", "/api/v1/checkout", 200);
    record.req_body = Some(serde_json::json!({
        "item_id": "item_441",
        "qty": 3,
        "discount_code": null,
        "gift": true
    }));
    record.resp_body = Some(serde_json::json!({
        "status": "confirmed",
        "order_id": 99201
    }));
    record.latency_ms = 14.5;
    record.src_ip = "192.168.1.50".to_string();
    record.role = "customer".to_string();

    // Verify JSON serialization / deserialization round-trip
    let serialized = serde_json::to_string(&record).expect("Serialization failed");
    assert!(serialized.contains("\"item_441\""));
    assert!(serialized.contains("\"confirmed\""));

    let deserialized: Record = serde_json::from_str(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized, record);
    assert_eq!(deserialized.req_body.unwrap()["item_id"], "item_441");
    assert_eq!(deserialized.resp_body.unwrap()["status"], "confirmed");
}

#[test]
fn test_stream_reassembler_end_to_end_body_matching() {
    let mut reassembler = StreamReassembler::new();

    let req_bytes = br#"POST /submit-form HTTP/1.1
Host: secure.app.internal
Authorization: Bearer mock.jwt.token
Content-Type: application/x-www-form-urlencoded
Content-Length: 39

action=register&user=tester01&team=blue"#;

    let resp_bytes = br#"HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 32

{"success": true, "user_id": 42}"#;

    let frag_req = RawFragment {
        ts: 100.0,
        connection_id: "10.0.0.5:54321->10.0.0.1:8080".to_string(),
        direction: TrafficDirection::Ingress,
        payload: req_bytes.to_vec(),
    };

    let frag_resp = RawFragment {
        ts: 100.035,
        connection_id: "10.0.0.1:8080->10.0.0.5:54321".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp_bytes.to_vec(),
    };

    let recs_req = reassembler.process_fragment(frag_req);
    assert!(recs_req.is_empty()); // Waiting for response

    let recs_resp = reassembler.process_fragment(frag_resp);
    assert_eq!(recs_resp.len(), 1);

    let rec = &recs_resp[0];
    assert_eq!(rec.method, "POST");
    assert_eq!(rec.path, "/submit-form");
    assert_eq!(rec.status, 201);
    assert!((rec.latency_ms - 35.0).abs() < 1e-4);

    // Verify request body form decoding
    let req_body = rec.req_body.as_ref().expect("Expected req_body");
    assert_eq!(req_body["action"], "register");
    assert_eq!(req_body["user"], "tester01");
    assert_eq!(req_body["team"], "blue");

    // Verify response body JSON decoding
    let resp_body = rec.resp_body.as_ref().expect("Expected resp_body");
    assert_eq!(resp_body["success"], true);
    assert_eq!(resp_body["user_id"], 42);
}
