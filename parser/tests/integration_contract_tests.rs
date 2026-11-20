//! Integration and Contract Verification Tests for Day 8: End-to-End Integration Contract Review.
//!
//! Verifies:
//! 1. Downstream `Record` schema compatibility with Detector (`Detector/model.py`) and Discovery.
//! 2. Binary / non-UTF-8 payload handling: verifies raw body byte preservation vs decoded text.
//! 3. Oversized payload & header rejection via `ParserLimits` without silent truncation or panics.
//! 4. Multi-connection concurrent stream stress testing (50 concurrent connections).
//! 5. Fragmented packet reassembly, pipelined requests, and FIFO latency calculation.
//! 6. Orphan response emission and pending request buffer bounding (`max_pending_requests`).
//! 7. Idle connection timeout sweep and memory cleanup.
//! 8. Identity extraction from JWT tokens (string/numeric claims) and API keys.

use api_sentinel_parser::{
    decode_body_content, decode_body_content_with_limits, extract_identity_and_role,
    parse_http_request, parse_http_request_with_limits, parse_http_response,
    parse_http_response_with_limits, ConnectionKey, ParserLimits, RawFragment, Record,
    StreamReassembler, TrafficDirection,
};
use std::collections::HashMap;

#[test]
fn test_record_contract_downstream_detector_compatibility() {
    // Construct Record with all fields populated
    let mut record = Record::new(
        1732000000.125,
        "operator_99",
        "POST",
        "/api/v1/resource/sync",
        201,
    );
    record.req_body = Some(serde_json::json!({
        "action": "sync",
        "targets": ["db1", "cache2"],
        "dry_run": false
    }));
    record.resp_body = Some(serde_json::json!({
        "status": "completed",
        "elapsed_ms": 12.4
    }));
    record.latency_ms = 18.75;
    record.src_ip = "192.168.10.45".to_string();
    record.role = "operator".to_string();

    // Verify .ok() property
    assert!(record.ok());

    // Verify error code not ok
    let mut err_record = record.clone();
    err_record.status = 403;
    assert!(!err_record.ok());

    // Test JSON Serialization / Deserialization
    let json_str = record
        .to_json()
        .expect("Failed to serialize Record to JSON");

    // Verify all keys expected by Python Record.from_dict() exist
    assert!(json_str.contains("\"ts\":"));
    assert!(json_str.contains("\"user\":"));
    assert!(json_str.contains("\"method\":"));
    assert!(json_str.contains("\"path\":"));
    assert!(json_str.contains("\"status\":"));
    assert!(json_str.contains("\"req_body\":"));
    assert!(json_str.contains("\"resp_body\":"));
    assert!(json_str.contains("\"latency_ms\":"));
    assert!(json_str.contains("\"src_ip\":"));
    assert!(json_str.contains("\"role\":"));

    let restored = Record::from_json(&json_str).expect("Failed to parse Record from JSON");
    assert_eq!(record, restored);

    // Verify null bodies (Option::None)
    let empty_record = Record::new(1732000001.0, "anon", "GET", "/ping", 200);
    let empty_json = empty_record
        .to_json()
        .expect("Failed to serialize empty Record");
    let restored_empty = Record::from_json(&empty_json).expect("Failed to parse empty Record");
    assert_eq!(restored_empty.req_body, None);
    assert_eq!(restored_empty.resp_body, None);
}

#[test]
fn test_raw_body_fidelity_non_utf8_binary() {
    // 10 bytes of binary payload with invalid UTF-8 sequences (PNG header + 0xFF)
    let binary_bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF];

    let mut request_raw: Vec<u8> = Vec::new();
    request_raw.extend_from_slice(b"POST /api/v1/upload/avatar HTTP/1.1\r\n");
    request_raw.extend_from_slice(b"Host: example.com\r\n");
    request_raw.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    request_raw
        .extend_from_slice(format!("Content-Length: {}\r\n\r\n", binary_bytes.len()).as_bytes());
    request_raw.extend_from_slice(&binary_bytes);

    let res = parse_http_request(&request_raw, 100.0, "10.0.0.1", 54321, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.expect("Expected request to parse");

    // 1. Verify exact raw bytes are preserved unaltered
    assert_eq!(req.raw_body_bytes(), Some(binary_bytes.as_slice()));
    assert_eq!(req.raw_body, Some(binary_bytes.clone()));

    // 2. Verify decoded body is safe lossy string and does NOT crash
    let body_val = req.body.expect("Expected decoded body");
    assert!(body_val.is_string());
    let lossy_str = body_val.as_str().unwrap();
    assert!(lossy_str.contains('\u{FFFD}')); // Unicode replacement character

    // 3. Confirm decoded text is distinct from original raw byte slice
    assert_ne!(lossy_str.as_bytes(), binary_bytes.as_slice());
}

#[test]
fn test_oversized_limits_rejection_no_silent_corruption() {
    let limits = ParserLimits::default()
        .with_max_body_size(100)
        .with_max_header_size(150)
        .with_max_line_length(80)
        .with_max_headers_count(5);

    // 1. Oversized body via Content-Length
    let mut huge_body_req = Vec::new();
    huge_body_req.extend_from_slice(
        b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 200\r\n\r\n",
    );
    huge_body_req.extend_from_slice(&vec![b'A'; 200]);

    let res_body = parse_http_request_with_limits(
        &huge_body_req,
        100.0,
        "1.1.1.1",
        1000,
        "2.2.2.2",
        80,
        &limits,
    );
    assert!(!res_body.is_complete);
    assert!(res_body.request.is_none());
    assert!(res_body
        .error
        .unwrap()
        .contains("exceeds maximum allowed body limit 100"));

    // 2. Oversized request-line
    let huge_line_req = format!(
        "GET /{} HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "a".repeat(120)
    );
    let res_line = parse_http_request_with_limits(
        huge_line_req.as_bytes(),
        100.0,
        "1.1.1.1",
        1000,
        "2.2.2.2",
        80,
        &limits,
    );
    assert!(!res_line.is_complete);
    assert!(res_line
        .error
        .unwrap()
        .contains("Request line exceeds maximum allowed length"));

    // 3. Oversized header count
    let mut many_headers_req = String::from("GET /api HTTP/1.1\r\nHost: example.com\r\n");
    for i in 1..=8 {
        many_headers_req.push_str(&format!("X-Custom-{}: val{}\r\n", i, i));
    }
    many_headers_req.push_str("\r\n");

    let res_headers = parse_http_request_with_limits(
        many_headers_req.as_bytes(),
        100.0,
        "1.1.1.1",
        1000,
        "2.2.2.2",
        80,
        &limits,
    );
    assert!(!res_headers.is_complete);
    assert!(res_headers
        .error
        .unwrap()
        .contains("Header count exceeds maximum allowed limit 5"));
}

#[test]
fn test_multi_connection_concurrent_stream_stress() {
    let mut reassembler = StreamReassembler::new();
    let num_connections = 50;

    // Send 50 concurrent requests from 50 distinct IPs
    for i in 1..=num_connections {
        let req_payload = format!(
            "GET /api/v1/user/{} HTTP/1.1\r\nHost: api.sentinel.internal\r\nX-User-Id: user_{}\r\n\r\n",
            i, i
        );
        let frag_req = RawFragment {
            ts: 100.0 + (i as f64) * 0.001,
            connection_id: format!("192.168.1.{}:{}->10.0.0.1:8080", i, 40000 + i),
            direction: TrafficDirection::Ingress,
            payload: req_payload.into_bytes(),
        };
        let out = reassembler.process_fragment(frag_req);
        assert!(out.is_empty(), "Request fragment should wait for response");
    }

    assert_eq!(reassembler.connections.len(), num_connections);

    // Send 50 matching responses in reverse order
    let mut emitted_records = Vec::new();
    for i in (1..=num_connections).rev() {
        let resp_payload = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{{\"user_id\": {}}}",
            i
        );
        let frag_resp = RawFragment {
            ts: 100.050 + (i as f64) * 0.001,
            connection_id: format!("10.0.0.1:8080->192.168.1.{}:{}", i, 40000 + i),
            direction: TrafficDirection::Egress,
            payload: resp_payload.into_bytes(),
        };
        let mut recs = reassembler.process_fragment(frag_resp);
        assert_eq!(
            recs.len(),
            1,
            "Each response should match exactly one request"
        );
        emitted_records.push(recs.remove(0));
    }

    assert_eq!(emitted_records.len(), num_connections);

    // Validate that each record preserved its specific user and path without cross-connection contamination
    for rec in emitted_records {
        let id_str = rec.path.trim_start_matches("/api/v1/user/");
        assert_eq!(rec.user, format!("user_{}", id_str));
        assert_eq!(rec.src_ip, format!("192.168.1.{}", id_str));
        assert_eq!(rec.status, 200);
        assert!(rec.latency_ms > 0.0);
    }
}

#[test]
fn test_fragmented_traffic_pipelined_fifo_latency() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.1.25:52110->10.0.0.1:8080";

    // 1. Send 3 pipelined requests in fragmented pieces
    let req1 = b"POST /api/orders HTTP/1.1\r\nHost: api.sentinel.internal\r\nContent-Length: 13\r\n\r\n{\"order\": 101}";
    let req2 = b"GET /api/status HTTP/1.1\r\nHost: api.sentinel.internal\r\n\r\n";
    let req3 = b"DELETE /api/cart HTTP/1.1\r\nHost: api.sentinel.internal\r\n\r\n";

    let mut combined_requests = Vec::new();
    combined_requests.extend_from_slice(req1);
    combined_requests.extend_from_slice(req2);
    combined_requests.extend_from_slice(req3);

    // Deliver combined requests in tiny 16-byte fragmented packets
    for chunk in combined_requests.chunks(16) {
        let frag = RawFragment {
            ts: 100.0,
            connection_id: conn_id.to_string(),
            direction: TrafficDirection::Ingress,
            payload: chunk.to_vec(),
        };
        let _ = reassembler.process_fragment(frag);
    }

    // Verify 3 pending requests queued in FIFO order
    let state = reassembler
        .connections
        .values()
        .next()
        .expect("Expected connection state");
    assert_eq!(state.pending_requests.len(), 3);
    assert_eq!(state.pending_requests[0].method, "POST");
    assert_eq!(state.pending_requests[1].method, "GET");
    assert_eq!(state.pending_requests[2].method, "DELETE");

    // 2. Deliver responses 1-by-1 with distinct timestamps
    let resp1 = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    let resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp3 = b"HTTP/1.1 204 No Content\r\n\r\n";

    let rec1 = reassembler.process_fragment(RawFragment {
        ts: 100.015,
        connection_id: "10.0.0.1:8080->10.0.1.25:52110".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp1.to_vec(),
    });
    assert_eq!(rec1.len(), 1);
    assert_eq!(rec1[0].method, "POST");
    assert_eq!(rec1[0].status, 201);
    assert!((rec1[0].latency_ms - 15.0).abs() < 1e-4);

    let rec2 = reassembler.process_fragment(RawFragment {
        ts: 100.030,
        connection_id: "10.0.0.1:8080->10.0.1.25:52110".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp2.to_vec(),
    });
    assert_eq!(rec2.len(), 1);
    assert_eq!(rec2[0].method, "GET");
    assert_eq!(rec2[0].status, 200);
    assert!((rec2[0].latency_ms - 30.0).abs() < 1e-4);

    let rec3 = reassembler.process_fragment(RawFragment {
        ts: 100.045,
        connection_id: "10.0.0.1:8080->10.0.1.25:52110".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp3.to_vec(),
    });
    assert_eq!(rec3.len(), 1);
    assert_eq!(rec3[0].method, "DELETE");
    assert_eq!(rec3[0].status, 204);
    assert!((rec3[0].latency_ms - 45.0).abs() < 1e-4);
}

#[test]
fn test_unmatched_orphan_responses_and_requests_eviction() {
    let mut reassembler = StreamReassembler::new();

    // 1. Orphan Response (no preceding request)
    let orphan_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\nGateway Timeout";
    let frag_orphan = RawFragment {
        ts: 100.0,
        connection_id: "10.0.0.1:8080->10.0.2.1:44556".to_string(),
        direction: TrafficDirection::Egress,
        payload: orphan_resp.to_vec(),
    };
    let recs = reassembler.process_fragment(frag_orphan);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].method, "UNKNOWN");
    assert_eq!(recs[0].status, 502);
    assert_eq!(recs[0].req_body, None);
    assert_eq!(
        recs[0].resp_body,
        Some(serde_json::Value::String("Gateway Timeout".to_string()))
    );
    assert_eq!(recs[0].latency_ms, 0.0);
    assert_eq!(reassembler.unmatched_responses_count, 1);

    // 2. Buffer Bounding (max_pending_requests eviction)
    let bounded_limits = ParserLimits::default();
    let mut tight_reassembler = StreamReassembler::new();
    tight_reassembler.limits.max_pending_requests = 3;

    for i in 1..=5 {
        let req = format!("GET /item/{} HTTP/1.1\r\nHost: example.com\r\n\r\n", i);
        tight_reassembler.process_fragment(RawFragment {
            ts: 100.0 + (i as f64),
            connection_id: "10.0.0.5:12345->10.0.0.1:80".to_string(),
            direction: TrafficDirection::Ingress,
            payload: req.into_bytes(),
        });
    }

    let state = tight_reassembler.connections.values().next().unwrap();
    // Must be capped at 3, with items 1 and 2 evicted
    assert_eq!(state.pending_requests.len(), 3);
    assert_eq!(state.pending_requests[0].path, "/item/3");
    assert_eq!(state.pending_requests[1].path, "/item/4");
    assert_eq!(state.pending_requests[2].path, "/item/5");
}

#[test]
fn test_idle_timeout_sweep_memory_cleanup() {
    let mut reassembler = StreamReassembler::with_timeout(30.0); // 30 sec timeout

    // Create 3 active connections at ts = 100.0
    for i in 1..=3 {
        let req = format!("GET /ping HTTP/1.1\r\nHost: test.com\r\n\r\n");
        reassembler.process_fragment(RawFragment {
            ts: 100.0,
            connection_id: format!("10.0.0.{}:1000->10.0.0.1:80", i),
            direction: TrafficDirection::Ingress,
            payload: req.into_bytes(),
        });
    }
    assert_eq!(reassembler.connections.len(), 3);

    // Keep connection 2 alive at ts = 120.0
    reassembler.process_fragment(RawFragment {
        ts: 120.0,
        connection_id: "10.0.0.2:1000->10.0.0.1:80".to_string(),
        direction: TrafficDirection::Ingress,
        payload: b"GET /alive HTTP/1.1\r\nHost: test.com\r\n\r\n".to_vec(),
    });

    // Advance time to 135.0 (connection 1 & 3 are 35s old > 30s timeout, connection 2 is 15s old < 30s)
    let swept = reassembler.sweep_idle_connections(135.0);
    assert_eq!(swept, 2, "Connections 1 & 3 should be swept");
    assert_eq!(reassembler.connections.len(), 1);
    assert!(reassembler
        .connections
        .values()
        .next()
        .unwrap()
        .canonical_key
        .contains("10.0.0.2"));
}

#[test]
fn test_auth_extraction_jwt_bearer_and_api_keys() {
    // 1. JWT with string subject and role
    // Payload: {"sub": "alice_secops", "role": "admin"}
    // Base64URL: eyJzdWIiOiAiYWxpY2Vfc2Vjb3BzIiwgInJvbGUiOiAiYWRtaW4ifQ
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Bearer header.eyJzdWIiOiAiYWxpY2Vfc2Vjb3BzIiwgInJvbGUiOiAiYWRtaW4ifQ.signature"
            .to_string(),
    );
    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "alice_secops");
    assert_eq!(role, "admin");

    // 2. JWT with numeric subject and array scope
    // Payload: {"sub": 8812, "scope": ["auditor", "analyst"]}
    // Base64URL: eyJzdWIiOiA4ODEyLCAic2NvcGUiOiBbImF1ZGl0b3IiLCAiYW5hbHlzdCJdfQ
    let mut num_jwt_headers = HashMap::new();
    num_jwt_headers.insert(
        "Authorization".to_string(),
        "Bearer h.eyJzdWIiOiA4ODEyLCAic2NvcGUiOiBbImF1ZGl0b3IiLCAiYW5hbHlzdCJdfQ.s".to_string(),
    );
    let (num_user, num_role) = extract_identity_and_role(&num_jwt_headers);
    assert_eq!(num_user, "8812");
    assert_eq!(num_role, "auditor");

    // 3. API Key header
    let mut api_key_headers = HashMap::new();
    api_key_headers.insert("X-API-Key".to_string(), "live_sec_prod_99482".to_string());
    api_key_headers.insert("X-Role".to_string(), "service".to_string());
    let (api_user, api_role) = extract_identity_and_role(&api_key_headers);
    assert_eq!(api_user, "key_live_sec");
    assert_eq!(api_role, "service");

    // 4. Missing auth headers -> Anonymous fallback
    let empty_headers = HashMap::new();
    let (anon_user, anon_role) = extract_identity_and_role(&empty_headers);
    assert_eq!(anon_user, "anonymous");
    assert_eq!(anon_role, "user");
}
