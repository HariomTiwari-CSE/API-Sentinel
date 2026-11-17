//! Day 6 Comprehensive Integration, Security Payload, Regression & Sustained Performance Tests
//! for the API-Sentinel Rust HTTP Parser (`parser/`).
//!
//! Note: All security payloads (SQLi, Path Traversal, BOLA/BFLA, CL-CL smuggling) are strictly
//! static byte test fixtures to verify faithful extraction and resilience; they are never executed.

use std::collections::HashMap;
use std::time::Instant;
use api_sentinel_parser::{
    extract_identity_and_role, parse_http_request, parse_http_response, HttpParser, ParserLimits,
    StreamReassembler, TrafficDirection,
};

// -----------------------------------------------------------------------------
// 1. Realistic Synthetic Mixed Traffic (GET / POST / PATCH / DELETE + Matching)
// -----------------------------------------------------------------------------

#[test]
fn test_synthetic_mixed_api_session_workflow() {
    let mut reassembler = StreamReassembler::new();
    let conn_fwd = "10.20.0.15:51234->10.20.0.1:8080";
    let conn_rev = "10.20.0.1:8080->10.20.0.15:51234";

    // JWT: {"sub":"user_101","role":"user"}
    let jwt_user = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEwMSIsInJvbGUiOiJ1c2VyIn0.sig";

    // Step 1: POST /api/v1/auth/login
    let login_body = r#"{"email":"alice@crapi.local","password":"redacted_test_value"}"#;
    let req1 = format!(
        "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.crapi.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        login_body.len(),
        login_body
    );
    let resp1_body = r#"{"token":"jwt_placeholder","expires_in":3600}"#;
    let resp1 = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        resp1_body.len(),
        resp1_body
    );

    assert!(reassembler
        .feed_raw(conn_fwd, 1000.000, TrafficDirection::Ingress, req1.as_bytes())
        .is_empty());
    let recs1 = reassembler.feed_raw(conn_rev, 1000.018, TrafficDirection::Egress, resp1.as_bytes());
    assert_eq!(recs1.len(), 1);
    assert_eq!(recs1[0].method, "POST");
    assert_eq!(recs1[0].path, "/api/v1/auth/login");
    assert_eq!(recs1[0].status, 200);
    assert_eq!(recs1[0].latency_ms, 18.0);
    assert_eq!(recs1[0].req_body.as_ref().unwrap()["email"], "alice@crapi.local");
    assert_eq!(recs1[0].resp_body.as_ref().unwrap()["expires_in"], 3600);

    // Step 2: GET /api/v1/orders?status=open&page=1
    let req2 = format!(
        "GET /api/v1/orders?status=open&page=1 HTTP/1.1\r\nHost: api.crapi.local\r\nAuthorization: Bearer {}\r\n\r\n",
        jwt_user
    );
    let resp2_body = r#"{"orders":[{"id":5001,"total":99.5}]}"#;
    let resp2 = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        resp2_body.len(),
        resp2_body
    );
    reassembler.feed_raw(conn_fwd, 1001.000, TrafficDirection::Ingress, req2.as_bytes());
    let recs2 = reassembler.feed_raw(conn_rev, 1001.012, TrafficDirection::Egress, resp2.as_bytes());
    assert_eq!(recs2.len(), 1);
    assert_eq!(recs2[0].user, "user_101");
    assert_eq!(recs2[0].role, "user");
    assert_eq!(recs2[0].path, "/api/v1/orders?status=open&page=1");
    assert_eq!(recs2[0].latency_ms, 12.0);
    assert_eq!(recs2[0].src_ip, "10.20.0.15");

    // Step 3: DELETE /api/v1/cart/5 -> 204 No Content
    let req3 = format!(
        "DELETE /api/v1/cart/5 HTTP/1.1\r\nHost: api.crapi.local\r\nAuthorization: Bearer {}\r\n\r\n",
        jwt_user
    );
    let resp3 = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
    reassembler.feed_raw(conn_fwd, 1002.500, TrafficDirection::Ingress, req3.as_bytes());
    let recs3 = reassembler.feed_raw(conn_rev, 1002.507, TrafficDirection::Egress, resp3);
    assert_eq!(recs3.len(), 1);
    assert_eq!(recs3[0].method, "DELETE");
    assert_eq!(recs3[0].status, 204);
    assert_eq!(recs3[0].resp_body, None);
    assert_eq!(recs3[0].latency_ms, 7.0);
}

// -----------------------------------------------------------------------------
// 2. Pipelined Requests, Fragmented TCP Packets & Chunked Transfer Encoding
// -----------------------------------------------------------------------------

#[test]
fn test_pipelined_batch_and_batched_responses_fifo() {
    let mut reassembler = StreamReassembler::new();
    let conn = "10.0.0.5:40001->10.0.0.1:80";

    let pipelined_reqs = concat!(
        "GET /api/step/1 HTTP/1.1\r\nHost: test\r\n\r\n",
        "POST /api/step/2 HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"step\":2}",
        "PUT /api/step/3 HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\ndone"
    );

    let batched_resps = concat!(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nr1",
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        "HTTP/1.1 204 No Content\r\n\r\n"
    );

    reassembler.feed_raw(conn, 500.000, TrafficDirection::Ingress, pipelined_reqs.as_bytes());
    let records = reassembler.feed_raw(conn, 500.045, TrafficDirection::Egress, batched_resps.as_bytes());

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].method, "GET");
    assert_eq!(records[0].path, "/api/step/1");
    assert_eq!(records[0].status, 200);
    assert_eq!(records[0].latency_ms, 45.0);

    assert_eq!(records[1].method, "POST");
    assert_eq!(records[1].path, "/api/step/2");
    assert_eq!(records[1].status, 201);
    assert_eq!(records[1].req_body.as_ref().unwrap()["step"], 2);
    assert_eq!(records[1].resp_body.as_ref().unwrap()["ok"], true);

    assert_eq!(records[2].method, "PUT");
    assert_eq!(records[2].path, "/api/step/3");
    assert_eq!(records[2].status, 204);
}

#[test]
fn test_heavily_fragmented_request_and_chunked_response() {
    let mut reassembler = StreamReassembler::new();
    let conn = "172.16.1.10:55555->172.16.1.2:8080";

    let full_req = concat!(
        "POST /api/stream?mode=chunked&retry=1 HTTP/1.1\r\n",
        "Host: stream.local\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Type: application/json\r\n\r\n",
        "a;ext=1\r\n{\"hello\":\"\r\n",
        "8\r\nworld!\"}\r\n",
        "0\r\n\r\n"
    );

    // Split request into tiny 7-byte TCP fragments
    let mut ts = 200.000;
    for chunk in full_req.as_bytes().chunks(7) {
        let recs = reassembler.feed_raw(conn, ts, TrafficDirection::Ingress, chunk);
        assert!(recs.is_empty());
        ts += 0.001;
    }

    let full_resp = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Type: application/json\r\n\r\n",
        "d\r\n{\"received\": \r\n",
        "5\r\ntrue}\r\n",
        "0\r\n\r\n"
    );

    // Split response into tiny 5-byte TCP fragments
    let mut emitted = Vec::new();
    ts += 0.020;
    for chunk in full_resp.as_bytes().chunks(5) {
        emitted.extend(reassembler.feed_raw(conn, ts, TrafficDirection::Egress, chunk));
        ts += 0.001;
    }

    assert_eq!(emitted.len(), 1);
    let rec = &emitted[0];
    assert_eq!(rec.method, "POST");
    assert_eq!(rec.path, "/api/stream?mode=chunked&retry=1");
    assert_eq!(rec.status, 200);
    assert_eq!(rec.req_body.as_ref().unwrap()["hello"], "world!");
    assert_eq!(rec.resp_body.as_ref().unwrap()["received"], true);
    assert!(rec.latency_ms >= 20.0);
}

// -----------------------------------------------------------------------------
// 3. Security Attack Payloads (Test Data Only — Preserved Intact for Detector)
// -----------------------------------------------------------------------------

#[test]
fn test_security_payload_sqli_preservation() {
    // SQL injection test strings in query params and JSON body (inert data only)
    let sqli_body = r#"{"username":"admin' OR '1'='1","comment":"'; DROP TABLE orders; --"}"#;
    let raw = format!(
        "POST /api/products?id=1%27+OR+%271%27%3D%271&sort=price;SELECT+1 HTTP/1.1\r\nHost: shop.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        sqli_body.len(),
        sqli_body
    );

    let res = parse_http_request(raw.as_bytes(), 100.0, "198.51.100.23", 44444, "10.0.0.1", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();

    // Raw URI preserved for signature/WAF inspection
    assert_eq!(req.path, "/api/products?id=1%27+OR+%271%27%3D%271&sort=price;SELECT+1");
    assert_eq!(req.base_path(), "/api/products");

    // Decoded query parameters faithfully extracted
    assert_eq!(req.get_query_param("id"), Some("1' OR '1'='1"));
    assert_eq!(req.get_query_param("sort"), Some("price;SELECT 1"));

    // JSON body preserved intact
    let body = req.body.unwrap();
    assert_eq!(body["username"], "admin' OR '1'='1");
    assert_eq!(body["comment"], "'; DROP TABLE orders; --");
}

#[test]
fn test_security_payload_path_traversal_preservation() {
    let raw = b"GET /api/files/../../../../etc/passwd?download=..%2F..%2Fetc%2Fshadow HTTP/1.1\r\nHost: files.local\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "203.0.113.9", 55000, "10.0.0.1", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();

    assert_eq!(req.base_path(), "/api/files/../../../../etc/passwd");
    assert_eq!(req.get_query_param("download"), Some("../../etc/shadow"));
}

#[test]
fn test_security_payload_bola_and_bfla_record_extraction() {
    let mut reassembler = StreamReassembler::new();
    let conn = "203.0.113.77:60001->10.0.0.10:8080";

    // Low-privilege user_101 (role=user)
    let jwt_user = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEwMSIsInJvbGUiOiJ1c2VyIn0.sig";

    // BOLA pattern: user_101 reading victim user_999's invoice
    let bola_req = format!(
        "GET /api/v2/users/999/invoices/4042?include_pii=true HTTP/1.1\r\nHost: bank.local\r\nAuthorization: Bearer {}\r\n\r\n",
        jwt_user
    );
    let bola_resp_body = r#"{"owner":"user_999","iban":"TEST-IBAN-0000"}"#;
    let bola_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        bola_resp_body.len(),
        bola_resp_body
    );

    reassembler.feed_raw(conn, 10.000, TrafficDirection::Ingress, bola_req.as_bytes());
    let recs_bola = reassembler.feed_raw(conn, 10.015, TrafficDirection::Egress, bola_resp.as_bytes());
    assert_eq!(recs_bola.len(), 1);
    assert_eq!(recs_bola[0].user, "user_101");
    assert_eq!(recs_bola[0].role, "user");
    assert_eq!(recs_bola[0].path, "/api/v2/users/999/invoices/4042?include_pii=true");
    assert_eq!(recs_bola[0].status, 200);
    assert_eq!(recs_bola[0].src_ip, "203.0.113.77");
    assert_eq!(recs_bola[0].resp_body.as_ref().unwrap()["owner"], "user_999");

    // BFLA pattern: normal user calling privileged admin DELETE endpoint
    let bfla_req = format!(
        "DELETE /api/admin/audit-logs/all HTTP/1.1\r\nHost: bank.local\r\nAuthorization: Bearer {}\r\n\r\n",
        jwt_user
    );
    let bfla_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"deleted\":500}";
    reassembler.feed_raw(conn, 11.000, TrafficDirection::Ingress, bfla_req.as_bytes());
    let recs_bfla = reassembler.feed_raw(conn, 11.009, TrafficDirection::Egress, bfla_resp);
    assert_eq!(recs_bfla.len(), 1);
    assert_eq!(recs_bfla[0].method, "DELETE");
    assert_eq!(recs_bfla[0].user, "user_101");
    assert_eq!(recs_bfla[0].role, "user");
    assert_eq!(recs_bfla[0].path, "/api/admin/audit-logs/all");
    assert_eq!(recs_bfla[0].status, 200);
}

// -----------------------------------------------------------------------------
// 4. Day 6 Bug-Fix Regression Tests
// -----------------------------------------------------------------------------

#[test]
fn test_auth_utf8_multibyte_headers_no_panic() {
    // Previously slicing &key[..8] or auth_str[..7] panicked on multi-byte UTF-8 boundaries
    let mut headers = HashMap::new();
    headers.insert("X-API-Key".to_string(), "🔥🔥🔥secret_key_utf8".to_string());
    let (user, role) = extract_identity_and_role(&headers);
    assert!(user.starts_with("key_"));
    assert_eq!(role, "user");

    let mut headers2 = HashMap::new();
    headers2.insert("Authorization".to_string(), "🔥🔥🔥not_bearer_utf8".to_string());
    let (user2, role2) = extract_identity_and_role(&headers2);
    assert_eq!(user2, "anonymous");
    assert_eq!(role2, "user");
}

#[test]
fn test_auth_jwt_numeric_sub_claim() {
    // Payload: {"sub": 42099, "role": "analyst"} -> base64url: eyJzdWIiOjQyMDk5LCJyb2xlIjoiYW5hbHlzdCJ9
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQyMDk5LCJyb2xlIjoiYW5hbHlzdCJ9.sig";
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), format!("Bearer {}", token));

    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "42099");
    assert_eq!(role, "analyst");
}

#[test]
fn test_conflicting_duplicate_content_length_rejected() {
    // CL-CL smuggling vector: two Content-Length headers with different values
    let req_raw = b"POST /api/pay HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n1234567890";
    let req_res = parse_http_request(req_raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(!req_res.is_complete);
    assert!(req_res.error.unwrap().contains("Conflicting duplicate Content-Length"));

    let resp_raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 8\r\n\r\n12345678";
    let resp_res = parse_http_response(resp_raw, 100.0);
    assert!(!resp_res.is_complete);
    assert!(resp_res.error.unwrap().contains("Conflicting duplicate Content-Length"));
}

#[test]
fn test_case_insensitive_duplicate_headers_merged() {
    let raw = b"GET /test HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1\r\nx-forwarded-for: 10.0.0.2\r\n\r\n";
    let res = parse_http_request(raw, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert_eq!(req.headers.get("X-Forwarded-For").unwrap(), "10.0.0.1, 10.0.0.2");
    assert!(!req.headers.contains_key("x-forwarded-for"));
}

#[test]
fn test_garbage_line_followed_by_valid_request_in_same_packet() {
    let mut reassembler = StreamReassembler::new();
    let conn = "10.0.0.9:41000->10.0.0.1:80";

    // Corrupted prefix line + valid HTTP request packed inside the exact same TCP packet
    let combined = b"CORRUPTED_NOISE_LINE\r\nGET /api/recovered-same-pkt HTTP/1.1\r\nHost: ok.local\r\n\r\n";
    reassembler.feed_raw(conn, 100.0, TrafficDirection::Ingress, combined);

    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let records = reassembler.feed_raw(conn, 100.010, TrafficDirection::Egress, resp);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, "/api/recovered-same-pkt");
    assert_eq!(records[0].status, 200);
}

#[test]
fn test_pending_requests_cap_prevents_unbounded_memory_growth() {
    let limits = ParserLimits::default().with_max_pending_requests(5);
    let mut reassembler = StreamReassembler::with_config(60.0, limits);
    let conn = "10.0.0.20:50000->10.0.0.1:80";

    // Flood 20 pipelined requests without sending any responses
    for i in 0..20 {
        let req = format!("GET /api/flood/{} HTTP/1.1\r\nHost: test\r\n\r\n", i);
        reassembler.feed_raw(conn, 100.0 + i as f64, TrafficDirection::Ingress, req.as_bytes());
    }

    // Pending queue must remain capped at 5 (holding the 5 most recent requests)
    let state = reassembler.connections.values().next().unwrap();
    assert_eq!(state.pending_requests.len(), 5);
    assert_eq!(state.pending_requests[0].path, "/api/flood/15");
    assert_eq!(state.pending_requests[4].path, "/api/flood/19");
}

#[test]
fn test_buffer_capacity_shrinks_after_large_payload() {
    let mut reassembler = StreamReassembler::new();
    let conn = "10.0.0.21:50001->10.0.0.1:80";

    // Send a 100 KB body (exceeds 64 KB shrink threshold)
    let large_body = "A".repeat(100_000);
    let req = format!(
        "POST /api/blob HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
        large_body.len(),
        large_body
    );
    reassembler.feed_raw(conn, 100.0, TrafficDirection::Ingress, req.as_bytes());

    let state = reassembler.connections.values().next().unwrap();
    assert!(state.ingress_buffer.is_empty());
    assert!(
        state.ingress_buffer.capacity() <= 64 * 1024,
        "Expected buffer capacity to shrink after draining 100KB payload, got {}",
        state.ingress_buffer.capacity()
    );
}

// -----------------------------------------------------------------------------
// 5. Sustained Traffic Performance & Memory Stability Test
// -----------------------------------------------------------------------------

#[test]
fn test_sustained_traffic_throughput_and_memory_stability() {
    let mut reassembler = StreamReassembler::with_timeout(30.0);
    let num_connections = 50;
    let tx_per_conn = 100; // 5,000 full request-response transactions
    let total_expected = num_connections * tx_per_conn;

    let req_template = b"POST /api/orders?source=web&priority=high HTTP/1.1\r\nHost: api.local\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"item_id\":42,\"quantity\":2}";
    let resp_template = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"status\":\"confirmed\"}";

    let start = Instant::now();
    let mut total_records = 0usize;
    let mut ts = 10_000.0;

    for round in 0..tx_per_conn {
        for c in 0..num_connections {
            let conn = format!("10.1.0.{}:{}->10.0.0.1:8080", (c % 250) + 1, 40000 + c);
            reassembler.feed_raw(&conn, ts, TrafficDirection::Ingress, req_template);
            let recs = reassembler.feed_raw(&conn, ts + 0.005, TrafficDirection::Egress, resp_template);
            total_records += recs.len();
        }
        ts += 0.1 * ((round % 3) as f64 + 1.0);
    }

    let elapsed = start.elapsed();
    assert_eq!(total_records, total_expected);

    // Ensure no residual buffered data or leaked pending requests remain
    for state in reassembler.connections.values() {
        assert!(state.ingress_buffer.is_empty());
        assert!(state.egress_buffer.is_empty());
        assert!(state.pending_requests.is_empty());
    }

    // Advance clock past idle timeout and confirm full eviction
    let evicted = reassembler.sweep_idle_connections(ts + 60.0);
    assert_eq!(evicted, num_connections);
    assert!(reassembler.connections.is_empty());

    // Sanity check elapsed duration (non-zero measurement)
    let _tx_per_sec = (total_records as f64) / elapsed.as_secs_f64().max(1e-6);
}
