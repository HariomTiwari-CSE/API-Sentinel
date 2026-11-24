//! Day 12 Regression and Parser Stability Test Suite.
//!
//! Validates the end-to-end HTTP/1.x parsing pipeline:
//! 1. Fragmented and chunked traffic handling
//! 2. Pipelined requests and responses with cursor-based buffer draining
//! 3. FIFO request-response matching and sub-millisecond latency calculation
//! 4. Caller identity and role extraction (JWT, headers, API keys, fallback)
//! 5. Downstream `Record` contract serialization and deserialization
//! 6. Day 11 performance optimizations preservation without data corruption
//! 7. Comprehensive regression suite for previously fixed security vulnerabilities:
//!    - RFC 7230 §3.2.4 whitespace-before-colon smuggling rejection
//!    - Conflicting framing headers (Transfer-Encoding vs Content-Length)
//!    - Conflicting duplicate Content-Length headers
//!    - Malformed chunk sizes, signed hex, and truncated chunks
//!    - Invalid JWTs, non-object JSON claims, and multibyte UTF-8 safety
//!    - `ParserLimits` enforcement (line length, header count, header size, body size)
//!    - Idle connection cleanup and resource eviction (`clean_idle_connections`)
//!    - Special status codes (1xx, 204, 304) body omission
//!    - Malformed/fuzz traffic safety without panics or infinite loops

use api_sentinel_parser::auth::{
    decode_base64_url, decode_jwt_payload, extract_identity_and_role, DEFAULT_ANONYMOUS_USER,
    DEFAULT_USER_ROLE,
};
use api_sentinel_parser::base::HttpParser;
use api_sentinel_parser::models::{
    ConnectionKey, ParsedHTTPRequest, ParsedHTTPResponse, ParserLimits, RawFragment, Record,
    TrafficDirection,
};
use api_sentinel_parser::reassembler::{
    canonical_connection_key, parse_endpoints, ConnectionState, StreamReassembler,
};
use api_sentinel_parser::request::{
    decode_body_content_with_limits, decode_chunked_body_with_limits, parse_http_request,
    parse_http_request_with_limits, RequestParseResult,
};
use api_sentinel_parser::response::{
    parse_http_response, parse_http_response_with_limits, ResponseParseResult,
};
use std::collections::HashMap;

// =========================================================================
// 1. Complete End-to-End Pipeline & Record Contract Verification
// =========================================================================

#[test]
fn test_e2e_pipeline_fragmented_request_chunked_response_and_record_json() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.1.100:54321->10.0.0.5:8080";

    // Valid JWT: header={"alg":"HS256","typ":"JWT"}, payload={"sub":"eng_alice","role":"admin"}
    // header b64: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    // payload b64: eyJzdWIiOiJlbmdfYWxpY2UiLCJyb2xlIjoiYWRtaW4ifQ
    let jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmdfYWxpY2UiLCJyb2xlIjoiYWRtaW4ifQ.signature123";

    let req_raw = format!(
        "POST /api/v2/deployments?env=prod&tier=gold HTTP/1.1\r\n\
         Host: api.internal.corp\r\n\
         Authorization: Bearer {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 32\r\n\r\n\
         {{\"service\":\"payments\",\"version\":\"2\"}}",
        jwt_token
    );

    // Feed request in small 11-byte fragments
    let req_bytes = req_raw.as_bytes();
    let mut offset = 0;
    while offset < req_bytes.len() {
        let chunk_end = (offset + 11).min(req_bytes.len());
        let records = reassembler.feed_fragment(&RawFragment {
            connection_id: conn_id.to_string(),
            ts: 100.0 + (offset as f64) * 0.001,
            direction: TrafficDirection::Ingress,
            payload: req_bytes[offset..chunk_end].to_vec(),
        });
        assert!(records.is_empty(), "No records before response");
        offset = chunk_end;
    }

    // Response with chunked encoding
    let resp_raw = "HTTP/1.1 201 Created\r\n\
                    Server: SentinelCore/1.0\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Type: application/json\r\n\r\n\
                    1a\r\n\
                    {\"deployment_id\":\"dep-789\"}\r\n\
                    0\r\n\r\n";

    // Feed response in two fragments
    let resp_bytes = resp_raw.as_bytes();
    let split_pos = 50;
    let r1 = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 100.100,
        direction: TrafficDirection::Egress,
        payload: resp_bytes[..split_pos].to_vec(),
    });
    assert!(r1.is_empty(), "Incomplete response should emit no records");

    let r2 = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 100.145,
        direction: TrafficDirection::Egress,
        payload: resp_bytes[split_pos..].to_vec(),
    });

    assert_eq!(
        r2.len(),
        1,
        "Exactly one matched transaction record emitted"
    );
    let record = &r2[0];

    // Validate fields
    assert_eq!(record.user, "eng_alice");
    assert_eq!(record.role, "admin");
    assert_eq!(record.method, "POST");
    assert_eq!(record.path, "/api/v2/deployments?env=prod&tier=gold");
    assert_eq!(record.status, 201);
    assert!(record.ok());
    assert_eq!(record.src_ip, "192.168.1.100");

    // Latency calculation: (100.145 - 100.0) * 1000 = 145.0 ms
    assert!((record.latency_ms - 145.0).abs() < 0.5);

    // Request body JSON
    let req_body = record.req_body.as_ref().expect("req_body present");
    assert_eq!(req_body["service"], "payments");
    assert_eq!(req_body["version"], "2");

    // Response body JSON
    let resp_body = record.resp_body.as_ref().expect("resp_body present");
    assert_eq!(resp_body["deployment_id"], "dep-789");

    // Serialization and deserialization contract
    let json_str = record.to_json().expect("Record serialized to JSON");
    let deserialized: Record = Record::from_json(&json_str).expect("Record deserialized");
    assert_eq!(*record, deserialized);
}

// =========================================================================
// 2. Day 11 Optimizations Preservation & Stability
// =========================================================================

#[test]
fn test_day11_pipelined_cursor_draining_preserves_multiple_transactions() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.1:50000->10.0.0.2:80";

    // Three pipelined requests in one TCP packet
    let pipelined_reqs = "GET /api/v1/users/1 HTTP/1.1\r\nHost: api.test\r\nX-User-Id: user_1\r\n\r\n\
                          POST /api/v1/items HTTP/1.1\r\nHost: api.test\r\nX-User-Id: user_2\r\nContent-Length: 13\r\n\r\n{\"name\":\"box\"}\
                          DELETE /api/v1/items/9 HTTP/1.1\r\nHost: api.test\r\nX-User-Id: user_3\r\n\r\n";

    let req_records = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 200.0,
        direction: TrafficDirection::Ingress,
        payload: pipelined_reqs.as_bytes().to_vec(),
    });
    assert!(req_records.is_empty());

    // Three pipelined responses in one TCP packet
    let pipelined_resps = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"id\":1,\"ok\":true}\
                           HTTP/1.1 201 Created\r\nContent-Length: 16\r\n\r\n{\"id\":9,\"ok\":true}\
                           HTTP/1.1 204 No Content\r\n\r\n";

    let resp_records = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 200.035,
        direction: TrafficDirection::Egress,
        payload: pipelined_resps.as_bytes().to_vec(),
    });

    assert_eq!(resp_records.len(), 3, "All three transactions matched FIFO");

    assert_eq!(resp_records[0].method, "GET");
    assert_eq!(resp_records[0].path, "/api/v1/users/1");
    assert_eq!(resp_records[0].user, "user_1");
    assert_eq!(resp_records[0].status, 200);

    assert_eq!(resp_records[1].method, "POST");
    assert_eq!(resp_records[1].path, "/api/v1/items");
    assert_eq!(resp_records[1].user, "user_2");
    assert_eq!(resp_records[1].status, 201);
    assert_eq!(resp_records[1].req_body.as_ref().unwrap()["name"], "box");

    assert_eq!(resp_records[2].method, "DELETE");
    assert_eq!(resp_records[2].path, "/api/v1/items/9");
    assert_eq!(resp_records[2].user, "user_3");
    assert_eq!(resp_records[2].status, 204);
    assert!(resp_records[2].resp_body.is_none());
}

#[test]
fn test_day11_lazy_line_parsing_parity_with_unusual_crlf_variants() {
    let limits = ParserLimits::default();

    // Mixed CRLF and LF lines
    let req_data = b"GET /status HTTP/1.1\nHost: example.com\r\nUser-Agent: Sentinel\n\n";
    let res =
        parse_http_request_with_limits(req_data, 1.0, "1.1.1.1", 1234, "2.2.2.2", 80, &limits);
    assert!(res.is_complete);
    let req = res.request.expect("Parsed request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/status");
    assert_eq!(req.headers.get("Host").unwrap(), "example.com");
    assert_eq!(req.headers.get("User-Agent").unwrap(), "Sentinel");
}

#[test]
fn test_day11_borrowed_header_lookup_case_insensitivity() {
    let mut headers = HashMap::new();
    headers.insert(
        "AuThOrIzAtIoN".to_string(),
        "Bearer invalid.jwt.sig".to_string(),
    );
    headers.insert("x-UsEr-Id".to_string(), "usr_fallback_99".to_string());
    headers.insert("X-rOlE".to_string(), "operator".to_string());

    // Because the JWT is invalid, it falls through to Tier 2 (x-user-id)
    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "usr_fallback_99");
    assert_eq!(role, "operator");
}

// =========================================================================
// 3. Security Regression: Header Parsing & Smuggling Defense
// =========================================================================

#[test]
fn test_security_rfc7230_whitespace_before_colon_rejected() {
    let limits = ParserLimits::default();

    // Space before colon in request header
    let bad_req_space = b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
    let res1 =
        parse_http_request_with_limits(bad_req_space, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res1.is_complete);
    assert!(res1.error.is_some());
    assert!(res1.error.unwrap().contains("Whitespace disallowed"));

    // Tab before colon in response header
    let bad_resp_tab = b"HTTP/1.1 200 OK\r\nServer\t: Apache\r\n\r\n";
    let res2 = parse_http_response_with_limits(bad_resp_tab, 1.0, &limits);
    assert!(!res2.is_complete);
    assert!(res2.error.is_some());
    assert!(res2.error.unwrap().contains("Whitespace disallowed"));
}

#[test]
fn test_security_missing_colon_and_empty_header_name() {
    let limits = ParserLimits::default();

    // Missing colon
    let missing_colon = b"GET / HTTP/1.1\r\nMalformedHeaderLineWithoutColon\r\n\r\n";
    let res1 =
        parse_http_request_with_limits(missing_colon, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res1.is_complete);
    assert!(res1.error.unwrap().contains("missing colon"));

    // Empty header name before colon
    let empty_name = b"GET / HTTP/1.1\r\n: value_without_name\r\n\r\n";
    let res2 = parse_http_request_with_limits(empty_name, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res2.is_complete);
    assert!(res2.error.unwrap().contains("Empty header name"));
}

#[test]
fn test_security_bare_cr_rejected() {
    let limits = ParserLimits::default();

    // Bare CR in request line
    let req_bare_cr = b"GET /path\r HTTP/1.1\r\nHost: test.com\r\n\r\n";
    let res1 =
        parse_http_request_with_limits(req_bare_cr, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res1.is_complete);
    assert!(res1.error.unwrap().contains("bare CR"));

    // Bare CR in response header
    let resp_bare_cr = b"HTTP/1.1 200 OK\r\nHeader: val\rue\r\n\r\n";
    let res2 = parse_http_response_with_limits(resp_bare_cr, 1.0, &limits);
    assert!(!res2.is_complete);
    assert!(res2.error.unwrap().contains("bare CR"));
}

// =========================================================================
// 4. Security Regression: Framing & Conflict Precedence
// =========================================================================

#[test]
fn test_security_chunked_overrides_content_length() {
    let limits = ParserLimits::default();

    // RFC 7230 §3.3.3: Transfer-Encoding chunked overrides Content-Length
    let req_data = b"POST /upload HTTP/1.1\r\n\
                     Host: example.com\r\n\
                     Content-Length: 9999\r\n\
                     Transfer-Encoding: chunked\r\n\r\n\
                     5\r\n\
                     hello\r\n\
                     0\r\n\r\n";

    let res = parse_http_request_with_limits(req_data, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(res.is_complete);
    let req = res.request.expect("Parsed request");
    assert_eq!(req.raw_body.as_deref(), Some(b"hello".as_slice()));
}

#[test]
fn test_security_conflicting_duplicate_content_length_rejected() {
    let limits = ParserLimits::default();

    // Conflicting duplicate Content-Length headers
    let req_data = b"POST /data HTTP/1.1\r\n\
                     Host: test.com\r\n\
                     Content-Length: 10\r\n\
                     Content-Length: 20\r\n\r\n\
                     1234567890";

    let res = parse_http_request_with_limits(req_data, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(!res.is_complete);
    assert!(res
        .error
        .unwrap()
        .contains("Conflicting duplicate Content-Length"));

    // Identical duplicate Content-Length headers are accepted safely
    let ok_dup = b"POST /data HTTP/1.1\r\n\
                   Host: test.com\r\n\
                   Content-Length: 5\r\n\
                   Content-Length: 5\r\n\r\n\
                   hello";

    let res_ok = parse_http_request_with_limits(ok_dup, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &limits);
    assert!(res_ok.is_complete);
}

// =========================================================================
// 5. Security Regression: Chunked Encoding Safety
// =========================================================================

#[test]
fn test_security_malformed_chunk_sizes_rejected() {
    let limits = ParserLimits::default();

    // Chunk size with 0x prefix
    let (body, _, complete, err) =
        decode_chunked_body_with_limits(b"0x05\r\nhello\r\n0\r\n\r\n", &limits);
    assert!(!complete);
    assert!(err.unwrap().contains("0x prefix"));

    // Chunk size with signed plus
    let (_, _, complete2, err2) =
        decode_chunked_body_with_limits(b"+5\r\nhello\r\n0\r\n\r\n", &limits);
    assert!(!complete2);
    assert!(err2.unwrap().contains("signed chunk size"));

    // Chunk size with invalid non-hex char
    let (_, _, complete3, err3) =
        decode_chunked_body_with_limits(b"5G\r\nhello\r\n0\r\n\r\n", &limits);
    assert!(!complete3);
    assert!(err3.unwrap().contains("non-hex character"));
}

#[test]
fn test_security_truncated_chunk_waits_for_data() {
    let limits = ParserLimits::default();

    // Chunk header specifies 10 bytes, but only 4 bytes are present
    let (body, consumed, complete, err) = decode_chunked_body_with_limits(b"a\r\n1234", &limits);
    assert!(!complete);
    assert_eq!(consumed, 0);
    assert!(body.is_none());
    assert!(
        err.is_none(),
        "Truncated body is not an error; waiting for packets"
    );
}

// =========================================================================
// 6. Security Regression: JWT & Identity Extraction Hardening
// =========================================================================

#[test]
fn test_security_multibyte_utf8_in_authorization_header_no_panic() {
    let mut headers = HashMap::new();
    // String starts with multibyte unicode emoji (4 bytes per emoji = 8 bytes total)
    headers.insert(
        "Authorization".to_string(),
        "🔒🔒🔒 secret_bearer_token".to_string(),
    );

    // Must safely parse without slicing panic at byte index 6
    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, DEFAULT_ANONYMOUS_USER);
    assert_eq!(role, DEFAULT_USER_ROLE);
}

#[test]
fn test_security_jwt_non_object_claims_rejected() {
    // Array payload: [1, 2, 3] -> b64: WzEsIDIsIDNd
    assert!(decode_jwt_payload("hdr.WzEsIDIsIDNd.sig").is_none());

    // String primitive payload: "hello_admin" -> b64: ImhlbGxvX2FkbWluIg
    assert!(decode_jwt_payload("hdr.ImhlbGxvX2FkbWluIg.sig").is_none());

    // Number primitive payload: 12345 -> b64: MTIzNDU
    assert!(decode_jwt_payload("hdr.MTIzNDU.sig").is_none());

    // Valid object with integer user_id fallback
    // {"user_id": 9876, "role": "auditor"} -> b64: eyJ1c2VyX2lkIjo5ODc2LCJyb2xlIjoiYXVkaXRvciJ9
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer hdr.eyJ1c2VyX2lkIjo5ODc2LCJyb2xlIjoiYXVkaXRvciJ9.sig".to_string(),
    );
    let (user, role) = extract_identity_and_role(&headers);
    assert_eq!(user, "9876");
    assert_eq!(role, "auditor");
}

#[test]
fn test_security_identity_tier_precedence() {
    let mut headers = HashMap::new();
    // Tier 1 JWT
    headers.insert(
        "Authorization".to_string(),
        "Bearer hdr.eyJzdWIiOiJqd3RfdXNlciIsInJvbGUiOiJqd3Rfcm9sZSJ9.sig".to_string(),
    );
    // Tier 2 User header
    headers.insert("X-User-Id".to_string(), "hdr_user".to_string());
    // Tier 3 API Key
    headers.insert("X-API-Key".to_string(), "app_sec_99998888".to_string());

    // Tier 1 wins
    let (u1, r1) = extract_identity_and_role(&headers);
    assert_eq!(u1, "jwt_user");
    assert_eq!(r1, "jwt_role");

    // Remove Tier 1 -> Tier 2 wins
    headers.remove("Authorization");
    let (u2, r2) = extract_identity_and_role(&headers);
    assert_eq!(u2, "hdr_user");

    // Remove Tier 2 -> Tier 3 wins (prefix format key_<prefix>)
    headers.remove("X-User-Id");
    let (u3, _) = extract_identity_and_role(&headers);
    assert_eq!(u3, "key_app_sec_");

    // Remove Tier 3 -> Tier 4 anonymous fallback
    headers.remove("X-API-Key");
    let (u4, r4) = extract_identity_and_role(&headers);
    assert_eq!(u4, DEFAULT_ANONYMOUS_USER);
    assert_eq!(r4, DEFAULT_USER_ROLE);
}

// =========================================================================
// 7. Security Regression: ParserLimits & DoS Protection
// =========================================================================

#[test]
fn test_security_parser_limits_enforced() {
    let strict_limits = ParserLimits::new()
        .with_max_header_size(128)
        .with_max_body_size(64)
        .with_max_headers_count(3)
        .with_max_line_length(32);

    // 1. Oversized request line (> 32 bytes)
    let long_line = b"GET /this/path/is/way/too/long/for/the/strict/limit HTTP/1.1\r\n\r\n";
    let r1 =
        parse_http_request_with_limits(long_line, 1.0, "1.1.1.1", 1, "2.2.2.2", 2, &strict_limits);
    assert!(!r1.is_complete);
    assert!(r1.error.unwrap().contains("maximum allowed length"));

    // 2. Excessive header count (> 3 headers)
    let too_many_headers = b"GET / HTTP/1.1\r\nH1: 1\r\nH2: 2\r\nH3: 3\r\nH4: 4\r\n\r\n";
    let r2 = parse_http_request_with_limits(
        too_many_headers,
        1.0,
        "1.1.1.1",
        1,
        "2.2.2.2",
        2,
        &strict_limits,
    );
    assert!(!r2.is_complete);
    assert!(r2.error.unwrap().contains("Header count exceeds"));

    // 3. Oversized body (> 64 bytes)
    let body_65 = vec![b'A'; 65];
    let oversized_body_req = format!(
        "POST /submit HTTP/1.1\r\nContent-Length: 65\r\n\r\n{}",
        std::str::from_utf8(&body_65).unwrap()
    );
    let r3 = parse_http_request_with_limits(
        oversized_body_req.as_bytes(),
        1.0,
        "1.1.1.1",
        1,
        "2.2.2.2",
        2,
        &strict_limits,
    );
    assert!(!r3.is_complete);
    assert!(r3
        .error
        .unwrap()
        .contains("exceeds maximum allowed body limit"));
}

// =========================================================================
// 8. Reassembler Stability: Idle Connection Cleanup & Sweep
// =========================================================================

#[test]
fn test_reassembler_idle_connection_sweep_and_clean_alias() {
    let mut reassembler = StreamReassembler::with_timeout(30.0);

    // Create 3 active connections at ts = 100.0
    for i in 1..=3 {
        let conn_id = format!("10.0.0.{}:1000->10.0.0.99:80", i);
        reassembler.feed_fragment(&RawFragment {
            connection_id: conn_id,
            ts: 100.0,
            direction: TrafficDirection::Ingress,
            payload: b"GET /ping HTTP/1.1\r\n\r\n".to_vec(),
        });
    }
    assert_eq!(reassembler.connections.len(), 3);

    // Update connection 1 activity at ts = 125.0
    reassembler.feed_fragment(&RawFragment {
        connection_id: "10.0.0.1:1000->10.0.0.99:80".to_string(),
        ts: 125.0,
        direction: TrafficDirection::Ingress,
        payload: b"".to_vec(),
    });

    // Sweep at ts = 140.0 (timeout = 30.0)
    // conn 1: inactive for 15s <= 30s -> retained
    // conn 2, 3: inactive for 40s > 30s -> evicted
    let evicted = reassembler.clean_idle_connections(140.0);
    assert_eq!(evicted, 2);
    assert_eq!(reassembler.connections.len(), 1);
    assert_eq!(reassembler.swept_connections_count, 2);
}

// =========================================================================
// 9. Special Status Codes: Body Omission (1xx, 204, 304)
// =========================================================================

#[test]
fn test_special_status_codes_body_omission_preserves_next_message() {
    let limits = ParserLimits::default();

    // 204 No Content with trailing data that belongs to the next response
    let data_204 = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let res1 = parse_http_response_with_limits(data_204, 1.0, &limits);
    assert!(res1.is_complete);
    let resp1 = res1.response.expect("204 parsed");
    assert_eq!(resp1.status, 204);
    assert!(resp1.body.is_none());

    // The remaining data parses as 200 OK
    let res2 = parse_http_response_with_limits(&data_204[res1.bytes_consumed..], 1.0, &limits);
    assert!(res2.is_complete);
    let resp2 = res2.response.expect("200 parsed");
    assert_eq!(resp2.status, 200);
}

// =========================================================================
// 10. Fault Tolerance: Fuzz & Corrupted Traffic
// =========================================================================

#[test]
fn test_fault_tolerance_fuzz_garbage_no_panics_or_infinite_loops() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.99.1:4000->192.168.99.2:80";

    let garbage_payloads: Vec<&[u8]> = vec![
        b"\x00\xff\xfe\xfd\x01\x02\x03",
        b"RANDOM_NON_HTTP_BINARY_DATA\x00\x00\r\n\r\n",
        b"GET\x00\x00HTTP/1.1\r\n\r\n",
        b"\r\n\r\n\r\n\r\n",
        b"HTTP/1.1 \r\n\r\n",
    ];

    for (idx, payload) in garbage_payloads.iter().enumerate() {
        let records = reassembler.feed_fragment(&RawFragment {
            connection_id: conn_id.to_string(),
            ts: 50.0 + (idx as f64),
            direction: TrafficDirection::Ingress,
            payload: payload.to_vec(),
        });
        // Verified: invalid garbage is drained/discarded safely without panicking
        assert!(records.is_empty());
    }

    // Now send a valid request on the same connection to verify recovery
    let ok_req = b"GET /recovery HTTP/1.1\r\nHost: test.com\r\n\r\n";
    reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 60.0,
        direction: TrafficDirection::Ingress,
        payload: ok_req.to_vec(),
    });

    let ok_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let records = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_id.to_string(),
        ts: 60.010,
        direction: TrafficDirection::Egress,
        payload: ok_resp.to_vec(),
    });

    assert_eq!(
        records.len(),
        1,
        "Reassembler successfully recovered from garbage"
    );
    assert_eq!(records[0].path, "/recovery");
    assert_eq!(records[0].status, 200);
}

// =========================================================================
// 11. Multi-Stream Concurrency Isolation
// =========================================================================

#[test]
fn test_concurrent_stream_isolation() {
    let mut reassembler = StreamReassembler::new();

    let conn_a = "10.0.0.1:1000->10.0.0.2:80";
    let conn_b = "10.0.0.3:2000->10.0.0.4:80";

    // Interleave requests and responses across conn A and conn B
    reassembler.feed_fragment(&RawFragment {
        connection_id: conn_a.to_string(),
        ts: 1.0,
        direction: TrafficDirection::Ingress,
        payload: b"GET /stream_a HTTP/1.1\r\nHost: a.com\r\nX-User-Id: alice\r\n\r\n".to_vec(),
    });

    reassembler.feed_fragment(&RawFragment {
        connection_id: conn_b.to_string(),
        ts: 1.1,
        direction: TrafficDirection::Ingress,
        payload: b"POST /stream_b HTTP/1.1\r\nHost: b.com\r\nX-User-Id: bob\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
    });

    // Response for B arrives first
    let rec_b = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_b.to_string(),
        ts: 1.2,
        direction: TrafficDirection::Egress,
        payload: b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".to_vec(),
    });
    assert_eq!(rec_b.len(), 1);
    assert_eq!(rec_b[0].user, "bob");
    assert_eq!(rec_b[0].path, "/stream_b");

    // Response for A arrives second
    let rec_a = reassembler.feed_fragment(&RawFragment {
        connection_id: conn_a.to_string(),
        ts: 1.3,
        direction: TrafficDirection::Egress,
        payload: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    });
    assert_eq!(rec_a.len(), 1);
    assert_eq!(rec_a[0].user, "alice");
    assert_eq!(rec_a[0].path, "/stream_a");
}
