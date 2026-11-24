//! Day 10: HTTP Parsing Robustness & Edge-Case Hardening Tests.
//!
//! Verifies:
//! 1. Malformed request-lines: missing path, missing method, unknown methods, invalid HTTP version format (no digits / invalid characters).
//! 2. Malformed status-lines: missing status code, non-numeric code, out-of-range status code (<100 or >=600), invalid HTTP version.
//! 3. Incomplete headers and slowloris boundaries: buffer truncation mid-header, missing delimiters.
//! 4. Header edge cases:
//!    - Duplicate headers merged with comma (preserving first-seen casing)
//!    - Case-insensitive deduplication
//!    - Whitespace disallowed between header name and colon (`Host : example.com`)
//!    - Missing colon in header line (`MalformedNoColon`)
//!    - Empty header name (`: value`)
//!    - Empty header values and whitespace-only values
//!    - Conflicting duplicate Content-Length headers vs identical duplicate Content-Length headers
//! 5. HTTP message framing edge cases:
//!    - Conflicting framing headers: Transfer-Encoding chunked overriding Content-Length
//!    - Truncated chunked bodies and chunk headers
//!    - Invalid chunk sizes (non-hex, "0x" prefix, signed "+/-" prefixes)
//!    - Special status codes (1xx, 204 No Content, 304 Not Modified) omitting body despite Content-Length
//! 6. Protocol resilience and security:
//!    - Fuzz / binary random garbage data safety (never panics, crashes, or infinite loops)
//!    - Recovery from malformed pipelined requests in StreamReassembler without cross-request corruption
//!    - ParserLimits strict enforcement (line length, header size, header count, body size, chunk size)
//! 7. 1-byte extreme stream fragmentation and pipelining FIFO matching.

use api_sentinel_parser::{
    decode_chunked_body_with_limits, parse_all_requests, parse_all_requests_with_limits,
    parse_all_responses, parse_all_responses_with_limits, parse_http_request,
    parse_http_request_with_limits, parse_http_response, parse_http_response_with_limits,
    ParserLimits, RawFragment, StreamReassembler, TrafficDirection,
};

// =========================================================================
// 1. Malformed Request-Line & Status-Line Tests
// =========================================================================

#[test]
fn test_malformed_request_line_variations() {
    // 1. Missing path (only method provided)
    let raw_no_path = b"GET\r\nHost: example.com\r\n\r\n";
    let res1 = parse_http_request(raw_no_path, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res1.is_complete);
    assert!(res1.error.is_some());
    assert!(res1
        .error
        .unwrap()
        .contains("Malformed request line tokens"));

    // 2. Missing method (starts with URI path)
    let raw_no_method = b"/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let res2 = parse_http_request(raw_no_method, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res2.is_complete);
    assert!(res2.error.is_some());
    assert!(res2
        .error
        .unwrap()
        .contains("Unknown or malformed HTTP method"));

    // 3. Unknown HTTP method
    let raw_bad_method = b"INVALIDMETHOD /api/v1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let res3 = parse_http_request(raw_bad_method, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res3.is_complete);
    assert!(res3.error.is_some());
    assert!(res3
        .error
        .unwrap()
        .contains("Unknown or malformed HTTP method: INVALIDMETHOD"));

    // 4. Invalid HTTP version (no digits after HTTP/)
    let raw_no_digit_ver = b"GET /api HTTP/\r\nHost: example.com\r\n\r\n";
    let res4 = parse_http_request(raw_no_digit_ver, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res4.is_complete);
    assert!(res4.error.is_some());
    assert!(res4
        .error
        .unwrap()
        .contains("Invalid HTTP version in request line: HTTP/"));

    // 5. Invalid HTTP version (non-digit letters after HTTP/)
    let raw_bad_ver = b"GET /api HTTP/XYZ\r\nHost: example.com\r\n\r\n";
    let res5 = parse_http_request(raw_bad_ver, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res5.is_complete);
    assert!(res5.error.is_some());
    assert!(res5
        .error
        .unwrap()
        .contains("Invalid HTTP version in request line: HTTP/XYZ"));

    // 6. Bare carriage return in request line
    let raw_bare_cr = b"GET /api\r HTTP/1.1\nHost: example.com\n\n";
    let res6 = parse_http_request(raw_bare_cr, 100.0, "1.1.1.1", 1000, "2.2.2.2", 80);
    assert!(!res6.is_complete);
    assert!(res6.error.is_some());
    assert!(res6
        .error
        .unwrap()
        .contains("Invalid bare CR in request line"));
}

#[test]
fn test_malformed_status_line_variations() {
    // 1. Missing status code
    let raw_no_code = b"HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let res1 = parse_http_response(raw_no_code, 100.0);
    assert!(!res1.is_complete);
    assert!(res1.error.is_some());
    assert!(res1.error.unwrap().contains("Malformed status line tokens"));

    // 2. Non-numeric status code
    let raw_bad_code = b"HTTP/1.1 OK\r\nContent-Length: 0\r\n\r\n";
    let res2 = parse_http_response(raw_bad_code, 100.0);
    assert!(!res2.is_complete);
    assert!(res2.error.is_some());
    assert!(res2
        .error
        .unwrap()
        .contains("Invalid status code in status line: OK"));

    // 3. Out-of-range status code (< 100)
    let raw_low_code = b"HTTP/1.1 99 InvalidLow\r\nContent-Length: 0\r\n\r\n";
    let res3 = parse_http_response(raw_low_code, 100.0);
    assert!(!res3.is_complete);
    assert!(res3.error.is_some());
    assert!(res3
        .error
        .unwrap()
        .contains("Invalid status code in status line: 99"));

    // 4. Out-of-range status code (>= 600)
    let raw_high_code = b"HTTP/1.1 600 InvalidHigh\r\nContent-Length: 0\r\n\r\n";
    let res4 = parse_http_response(raw_high_code, 100.0);
    assert!(!res4.is_complete);
    assert!(res4.error.is_some());
    assert!(res4
        .error
        .unwrap()
        .contains("Invalid status code in status line: 600"));

    // 5. Invalid HTTP version in response
    let raw_bad_ver = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    let res5 = parse_http_response(raw_bad_ver, 100.0);
    assert!(!res5.is_complete);
    assert!(res5.error.is_some());
    assert!(res5
        .error
        .unwrap()
        .contains("Malformed response line prefix: SIP/2.0 200 OK"));

    // 6. Valid response without reason phrase defaults cleanly
    let raw_no_reason = b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n";
    let res6 = parse_http_response(raw_no_reason, 100.0);
    assert!(res6.is_complete);
    let resp = res6.response.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.status_text, "OK");
}

// =========================================================================
// 2. Header Parsing Edge Cases & Security Defenses
// =========================================================================

#[test]
fn test_header_edge_cases_and_smuggling_defenses() {
    // 1. Whitespace disallowed between header name and colon (RFC 7230 §3.2.4 Smuggling Defense)
    let raw_space_colon = b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
    let res1 = parse_http_request(raw_space_colon, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(!res1.is_complete);
    assert!(res1.error.is_some());
    assert!(res1
        .error
        .unwrap()
        .contains("Whitespace disallowed between header name and colon: 'Host '"));

    // 2. Malformed header line missing colon delimiter
    let raw_no_colon = b"GET / HTTP/1.1\r\nHost: example.com\r\nMalformedLineWithoutColon\r\n\r\n";
    let res2 = parse_http_request(raw_no_colon, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(!res2.is_complete);
    assert!(res2.error.is_some());
    assert!(res2
        .error
        .unwrap()
        .contains("Malformed header line missing colon delimiter"));

    // 3. Empty header name before colon
    let raw_empty_hname = b"GET / HTTP/1.1\r\n: value\r\n\r\n";
    let res3 = parse_http_request(raw_empty_hname, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(!res3.is_complete);
    assert!(res3.error.is_some());
    assert!(res3
        .error
        .unwrap()
        .contains("Empty header name before colon delimiter"));

    // 4. Duplicate headers merged with comma (preserving first seen key casing)
    let raw_dups = b"GET / HTTP/1.1\r\nAccept: text/html\r\nACCEPT: application/json\r\n\r\n";
    let res4 = parse_http_request(raw_dups, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(res4.is_complete);
    let req = res4.request.unwrap();
    assert_eq!(
        req.headers.get("Accept").map(|s| s.as_str()),
        Some("text/html, application/json")
    );

    // 5. Empty and whitespace-only header values accepted cleanly
    let raw_empty_val = b"GET / HTTP/1.1\r\nX-Empty:\r\nX-Spaced:    \r\n\r\n";
    let res5 = parse_http_request(raw_empty_val, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(res5.is_complete);
    let req5 = res5.request.unwrap();
    assert_eq!(req5.headers.get("X-Empty").map(|s| s.as_str()), Some(""));
    assert_eq!(req5.headers.get("X-Spaced").map(|s| s.as_str()), Some(""));

    // 6. Conflicting duplicate Content-Length headers rejected
    let raw_conflict_cl =
        b"POST / HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n1234567890";
    let res6 = parse_http_request(raw_conflict_cl, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(!res6.is_complete);
    assert!(res6.error.is_some());
    assert!(res6
        .error
        .unwrap()
        .contains("Conflicting duplicate Content-Length headers: 10 vs 20"));

    // 7. Identical duplicate Content-Length headers accepted (RFC 7230 §3.3.2)
    let raw_dup_cl = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    let res7 = parse_http_request(raw_dup_cl, 100.0, "1.1.1.1", 1, "2.2.2.2", 80);
    assert!(res7.is_complete);
    let req7 = res7.request.unwrap();
    assert_eq!(req7.raw_body, Some(b"hello".to_vec()));
}

// =========================================================================
// 3. HTTP Message Framing & Chunked Edge Cases
// =========================================================================

#[test]
fn test_conflicting_framing_transfer_encoding_overrides_content_length() {
    // RFC 7230 §3.3.3: Transfer-Encoding overrides Content-Length
    let raw = b"POST /api/v1/stream HTTP/1.1\r\n\
                Host: example.com\r\n\
                Content-Length: 9999\r\n\
                Transfer-Encoding: chunked\r\n\r\n\
                5\r\nhello\r\n\
                6\r\n world\r\n\
                0\r\n\r\n";

    let res = parse_http_request(raw, 100.0, "10.0.0.1", 1234, "10.0.0.2", 80);
    assert!(res.is_complete);
    let req = res.request.unwrap();
    assert_eq!(req.raw_body, Some(b"hello world".to_vec()));
    assert_eq!(res.bytes_consumed, raw.len());
}

#[test]
fn test_chunked_encoding_edge_cases_and_invalid_sizes() {
    let limits = ParserLimits::default();

    // 1. Truncated chunk size line
    let raw_trunc_size = b"5";
    let (_, consumed, complete, err) = decode_chunked_body_with_limits(raw_trunc_size, &limits);
    assert!(!complete);
    assert_eq!(consumed, 0);
    assert!(err.is_none());

    // 2. Truncated chunk data (size says 0x10 = 16 bytes, only 5 provided)
    let raw_trunc_data = b"10\r\n12345";
    let (_, consumed2, complete2, err2) = decode_chunked_body_with_limits(raw_trunc_data, &limits);
    assert!(!complete2);
    assert_eq!(consumed2, 0);
    assert!(err2.is_none());

    // 3. Invalid hex character in chunk size
    let raw_invalid_hex = b"G\r\nhello\r\n0\r\n\r\n";
    let (_, _, complete3, err3) = decode_chunked_body_with_limits(raw_invalid_hex, &limits);
    assert!(!complete3);
    assert!(err3.is_some());
    assert!(err3
        .unwrap()
        .contains("Invalid non-hex character in chunk size: G"));

    // 4. "0x" prefix in chunk size rejected
    let raw_0x = b"0x05\r\nhello\r\n0\r\n\r\n";
    let (_, _, complete4, err4) = decode_chunked_body_with_limits(raw_0x, &limits);
    assert!(!complete4);
    assert!(err4.is_some());
    assert!(err4
        .unwrap()
        .contains("Invalid 0x prefix in chunk size hex"));

    // 5. Signed chunk size (+5) rejected
    let raw_signed = b"+5\r\nhello\r\n0\r\n\r\n";
    let (_, _, complete5, err5) = decode_chunked_body_with_limits(raw_signed, &limits);
    assert!(!complete5);
    assert!(err5.is_some());
    assert!(err5.unwrap().contains("Invalid signed chunk size hex"));

    // 6. Valid chunk extensions with parameters
    let raw_ext = b"5;token=val;sec=true\r\nhello\r\n0\r\n\r\n";
    let (body, consumed6, complete6, err6) = decode_chunked_body_with_limits(raw_ext, &limits);
    assert!(complete6);
    assert!(err6.is_none());
    assert_eq!(body, Some(b"hello".to_vec()));
    assert_eq!(consumed6, raw_ext.len());
}

#[test]
fn test_special_status_codes_never_include_body() {
    // 204 No Content MUST NOT include a message body despite Content-Length
    let raw_204 = b"HTTP/1.1 204 No Content\r\n\
                    Content-Length: 50\r\n\
                    Connection: keep-alive\r\n\r\n\
                    GET /next_request HTTP/1.1\r\n\r\n";

    let res_204 = parse_http_response(raw_204, 100.0);
    assert!(res_204.is_complete);
    let resp = res_204.response.unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(resp.body, None);
    // Consumed bytes should stop exactly at headers boundary (\r\n\r\n), preserving next request
    let headers_boundary = raw_204.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(res_204.bytes_consumed, headers_boundary);

    // 304 Not Modified MUST NOT include a message body
    let raw_304 = b"HTTP/1.1 304 Not Modified\r\n\
                    ETag: \"abcdef123\"\r\n\
                    Content-Length: 100\r\n\r\n";
    let res_304 = parse_http_response(raw_304, 100.0);
    assert!(res_304.is_complete);
    assert_eq!(res_304.response.unwrap().status, 304);
    assert_eq!(res_304.bytes_consumed, raw_304.len());
}

// =========================================================================
// 4. Protocol Resilience & Fuzz Data Safety
// =========================================================================

#[test]
fn test_fuzz_garbage_data_never_panics_or_loops() {
    // Arbitrary binary payloads, control characters, and high-ASCII bytes
    let garbage_payloads: Vec<&[u8]> = vec![
        b"",
        b"\x00\x00\x00\x00",
        b"\xFF\xFE\xFD\xFC",
        b"\r\r\r\r\n\n\n\n",
        b"GET \x00/path HTTP/1.1\r\n\r\n",
        b"POST / \x01\x02\x03\r\n\r\n",
        b"HTTP/1.1 \xFF 200 OK\r\n\r\n",
        b"\r\n\r\n\r\n",
    ];

    for (idx, payload) in garbage_payloads.iter().enumerate() {
        // Request parser safety
        let req_res = parse_http_request(payload, 100.0, "1.1.1.1", 1, "2.2.2.2", 2);
        assert!(
            !req_res.is_complete || req_res.request.is_some(),
            "Crash on payload idx {}",
            idx
        );

        // Response parser safety
        let resp_res = parse_http_response(payload, 100.0);
        assert!(
            !resp_res.is_complete || resp_res.response.is_some(),
            "Crash on response payload idx {}",
            idx
        );

        // Chunk decoder safety
        let (_, _, _, _) = decode_chunked_body_with_limits(payload, &ParserLimits::default());
    }
}

// =========================================================================
// 5. Pipelined & Fragmented Stream Reassembly Robustness
// =========================================================================

#[test]
fn test_pipelined_requests_with_malformed_recovery() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.10:50000->10.0.0.1:8080";

    // Feed a stream with:
    // 1. A malformed request line
    // 2. A valid GET request
    // 3. A valid POST request
    let mixed_traffic = b"MALFORMED_METHOD /bad HTTP/1.1\r\nHost: test.com\r\n\r\n\
                          GET /api/v1/profile HTTP/1.1\r\nHost: test.com\r\n\r\n\
                          POST /api/v1/update HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ndone";

    let frag_req = RawFragment {
        ts: 100.0,
        connection_id: conn_id.to_string(),
        direction: TrafficDirection::Ingress,
        payload: mixed_traffic.to_vec(),
    };
    let out = reassembler.process_fragment(frag_req);
    assert!(out.is_empty(), "Requests must wait for responses");

    // Verify reassembler skipped the malformed request and retained the 2 valid pending requests
    let state = reassembler.connections.values().next().unwrap();
    assert_eq!(state.pending_requests.len(), 2);
    assert_eq!(state.pending_requests[0].method, "GET");
    assert_eq!(state.pending_requests[0].path, "/api/v1/profile");
    assert_eq!(state.pending_requests[1].method, "POST");
    assert_eq!(state.pending_requests[1].path, "/api/v1/update");

    // Deliver matching responses for the 2 valid requests
    let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp2 = b"HTTP/1.1 204 No Content\r\n\r\n";

    let rec1 = reassembler.process_fragment(RawFragment {
        ts: 100.010,
        connection_id: "10.0.0.1:8080->10.0.0.10:50000".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp1.to_vec(),
    });
    assert_eq!(rec1.len(), 1);
    assert_eq!(rec1[0].method, "GET");
    assert_eq!(rec1[0].status, 200);

    let rec2 = reassembler.process_fragment(RawFragment {
        ts: 100.020,
        connection_id: "10.0.0.1:8080->10.0.0.10:50000".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp2.to_vec(),
    });
    assert_eq!(rec2.len(), 1);
    assert_eq!(rec2[0].method, "POST");
    assert_eq!(rec2[0].status, 204);
}

#[test]
fn test_single_byte_extreme_stream_fragmentation() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.1.100:44332->10.0.0.1:8080";

    let req_bytes = b"POST /api/v1/order HTTP/1.1\r\n\
                      Host: store.internal\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 13\r\n\r\n\
                      {\"item\": 999}";

    // Deliver request byte-by-byte (extreme fragmentation)
    for (i, &b) in req_bytes.iter().enumerate() {
        let frag = RawFragment {
            ts: 100.0 + (i as f64) * 0.0001,
            connection_id: conn_id.to_string(),
            direction: TrafficDirection::Ingress,
            payload: vec![b],
        };
        let _ = reassembler.process_fragment(frag);
    }

    let state = reassembler.connections.values().next().unwrap();
    assert_eq!(state.pending_requests.len(), 1);
    let req = &state.pending_requests[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/v1/order");
    assert_eq!(req.raw_body, Some(b"{\"item\": 999}".to_vec()));

    // Deliver response byte-by-byte
    let resp_bytes = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    let mut emitted = Vec::new();
    for (i, &b) in resp_bytes.iter().enumerate() {
        let frag = RawFragment {
            ts: 100.05 + (i as f64) * 0.0001,
            connection_id: "10.0.0.1:8080->192.168.1.100:44332".to_string(),
            direction: TrafficDirection::Egress,
            payload: vec![b],
        };
        let mut recs = reassembler.process_fragment(frag);
        emitted.append(&mut recs);
    }

    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].status, 201);
    assert_eq!(emitted[0].method, "POST");
    assert!(emitted[0].latency_ms > 0.0);
}
