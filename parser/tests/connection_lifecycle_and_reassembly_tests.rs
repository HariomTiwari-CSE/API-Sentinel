//! Day 14 Connection Lifecycle & Stream Reassembly Reliability Test Suite.
//!
//! Validates:
//! 1. Repeated connection lifecycle cycles (create -> process -> close/reset -> reconnect)
//! 2. Heavy TCP fragmentation across arbitrary slice boundaries (byte-by-byte, uneven chunks, boundary splits)
//! 3. Pipelining with delayed responses and interleaved orphan responses
//! 4. Bounded pending-request queue enforcement (`max_pending_requests` eviction)
//! 5. Bidirectional socket 4-tuple isolation (different client IPs, different ephemeral ports)
//! 6. Active vs. idle connection discrimination during cleanup sweeps (zero loss of in-flight transactions)
//! 7. Stream corruption recovery followed by valid transaction processing on the same connection

use api_sentinel_parser::{
    canonical_connection_key, parse_endpoints, ConnectionState, HttpParser, ParserLimits,
    RawFragment, Record, StreamReassembler, TrafficDirection, DEFAULT_ANONYMOUS_USER,
};

// =========================================================================
// 1. Repeated Connection Lifecycle & Reconnect Cycles
// =========================================================================

#[test]
fn test_repeated_connection_create_process_reset_reconnect_cycles() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.10.15:40000->10.0.0.1:8080";

    for cycle in 1..=50 {
        // Step 1: Send request
        let req = format!(
            "GET /api/cycle/{} HTTP/1.1\r\nHost: local.test\r\nX-User-Id: client_{}\r\n\r\n",
            cycle, cycle
        );
        let r1 = reassembler.feed_raw(
            conn_id,
            100.0 + (cycle as f64),
            TrafficDirection::Ingress,
            req.as_bytes(),
        );
        assert!(r1.is_empty(), "Cycle {}: request should be pending", cycle);
        assert_eq!(reassembler.active_connections().len(), 1);

        // Step 2: Send matching response
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{{\"cycle\":{}}}",
            cycle
        );
        let r2 = reassembler.feed_raw(
            conn_id,
            100.0 + (cycle as f64) + 0.010,
            TrafficDirection::Egress,
            resp.as_bytes(),
        );
        assert_eq!(r2.len(), 1, "Cycle {}: transaction should match", cycle);
        assert_eq!(r2[0].path, format!("/api/cycle/{}", cycle));
        assert_eq!(r2[0].user, format!("client_{}", cycle));
        assert_eq!(r2[0].status, 200);

        // Step 3: Explicit connection reset / close
        reassembler.reset(Some(conn_id));
        assert!(
            reassembler.active_connections().is_empty(),
            "Cycle {}: connection should be removed after reset",
            cycle
        );
    }

    assert_eq!(reassembler.connection_count(), 0);
}

// =========================================================================
// 2. Heavy TCP Fragmentation Across Arbitrary Slice Boundaries
// =========================================================================

#[test]
fn test_byte_by_byte_fragmentation_trickle() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.1.1.1:51234->10.1.1.2:80";

    let req = "POST /trickle HTTP/1.1\r\nHost: test.io\r\nContent-Length: 5\r\n\r\nHELLO";
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

    // Feed request 1 byte at a time
    for (idx, b) in req.bytes().enumerate() {
        let records = reassembler.feed_raw(
            conn_id,
            10.0 + (idx as f64) * 0.001,
            TrafficDirection::Ingress,
            &[b],
        );
        assert!(records.is_empty(), "No record before response completes");
    }

    // Feed response 1 byte at a time
    let mut final_records = Vec::new();
    for (idx, b) in resp.bytes().enumerate() {
        let records = reassembler.feed_raw(
            conn_id,
            20.0 + (idx as f64) * 0.001,
            TrafficDirection::Egress,
            &[b],
        );
        final_records.extend(records);
    }

    assert_eq!(final_records.len(), 1);
    assert_eq!(final_records[0].method, "POST");
    assert_eq!(final_records[0].path, "/trickle");
    assert_eq!(
        final_records[0].req_body.as_ref().unwrap(),
        &serde_json::Value::String("HELLO".to_string())
    );
    assert_eq!(final_records[0].status, 200);
}

#[test]
fn test_uneven_fragment_splits_at_critical_boundaries() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.2.2.2:33333->10.2.2.1:8080";

    // Split across:
    // 1. Middle of method ("PO" + "ST")
    // 2. Middle of URI ("/api/pay" + "ments")
    // 3. Middle of Header ("Content-Len" + "gth: 13")
    // 4. Middle of headers delimiter ("\r\n\r" + "\n")
    // 5. Middle of JSON body ("{\"val\":" + "42}")
    let slices: &[&[u8]] = &[
        b"PO",
        b"ST /api/pay",
        b"ments HTTP/1.1\r\nHost: pay.local\r\nContent-Len",
        b"gth: 11\r\nContent-Type: application/json\r\n\r",
        b"\n{\"val\":42}",
    ];

    for (i, slice) in slices.iter().enumerate() {
        let recs = reassembler.feed_raw(
            conn_id,
            100.0 + (i as f64),
            TrafficDirection::Ingress,
            slice,
        );
        assert!(recs.is_empty());
    }

    // Response split across status line and body
    let resp_slices: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: ",
        b"14\r\n\r\n{\"processed\":true}",
    ];

    let mut out = Vec::new();
    for (i, slice) in resp_slices.iter().enumerate() {
        let recs =
            reassembler.feed_raw(conn_id, 200.0 + (i as f64), TrafficDirection::Egress, slice);
        out.extend(recs);
    }

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].method, "POST");
    assert_eq!(out[0].path, "/api/payments");
    assert_eq!(out[0].req_body.as_ref().unwrap()["val"], 42);
    assert_eq!(out[0].resp_body.as_ref().unwrap()["processed"], true);
}

// =========================================================================
// 3. Pipelining, Delayed Responses & Interleaved Orphans
// =========================================================================

#[test]
fn test_pipelining_with_delayed_and_batched_responses() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "172.16.0.5:44444->172.16.0.1:80";

    // Send 4 pipelined requests in a single batch
    let pipelined_reqs = "GET /items/1 HTTP/1.1\r\n\r\n\
                          GET /items/2 HTTP/1.1\r\n\r\n\
                          GET /items/3 HTTP/1.1\r\n\r\n\
                          GET /items/4 HTTP/1.1\r\n\r\n";

    let r_init = reassembler.feed_raw(
        conn_id,
        100.0,
        TrafficDirection::Ingress,
        pipelined_reqs.as_bytes(),
    );
    assert!(r_init.is_empty());
    assert_eq!(reassembler.total_pending_requests(), 4);

    // Delayed response 1 arrives
    let r1 = reassembler.feed_raw(
        conn_id,
        100.010,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n#1\n",
    );
    assert_eq!(r1.len(), 1);
    assert_eq!(r1[0].path, "/items/1");
    assert_eq!(reassembler.total_pending_requests(), 3);

    // Responses 2 and 3 arrive together in one batch
    let batch_23 = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n#2\n\
                     HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n#3\n";
    let r23 = reassembler.feed_raw(conn_id, 100.020, TrafficDirection::Egress, batch_23);
    assert_eq!(r23.len(), 2);
    assert_eq!(r23[0].path, "/items/2");
    assert_eq!(r23[1].path, "/items/3");
    assert_eq!(reassembler.total_pending_requests(), 1);

    // Response 4 arrives last
    let r4 = reassembler.feed_raw(
        conn_id,
        100.035,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n#4\n",
    );
    assert_eq!(r4.len(), 1);
    assert_eq!(r4[0].path, "/items/4");
    assert_eq!(reassembler.total_pending_requests(), 0);
}

#[test]
fn test_unmatched_orphan_responses_do_not_corrupt_subsequent_matching() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "10.0.0.99:50000->10.0.0.1:8080";

    // 1. Orphan response arrives with no prior request
    let orphan_records = reassembler.feed_raw(
        conn_id,
        50.0,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norphan",
    );
    assert_eq!(orphan_records.len(), 1);
    assert!(orphan_records[0].is_orphan());
    assert_eq!(orphan_records[0].method, "UNKNOWN");
    assert_eq!(reassembler.unmatched_responses_count, 1);

    // 2. Legitimate request-response transaction arrives immediately after
    reassembler.feed_raw(
        conn_id,
        51.0,
        TrafficDirection::Ingress,
        b"GET /valid HTTP/1.1\r\nX-User-Id: legitimate\r\n\r\n",
    );

    let valid_records = reassembler.feed_raw(
        conn_id,
        51.015,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );

    assert_eq!(valid_records.len(), 1);
    assert!(!valid_records[0].is_orphan());
    assert_eq!(valid_records[0].method, "GET");
    assert_eq!(valid_records[0].path, "/valid");
    assert_eq!(valid_records[0].user, "legitimate");
    assert_eq!(valid_records[0].status, 200);
}

// =========================================================================
// 4. Bounded Pending-Request Queue Enforcement (DoS Protection)
// =========================================================================

#[test]
fn test_pending_request_queue_bound_eviction() {
    // Restrict max pending requests to 3
    let strict_limits = ParserLimits::new().with_max_pending_requests(3);
    let mut reassembler = StreamReassembler::with_config(60.0, strict_limits);
    let conn_id = "10.0.0.88:12345->10.0.0.1:80";

    // Send 5 requests without any responses
    for i in 1..=5 {
        let req = format!("GET /req/{} HTTP/1.1\r\n\r\n", i);
        reassembler.feed_raw(
            conn_id,
            10.0 + (i as f64),
            TrafficDirection::Ingress,
            req.as_bytes(),
        );
    }

    // Queue must be capped at 3 (oldest requests /req/1 and /req/2 evicted)
    assert_eq!(reassembler.total_pending_requests(), 3);

    // Now send 3 responses: they must match requests 3, 4, 5 in FIFO order
    let mut matched = Vec::new();
    for i in 1..=3 {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let recs = reassembler.feed_raw(conn_id, 20.0 + (i as f64), TrafficDirection::Egress, resp);
        matched.extend(recs);
    }

    assert_eq!(matched.len(), 3);
    assert_eq!(matched[0].path, "/req/3");
    assert_eq!(matched[1].path, "/req/4");
    assert_eq!(matched[2].path, "/req/5");
    assert_eq!(reassembler.total_pending_requests(), 0);
}

// =========================================================================
// 5. Bidirectional Socket 4-Tuple Isolation & Key Normalization
// =========================================================================

#[test]
fn test_socket_tuple_isolation_different_ports_and_ips() {
    let mut reassembler = StreamReassembler::new();

    // Client A: 10.0.0.1:50000 -> 10.0.0.2:80
    // Client B: 10.0.0.1:50001 -> 10.0.0.2:80 (same IP, different ephemeral port)
    // Client C: 10.0.0.3:50000 -> 10.0.0.2:80 (different IP, same port)
    let conn_a = "10.0.0.1:50000->10.0.0.2:80";
    let conn_b = "10.0.0.1:50001->10.0.0.2:80";
    let conn_c = "10.0.0.3:50000->10.0.0.2:80";

    reassembler.feed_raw(
        conn_a,
        1.0,
        TrafficDirection::Ingress,
        b"GET /from_a HTTP/1.1\r\nX-User-Id: a\r\n\r\n",
    );
    reassembler.feed_raw(
        conn_b,
        1.1,
        TrafficDirection::Ingress,
        b"GET /from_b HTTP/1.1\r\nX-User-Id: b\r\n\r\n",
    );
    reassembler.feed_raw(
        conn_c,
        1.2,
        TrafficDirection::Ingress,
        b"GET /from_c HTTP/1.1\r\nX-User-Id: c\r\n\r\n",
    );

    assert_eq!(reassembler.active_connections().len(), 3);

    // Respond to B first using reverse directional ID (as sent by server)
    let rev_b = "10.0.0.2:80->10.0.0.1:50001";
    let rec_b = reassembler.feed_raw(
        rev_b,
        1.5,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(rec_b.len(), 1);
    assert_eq!(rec_b[0].path, "/from_b");
    assert_eq!(rec_b[0].user, "b");

    // Respond to C next using reverse directional ID
    let rev_c = "10.0.0.2:80->10.0.0.3:50000";
    let rec_c = reassembler.feed_raw(
        rev_c,
        1.6,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(rec_c.len(), 1);
    assert_eq!(rec_c[0].path, "/from_c");
    assert_eq!(rec_c[0].user, "c");

    // Respond to A last using forward ID
    let rec_a = reassembler.feed_raw(
        conn_a,
        1.7,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(rec_a.len(), 1);
    assert_eq!(rec_a[0].path, "/from_a");
    assert_eq!(rec_a[0].user, "a");

    assert!(reassembler.active_connections().is_empty());
}

#[test]
fn test_canonical_key_and_endpoints_normalization() {
    // Directional normalization
    assert_eq!(
        canonical_connection_key("10.0.0.1:5000->10.0.0.2:80"),
        canonical_connection_key("10.0.0.2:80->10.0.0.1:5000")
    );

    // Bidirectional symmetric normalization
    assert_eq!(
        canonical_connection_key("10.0.0.1:5000<->10.0.0.2:80"),
        canonical_connection_key("10.0.0.2:80<->10.0.0.1:5000")
    );

    // Parse endpoints from directional and bidirectional strings
    let (s1, p1, d1, q1) = parse_endpoints("10.0.0.1:5000->10.0.0.2:80");
    assert_eq!(s1, "10.0.0.1");
    assert_eq!(p1, 5000);
    assert_eq!(d1, "10.0.0.2");
    assert_eq!(q1, 80);

    let (s2, p2, d2, q2) = parse_endpoints("10.0.0.1:5000<->10.0.0.2:80");
    assert_eq!(s2, "10.0.0.1");
    assert_eq!(p2, 5000);
    assert_eq!(d2, "10.0.0.2");
    assert_eq!(q2, 80);
}

// =========================================================================
// 6. Active vs. Idle Connection Discrimination (Zero Transaction Loss)
// =========================================================================

#[test]
fn test_cleanup_preserves_active_in_flight_transactions() {
    let mut reassembler = StreamReassembler::with_timeout(10.0);

    let conn_active = "10.0.0.1:1000->10.0.0.2:80";
    let conn_stale = "10.0.0.3:2000->10.0.0.4:80";

    // At ts = 100.0, both connections become active
    reassembler.feed_raw(
        conn_active,
        100.0,
        TrafficDirection::Ingress,
        b"GET /active HTTP/1.1\r\nX-User-Id: alice\r\n\r\n",
    );
    reassembler.feed_raw(
        conn_stale,
        100.0,
        TrafficDirection::Ingress,
        b"GET /stale HTTP/1.1\r\n\r\n",
    );

    assert_eq!(reassembler.total_pending_requests(), 2);
    assert_eq!(reassembler.connection_count(), 2);

    // Keep conn_active refreshed at ts = 108.0 (e.g. keepalive chunk)
    reassembler.feed_raw(conn_active, 108.0, TrafficDirection::Ingress, b"");

    // Perform cleanup at ts = 112.0 (timeout = 10.0s)
    // conn_stale: inactive for 12.0s (> 10.0s) -> evicted
    // conn_active: inactive for 4.0s (<= 10.0s) -> preserved with pending request intact!
    let evicted = reassembler.clean_idle_connections(112.0);
    assert_eq!(evicted, 1);
    assert_eq!(reassembler.connection_count(), 1);
    assert_eq!(reassembler.total_pending_requests(), 1);

    // Response arrives for conn_active: must match successfully without loss!
    let records = reassembler.feed_raw(
        conn_active,
        112.005,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, "/active");
    assert_eq!(records[0].user, "alice");
    assert_eq!(records[0].status, 200);
    assert_eq!(reassembler.total_pending_requests(), 0);
}

// =========================================================================
// 7. Stream Corruption Recovery Followed by Valid Traffic
// =========================================================================

#[test]
fn test_corruption_recovery_and_reconnect() {
    let mut reassembler = StreamReassembler::new();
    let conn_id = "192.168.100.1:9090->10.0.0.1:80";

    // 1. Ingress receives corrupted partial request line
    let corrupted_chunk = b"GARBAGE_NO_METHOD /broken\r\nHost: test\r\n\r\n";
    let r_bad = reassembler.feed_raw(conn_id, 1.0, TrafficDirection::Ingress, corrupted_chunk);
    assert!(r_bad.is_empty());

    // 2. Immediately followed by valid pipelined request on the same stream
    let valid_chunk = b"GET /recovered HTTP/1.1\r\nHost: test\r\nX-User-Id: resilient_user\r\n\r\n";
    let r_valid_in = reassembler.feed_raw(conn_id, 1.1, TrafficDirection::Ingress, valid_chunk);
    assert!(r_valid_in.is_empty());
    assert_eq!(reassembler.total_pending_requests(), 1);

    // 3. Response arrives for valid request
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nSUCCESS";
    let r_out = reassembler.feed_raw(conn_id, 1.2, TrafficDirection::Egress, resp);
    assert_eq!(r_out.len(), 1);
    assert_eq!(r_out[0].path, "/recovered");
    assert_eq!(r_out[0].user, "resilient_user");
    assert_eq!(r_out[0].status, 200);

    // 4. Connection closure and clean reconnection
    reassembler.reset(Some(conn_id));
    assert_eq!(reassembler.connection_count(), 0);

    // 5. Reconnect with same 4-tuple and execute another clean transaction
    reassembler.feed_raw(
        conn_id,
        2.0,
        TrafficDirection::Ingress,
        b"GET /reconnected HTTP/1.1\r\n\r\n",
    );
    let r_reconn = reassembler.feed_raw(
        conn_id,
        2.010,
        TrafficDirection::Egress,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(r_reconn.len(), 1);
    assert_eq!(r_reconn[0].path, "/reconnected");
}
