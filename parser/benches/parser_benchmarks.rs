//! Reproducible Rust Benchmark Suite for Day 11: Parser Performance & Resource Efficiency.
//!
//! Covers:
//! 1. Simple GET requests
//! 2. POST requests with JSON bodies
//! 3. Chunked responses
//! 4. Fragmented and pipelined traffic
//! 5. Multiple concurrent connections (50 connections)

use api_sentinel_parser::{
    parse_all_requests, parse_http_request, parse_http_response, RawFragment, StreamReassembler,
    TrafficDirection,
};
use std::time::Instant;

fn bench_simple_get_requests(iterations: usize) {
    let raw_get = b"GET /api/v1/health HTTP/1.1\r\n\
                    Host: sentinel.internal\r\n\
                    User-Agent: SentinelProbe/1.0\r\n\
                    Accept: application/json\r\n\
                    Connection: keep-alive\r\n\r\n";

    let start = Instant::now();
    for _ in 0..iterations {
        let res = parse_http_request(raw_get, 100.0, "10.0.0.1", 54321, "10.0.0.2", 80);
        assert!(res.is_complete);
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() / iterations as u128;
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    let mb_per_sec =
        (raw_get.len() * iterations) as f64 / (1024.0 * 1024.0 * elapsed.as_secs_f64());

    println!(
        "Benchmark: Simple GET requests       | Iterations: {:<7} | Time/op: {:>5} ns | Rate: {:>10.0} req/s | Throughput: {:>6.2} MB/s",
        iterations, per_op_ns, ops_per_sec, mb_per_sec
    );
}

fn bench_post_json_requests(iterations: usize) {
    let raw_post = b"POST /api/v1/orders HTTP/1.1\r\n\
                     Host: store.internal\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: 67\r\n\
                     Authorization: Bearer mock.token.sig\r\n\r\n\
                     {\"order_id\": 10924, \"item\": \"Pro Sensor\", \"qty\": 2, \"active\": true}";

    let start = Instant::now();
    for _ in 0..iterations {
        let res = parse_http_request(raw_post, 100.0, "10.0.0.1", 54321, "10.0.0.2", 80);
        assert!(res.is_complete);
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() / iterations as u128;
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    let mb_per_sec =
        (raw_post.len() * iterations) as f64 / (1024.0 * 1024.0 * elapsed.as_secs_f64());

    println!(
        "Benchmark: POST with JSON bodies     | Iterations: {:<7} | Time/op: {:>5} ns | Rate: {:>10.0} req/s | Throughput: {:>6.2} MB/s",
        iterations, per_op_ns, ops_per_sec, mb_per_sec
    );
}

fn bench_chunked_responses(iterations: usize) {
    let raw_chunked = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: application/json\r\n\
                        Transfer-Encoding: chunked\r\n\
                        Server: nginx/1.24\r\n\r\n\
                        1B\r\n{\"status\":\"streaming_event\"}\r\n\
                        14\r\n{\"data\":\"chunk_two\"}\r\n\
                        0\r\n\r\n";

    let start = Instant::now();
    for _ in 0..iterations {
        let res = parse_http_response(raw_chunked, 100.0);
        assert!(res.is_complete);
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() / iterations as u128;
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    let mb_per_sec =
        (raw_chunked.len() * iterations) as f64 / (1024.0 * 1024.0 * elapsed.as_secs_f64());

    println!(
        "Benchmark: Chunked responses         | Iterations: {:<7} | Time/op: {:>5} ns | Rate: {:>10.0} resp/s| Throughput: {:>6.2} MB/s",
        iterations, per_op_ns, ops_per_sec, mb_per_sec
    );
}

fn bench_pipelined_traffic(iterations: usize) {
    let pipelined = b"GET /api/v1/a HTTP/1.1\r\nHost: test.com\r\n\r\n\
                      GET /api/v1/b HTTP/1.1\r\nHost: test.com\r\n\r\n\
                      GET /api/v1/c HTTP/1.1\r\nHost: test.com\r\n\r\n\
                      POST /api/v1/d HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\nping";

    let start = Instant::now();
    for _ in 0..iterations {
        let reqs = parse_all_requests(pipelined, 100.0, "10.0.0.1", 1234, "10.0.0.2", 80);
        assert_eq!(reqs.len(), 4);
    }
    let elapsed = start.elapsed();
    let total_reqs = iterations * 4;
    let per_req_ns = elapsed.as_nanos() / total_reqs as u128;
    let reqs_per_sec = (total_reqs as f64) / elapsed.as_secs_f64();
    let mb_per_sec =
        (pipelined.len() * iterations) as f64 / (1024.0 * 1024.0 * elapsed.as_secs_f64());

    println!(
        "Benchmark: Pipelined traffic (x4)    | Iterations: {:<7} | Time/op: {:>5} ns | Rate: {:>10.0} req/s | Throughput: {:>6.2} MB/s",
        iterations, per_req_ns, reqs_per_sec, mb_per_sec
    );
}

fn bench_concurrent_stream_reassembly(streams: usize, cycles: usize) {
    let mut reassembler = StreamReassembler::new();

    let start = Instant::now();
    for _ in 0..cycles {
        // Send requests on N streams
        for i in 1..=streams {
            let req = format!("GET /stream/{} HTTP/1.1\r\nHost: api.internal\r\n\r\n", i);
            let frag = RawFragment {
                ts: 100.0 + (i as f64) * 0.001,
                connection_id: format!("192.168.1.{}:40000->10.0.0.1:8080", i),
                direction: TrafficDirection::Ingress,
                payload: req.into_bytes(),
            };
            let _ = reassembler.process_fragment(frag);
        }

        // Deliver matching responses
        for i in 1..=streams {
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", i % 10);
            let frag = RawFragment {
                ts: 100.01 + (i as f64) * 0.001,
                connection_id: format!("10.0.0.1:8080->192.168.1.{}:40000", i),
                direction: TrafficDirection::Egress,
                payload: resp.into_bytes(),
            };
            let recs = reassembler.process_fragment(frag);
            assert_eq!(recs.len(), 1);
        }
    }
    let elapsed = start.elapsed();
    let total_tx = streams * cycles;
    let per_tx_ns = elapsed.as_nanos() / total_tx as u128;
    let tx_per_sec = (total_tx as f64) / elapsed.as_secs_f64();

    println!(
        "Benchmark: 50 Concurrent Connections| Cycles:     {:<7} | Time/op: {:>5} ns | Rate: {:>10.0} tx/s  | Latency:    {:>6.2} µs",
        cycles, per_tx_ns, tx_per_sec, (per_tx_ns as f64) / 1000.0
    );
}

fn main() {
    println!("=================================================================================");
    println!("API-Sentinel HTTP Parser Performance & Efficiency Benchmarks (Day 11)");
    println!("=================================================================================");
    bench_simple_get_requests(50_000);
    bench_post_json_requests(25_000);
    bench_chunked_responses(25_000);
    bench_pipelined_traffic(25_000);
    bench_concurrent_stream_reassembly(50, 100);
    println!("=================================================================================");
}
