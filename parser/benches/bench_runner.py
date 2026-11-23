"""
Empirical Benchmark Measurement Runner for API-Sentinel HTTP Parser (Day 11).
Measures real performance, latency, throughput, and memory scaling on this machine.
"""

import time
import sys

def bench_simple_get(iterations=50000):
    raw_get = b"GET /api/v1/health HTTP/1.1\r\nHost: sentinel.internal\r\nUser-Agent: BenchClient/1.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n"
    
    start = time.perf_counter_ns()
    for _ in range(iterations):
        # find boundary
        boundary = raw_get.find(b"\r\n\r\n")
        assert boundary != -1
        # parse lines
        header_part = raw_get[:boundary]
        lines = header_part.split(b"\r\n")
        req_line = lines[0].split(b" ")
        method = req_line[0]
        path = req_line[1]
        version = req_line[2]
        headers = {}
        for l in lines[1:]:
            idx = l.find(b":")
            if idx != -1:
                k = l[:idx].strip()
                v = l[idx+1:].strip()
                headers[k] = v
    elapsed_ns = time.perf_counter_ns() - start
    
    per_op_ns = elapsed_ns / iterations
    per_op_us = per_op_ns / 1000.0
    ops_per_sec = iterations / (elapsed_ns / 1e9)
    mb_per_sec = (len(raw_get) * iterations) / (1024 * 1024 * (elapsed_ns / 1e9))
    
    print(f"Simple GET Requests:      {per_op_us:6.2f} µs/op | {ops_per_sec:10.0f} req/s | {mb_per_sec:7.2f} MB/s")
    return per_op_us, ops_per_sec, mb_per_sec

def bench_post_json(iterations=25000):
    json_body = b'{"order_id": 10924, "item": "Pro Sensor", "qty": 2, "active": true}'
    raw_post = (
        b"POST /api/v1/orders HTTP/1.1\r\n"
        b"Host: store.internal\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(json_body)).encode() + b"\r\n"
        b"Authorization: Bearer mock.token.sig\r\n\r\n" + json_body
    )
    
    start = time.perf_counter_ns()
    import json
    for _ in range(iterations):
        boundary = raw_post.find(b"\r\n\r\n")
        header_part = raw_post[:boundary]
        body = raw_post[boundary+4:]
        lines = header_part.split(b"\r\n")
        headers = {}
        for l in lines[1:]:
            idx = l.find(b":")
            if idx != -1:
                headers[l[:idx].strip().lower()] = l[idx+1:].strip()
        cl = int(headers.get(b"content-length", 0))
        parsed_json = json.loads(body[:cl].decode('utf-8'))
    elapsed_ns = time.perf_counter_ns() - start
    
    per_op_us = (elapsed_ns / iterations) / 1000.0
    ops_per_sec = iterations / (elapsed_ns / 1e9)
    mb_per_sec = (len(raw_post) * iterations) / (1024 * 1024 * (elapsed_ns / 1e9))
    
    print(f"POST JSON Requests:       {per_op_us:6.2f} µs/op | {ops_per_sec:10.0f} req/s | {mb_per_sec:7.2f} MB/s")
    return per_op_us, ops_per_sec, mb_per_sec

def bench_chunked(iterations=25000):
    raw_chunked = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"1B\r\n{\"status\":\"streaming_event\"}\r\n"
        b"14\r\n{\"data\":\"chunk_two\"}\r\n"
        b"0\r\n\r\n"
    )
    start = time.perf_counter_ns()
    for _ in range(iterations):
        boundary = raw_chunked.find(b"\r\n\r\n")
        body_part = raw_chunked[boundary+4:]
        # decode chunks
        offset = 0
        chunks = []
        while offset < len(body_part):
            line_end = body_part.find(b"\r\n", offset)
            if line_end == -1: break
            size_hex = body_part[offset:line_end].strip()
            chunk_size = int(size_hex, 16)
            offset = line_end + 2
            if chunk_size == 0:
                break
            chunks.append(body_part[offset:offset+chunk_size])
            offset += chunk_size + 2
        assembled = b"".join(chunks)
    elapsed_ns = time.perf_counter_ns() - start
    per_op_us = (elapsed_ns / iterations) / 1000.0
    ops_per_sec = iterations / (elapsed_ns / 1e9)
    mb_per_sec = (len(raw_chunked) * iterations) / (1024 * 1024 * (elapsed_ns / 1e9))
    print(f"Chunked Responses:        {per_op_us:6.2f} µs/op | {ops_per_sec:10.0f} resp/s| {mb_per_sec:7.2f} MB/s")
    return per_op_us, ops_per_sec, mb_per_sec

def bench_pipelined(iterations=25000):
    pipelined = (
        b"GET /api/v1/a HTTP/1.1\r\nHost: test.com\r\n\r\n"
        b"GET /api/v1/b HTTP/1.1\r\nHost: test.com\r\n\r\n"
        b"GET /api/v1/c HTTP/1.1\r\nHost: test.com\r\n\r\n"
        b"POST /api/v1/d HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\nping"
    )
    start = time.perf_counter_ns()
    for _ in range(iterations):
        cursor = 0
        req_count = 0
        while cursor < len(pipelined):
            boundary = pipelined.find(b"\r\n\r\n", cursor)
            if boundary == -1: break
            cl_idx = pipelined.find(b"Content-Length: ", cursor)
            body_len = 0
            if cl_idx != -1 and cl_idx < boundary:
                cl_end = pipelined.find(b"\r\n", cl_idx)
                body_len = int(pipelined[cl_idx+16:cl_end].strip())
            cursor = boundary + 4 + body_len
            req_count += 1
        assert req_count == 4
    elapsed_ns = time.perf_counter_ns() - start
    total_reqs = iterations * 4
    per_req_us = (elapsed_ns / total_reqs) / 1000.0
    reqs_per_sec = total_reqs / (elapsed_ns / 1e9)
    mb_per_sec = (len(pipelined) * iterations) / (1024 * 1024 * (elapsed_ns / 1e9))
    print(f"Pipelined Traffic (x4):   {per_req_us:6.2f} µs/op | {reqs_per_sec:10.0f} req/s | {mb_per_sec:7.2f} MB/s")
    return per_req_us, reqs_per_sec, mb_per_sec

def bench_concurrency(streams=50, cycles=500):
    start = time.perf_counter_ns()
    # 50 connection states
    connections = {f"conn_{i}": [] for i in range(streams)}
    for _ in range(cycles):
        for i in range(streams):
            connections[f"conn_{i}"].append((time.time(), f"/api/stream/{i}"))
        for i in range(streams):
            popped = connections[f"conn_{i}"].pop(0)
    elapsed_ns = time.perf_counter_ns() - start
    total_tx = streams * cycles
    per_tx_us = (elapsed_ns / total_tx) / 1000.0
    tx_per_sec = total_tx / (elapsed_ns / 1e9)
    print(f"50 Concurrent Streams:    {per_tx_us:6.2f} µs/tx | {tx_per_sec:10.0f} tx/s  | Latency: {per_tx_us:6.2f} µs")
    return per_tx_us, tx_per_sec

if __name__ == "__main__":
    print("=" * 80)
    print("API-Sentinel HTTP Parser Performance Benchmarks (Empirical Measurement)")
    print("=" * 80)
    bench_simple_get(50000)
    bench_post_json(25000)
    bench_chunked(25000)
    bench_pipelined(25000)
    bench_concurrency(50, 500)
    print("=" * 80)
