//! Stateful TCP stream reassembly, connection buffer tracking, and request-response matching.
//!
//! Maintains per-connection in-flight buffers to reassemble TCP segments across
//! multiple kernel socket syscalls, pairs HTTP requests with responses in FIFO order,
//! and computes accurate transaction round-trip latencies.
//!
//! Day 4 Hardening:
//! - Connection idle timeout / TTL sweep (`sweep_idle_connections`) to prevent memory leaks
//! - Configurable `ParserLimits` to bound memory usage
//! - Safe handling of orphan/unmatched responses when capture starts mid-session
//! - Trailing garbage drain to prevent buffer deadlocks on malformed payloads

use std::collections::HashMap;
use crate::auth::extract_identity_and_role;
use crate::base::HttpParser;
use crate::models::{ParsedHTTPRequest, ParsedHTTPResponse, ParserLimits, RawFragment, Record, TrafficDirection};
use crate::request::parse_http_request_with_limits;
use crate::response::parse_http_response_with_limits;

/// Tracks the byte buffers and in-flight transactions for a single TCP connection.
#[derive(Debug, Clone, Default)]
pub struct ConnectionState {
    pub connection_id: String,
    pub created_at: f64,
    pub last_activity: f64,
    pub ingress_buffer: Vec<u8>,
    pub egress_buffer: Vec<u8>,
    pub pending_requests: Vec<ParsedHTTPRequest>,
}

impl ConnectionState {
    pub fn new(connection_id: impl Into<String>, ts: f64) -> Self {
        Self {
            connection_id: connection_id.into(),
            created_at: ts,
            last_activity: ts,
            ingress_buffer: Vec::new(),
            egress_buffer: Vec::new(),
            pending_requests: Vec::new(),
        }
    }

    /// Append incoming request bytes to the ingress buffer.
    pub fn append_ingress(&mut self, chunk: &[u8], ts: f64) {
        self.ingress_buffer.extend_from_slice(chunk);
        self.last_activity = ts;
    }

    /// Append incoming response bytes to the egress buffer.
    pub fn append_egress(&mut self, chunk: &[u8], ts: f64) {
        self.egress_buffer.extend_from_slice(chunk);
        self.last_activity = ts;
    }

    /// Calculate round-trip transaction latency in milliseconds.
    pub fn calculate_latency_ms(&self, req: &ParsedHTTPRequest, resp: &ParsedHTTPResponse) -> f64 {
        if req.ts > 0.0 && resp.ts >= req.ts {
            ((resp.ts - req.ts) * 1000.0 * 100.0).round() / 100.0
        } else {
            0.0
        }
    }

    /// Clear all internal stream buffers and pending requests.
    pub fn clear(&mut self) {
        self.ingress_buffer.clear();
        self.egress_buffer.clear();
        self.pending_requests.clear();
    }
}

/// Canonical bidirectional connection key helper.
///
/// Normalizes "10.0.0.5:45000->10.0.0.1:8080" and "10.0.0.1:8080->10.0.0.5:45000"
/// into a canonical bidirectional key so ingress and egress fragments map to the same state.
pub fn canonical_connection_key(conn_id: &str) -> String {
    if let Some((left, right)) = conn_id.split_once("->") {
        let left = left.trim();
        let right = right.trim();
        if left <= right {
            format!("{}<->{}", left, right)
        } else {
            format!("{}<->{}", right, left)
        }
    } else {
        conn_id.to_string()
    }
}

/// Parse source IP and port from a connection ID string (e.g. "10.0.0.5:45000->10.0.0.1:8080").
pub fn parse_endpoints(conn_id: &str) -> (String, u16, String, u16) {
    if let Some((src, dst)) = conn_id.split_once("->") {
        let (s_ip, s_port) = src.trim().split_once(':').unwrap_or((src.trim(), "0"));
        let (d_ip, d_port) = dst.trim().split_once(':').unwrap_or((dst.trim(), "0"));
        (
            s_ip.to_string(),
            s_port.parse().unwrap_or(0),
            d_ip.to_string(),
            d_port.parse().unwrap_or(0),
        )
    } else {
        (String::new(), 0, String::new(), 0)
    }
}

/// Helper to find next line boundary when skipping malformed stream bytes.
fn find_next_line_boundary(buf: &[u8]) -> usize {
    if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
        pos + 2
    } else if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        pos + 1
    } else {
        buf.len()
    }
}

/// Buffer capacity threshold above which drained empty buffers are shrunk to prevent memory retention.
const BUFFER_SHRINK_THRESHOLD: usize = 64 * 1024;
const BUFFER_SHRINK_TARGET: usize = 4096;

/// Core stream reassembly engine that buffers network fragments, parses HTTP/1.x
/// transactions, matches requests with responses in FIFO order, and emits standardized `Record`s.
#[derive(Debug, Clone)]
pub struct StreamReassembler {
    pub connections: HashMap<String, ConnectionState>,
    pub idle_timeout_secs: f64,
    pub limits: ParserLimits,
    pub unmatched_responses_count: usize,
    pub swept_connections_count: usize,
    pub last_sweep_ts: f64,
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            idle_timeout_secs: 60.0,
            limits: ParserLimits::default(),
            unmatched_responses_count: 0,
            swept_connections_count: 0,
            last_sweep_ts: 0.0,
        }
    }

    pub fn with_timeout(timeout_secs: f64) -> Self {
        Self {
            connections: HashMap::new(),
            idle_timeout_secs: timeout_secs,
            limits: ParserLimits::default(),
            unmatched_responses_count: 0,
            swept_connections_count: 0,
            last_sweep_ts: 0.0,
        }
    }

    pub fn with_config(timeout_secs: f64, limits: ParserLimits) -> Self {
        Self {
            connections: HashMap::new(),
            idle_timeout_secs: timeout_secs,
            limits,
            unmatched_responses_count: 0,
            swept_connections_count: 0,
            last_sweep_ts: 0.0,
        }
    }

    /// Sweep and evict connections that have been inactive longer than `idle_timeout_secs`.
    /// Returns the number of connections evicted.
    pub fn sweep_idle_connections(&mut self, current_ts: f64) -> usize {
        let timeout = self.idle_timeout_secs;
        if timeout <= 0.0 {
            return 0;
        }

        self.last_sweep_ts = current_ts;
        let before_count = self.connections.len();
        self.connections.retain(|_, state| {
            if state.last_activity > 0.0 && current_ts >= state.last_activity {
                (current_ts - state.last_activity) <= timeout
            } else {
                true
            }
        });
        let evicted = before_count - self.connections.len();
        self.swept_connections_count += evicted;
        evicted
    }
}

impl HttpParser for StreamReassembler {
    fn feed_fragment(&mut self, fragment: &RawFragment) -> Vec<Record> {
        // Throttled periodic cleanup of expired idle connections (avoids O(N) scan on every packet)
        if fragment.ts > 0.0 && self.idle_timeout_secs > 0.0 {
            let sweep_interval = (self.idle_timeout_secs / 4.0).max(1.0);
            if self.last_sweep_ts == 0.0 {
                self.last_sweep_ts = fragment.ts;
            } else if fragment.ts - self.last_sweep_ts >= sweep_interval {
                self.sweep_idle_connections(fragment.ts);
            }
        }

        let canon_id = canonical_connection_key(&fragment.connection_id);
        let (src_ip, src_port, dst_ip, dst_port) = parse_endpoints(&fragment.connection_id);

        let limits = self.limits;
        let state = self.connections
            .entry(canon_id.clone())
            .or_insert_with(|| ConnectionState::new(&canon_id, fragment.ts));

        let mut finalized_records = Vec::new();

        match fragment.direction {
            TrafficDirection::Ingress => {
                state.append_ingress(&fragment.payload, fragment.ts);

                // Drain complete requests from ingress buffer
                loop {
                    if state.ingress_buffer.is_empty() {
                        break;
                    }

                    let res = parse_http_request_with_limits(
                        &state.ingress_buffer,
                        fragment.ts,
                        &src_ip,
                        src_port,
                        &dst_ip,
                        dst_port,
                        &limits,
                    );

                    if res.is_complete && res.request.is_some() && res.bytes_consumed > 0 {
                        let req = res.request.unwrap();
                        let consumed = res.bytes_consumed;
                        if limits.max_pending_requests > 0
                            && state.pending_requests.len() >= limits.max_pending_requests
                        {
                            // Evict oldest unmatched pending request to bound memory growth
                            state.pending_requests.remove(0);
                        }
                        state.pending_requests.push(req);
                        state.ingress_buffer.drain(..consumed);
                    } else if res.error.is_some() {
                        // Malformed request line or unrecoverable error:
                        // Discard the corrupted line and continue scanning for valid pipelined requests
                        let drain_len = if res.bytes_consumed > 0 {
                            res.bytes_consumed.min(state.ingress_buffer.len())
                        } else {
                            find_next_line_boundary(&state.ingress_buffer)
                        };
                        if drain_len == 0 {
                            break;
                        }
                        state.ingress_buffer.drain(..drain_len);
                        continue;
                    } else {
                        // Incomplete, waiting for more data
                        break;
                    }
                }

                // Release excess allocated memory after large payloads drain
                if state.ingress_buffer.is_empty() && state.ingress_buffer.capacity() > BUFFER_SHRINK_THRESHOLD {
                    state.ingress_buffer.shrink_to(BUFFER_SHRINK_TARGET);
                }
            }
            TrafficDirection::Egress => {
                state.append_egress(&fragment.payload, fragment.ts);

                // Drain complete responses from egress buffer
                loop {
                    if state.egress_buffer.is_empty() {
                        break;
                    }

                    let res = parse_http_response_with_limits(&state.egress_buffer, fragment.ts, &limits);

                    if res.is_complete && res.response.is_some() && res.bytes_consumed > 0 {
                        let resp = res.response.unwrap();
                        let consumed = res.bytes_consumed;
                        state.egress_buffer.drain(..consumed);

                        // Match with pending request (FIFO)
                        if !state.pending_requests.is_empty() {
                            let req = state.pending_requests.remove(0);
                            let latency_ms = state.calculate_latency_ms(&req, &resp);
                            let (user, role) = extract_identity_and_role(&req.headers);
                            let client_ip = if !req.src_ip.is_empty() {
                                req.src_ip
                            } else {
                                src_ip.clone()
                            };

                            let record = Record {
                                ts: req.ts,
                                user,
                                role,
                                method: req.method,
                                path: req.path,
                                status: resp.status,
                                req_body: req.body,
                                resp_body: resp.body,
                                latency_ms,
                                src_ip: client_ip,
                            };
                            finalized_records.push(record);
                        } else {
                            // Task 4: Orphan/unmatched response (e.g. captured mid-session or missing request fragment)
                            self.unmatched_responses_count += 1;
                            let client_ip = if !dst_ip.is_empty() {
                                dst_ip.clone()
                            } else {
                                "unknown".to_string()
                            };
                            let record = Record {
                                ts: resp.ts,
                                user: "anonymous".to_string(),
                                role: "user".to_string(),
                                method: "UNKNOWN".to_string(),
                                path: String::new(),
                                status: resp.status,
                                req_body: None,
                                resp_body: resp.body,
                                latency_ms: 0.0,
                                src_ip: client_ip,
                            };
                            finalized_records.push(record);
                        }
                    } else if res.error.is_some() {
                        let drain_len = if res.bytes_consumed > 0 {
                            res.bytes_consumed.min(state.egress_buffer.len())
                        } else {
                            find_next_line_boundary(&state.egress_buffer)
                        };
                        if drain_len == 0 {
                            break;
                        }
                        state.egress_buffer.drain(..drain_len);
                        continue;
                    } else {
                        break;
                    }
                }

                // Release excess allocated memory after large payloads drain
                if state.egress_buffer.is_empty() && state.egress_buffer.capacity() > BUFFER_SHRINK_THRESHOLD {
                    state.egress_buffer.shrink_to(BUFFER_SHRINK_TARGET);
                }
            }
        }

        finalized_records
    }

    fn reset(&mut self, connection_id: Option<&str>) {
        if let Some(id) = connection_id {
            let canon_id = canonical_connection_key(id);
            self.connections.remove(&canon_id);
            self.connections.remove(id);
        } else {
            self.connections.clear();
        }
    }

    fn active_connections(&self) -> Vec<String> {
        self.connections
            .iter()
            .filter(|(_, state)| {
                !state.ingress_buffer.is_empty()
                    || !state.egress_buffer.is_empty()
                    || !state.pending_requests.is_empty()
            })
            .map(|(id, _)| id.clone())
            .collect()
    }
}
