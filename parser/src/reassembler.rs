//! Stateful TCP stream reassembly, connection buffer tracking, and request-response matching.
//!
//! Maintains per-connection in-flight buffers to reassemble TCP segments across
//! multiple kernel socket syscalls, pairs HTTP requests with responses in FIFO order,
//! and computes accurate transaction round-trip latencies.

use std::collections::HashMap;
use crate::auth::extract_identity_and_role;
use crate::base::HttpParser;
use crate::models::{ParsedHTTPRequest, ParsedHTTPResponse, RawFragment, Record, TrafficDirection};
use crate::request::parse_http_request;
use crate::response::parse_http_response;

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

/// Core stream reassembly engine that buffers network fragments, parses HTTP/1.x
/// transactions, matches requests with responses in FIFO order, and emits standardized `Record`s.
#[derive(Debug, Clone, Default)]
pub struct StreamReassembler {
    pub connections: HashMap<String, ConnectionState>,
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }
}

impl HttpParser for StreamReassembler {
    fn feed_fragment(&mut self, fragment: &RawFragment) -> Vec<Record> {
        let canon_id = canonical_connection_key(&fragment.connection_id);
        let (src_ip, src_port, dst_ip, dst_port) = parse_endpoints(&fragment.connection_id);

        let state = self.connections
            .entry(canon_id.clone())
            .or_insert_with(|| ConnectionState::new(&canon_id, fragment.ts));

        let mut finalized_records = Vec::new();

        match fragment.direction {
            TrafficDirection::Ingress => {
                state.append_ingress(&fragment.payload, fragment.ts);

                // Drain complete requests from ingress buffer
                loop {
                    let res = parse_http_request(
                        &state.ingress_buffer,
                        fragment.ts,
                        &src_ip,
                        src_port,
                        &dst_ip,
                        dst_port,
                    );

                    if !res.is_complete || res.request.is_none() || res.bytes_consumed == 0 {
                        break;
                    }

                    let req = res.request.unwrap();
                    let consumed = res.bytes_consumed;
                    state.pending_requests.push(req);
                    state.ingress_buffer.drain(..consumed);
                }
            }
            TrafficDirection::Egress => {
                state.append_egress(&fragment.payload, fragment.ts);

                // Drain complete responses from egress buffer
                loop {
                    let res = parse_http_response(&state.egress_buffer, fragment.ts);

                    if !res.is_complete || res.response.is_none() || res.bytes_consumed == 0 {
                        break;
                    }

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
                        // Orphan/unmatched response (e.g. captured mid-session or missing request fragment)
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
                            src_ip: dst_ip.clone(),
                        };
                        finalized_records.push(record);
                    }
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
