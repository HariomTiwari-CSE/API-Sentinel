//! Stateful TCP stream reassembly and connection buffer tracking.
//!
//! Maintains per-connection in-flight buffers to reassemble TCP segments across
//! multiple kernel socket syscalls and compute accurate transaction round-trip latencies.

use crate::models::{ParsedHTTPRequest, ParsedHTTPResponse};

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

