//! Abstract trait and interface definition for HTTP parsers.
//!
//! Enables modular parser implementations, testing mocks, and alternate backends
//! while enforcing a strict interface contract.

use crate::models::{RawFragment, Record, TrafficDirection};

/// Trait defining the core HTTP stream parser interface.
pub trait HttpParser {
    /// Ingest a single raw traffic fragment and return any completed transactions as `Record`s.
    fn feed_fragment(&mut self, fragment: &RawFragment) -> Vec<Record>;

    /// Convenience helper to feed raw stream parameters directly.
    fn feed_raw(
        &mut self,
        connection_id: &str,
        ts: f64,
        direction: TrafficDirection,
        payload: &[u8],
    ) -> Vec<Record> {
        let fragment = RawFragment {
            connection_id: connection_id.to_string(),
            ts,
            direction,
            payload: payload.to_vec(),
        };
        self.feed_fragment(&fragment)
    }

    /// Reset buffered state for a specific connection or all connections.
    fn reset(&mut self, connection_id: Option<&str>);

    /// Return list of connection IDs currently holding buffered in-flight data.
    fn active_connections(&self) -> Vec<String>;
}

