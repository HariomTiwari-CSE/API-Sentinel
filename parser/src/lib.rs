//! API-Sentinel HTTP Parser Crate.
//!
//! High-performance HTTP stream reconstruction and normalization engine.
//! Bridges the kernel-level eBPF sensor/Rust agent with downstream security
//! analytics engines (Shadow API Discovery & BOLA/BFLA Detection).

pub mod auth;
pub mod base;
pub mod models;
pub mod reassembler;
pub mod request;

pub use auth::{decode_base64_url, decode_jwt_payload, extract_identity_and_role};
pub use base::HttpParser;
pub use models::{
    ConnectionKey, ParsedHTTPRequest, ParsedHTTPResponse, RawFragment, Record, TrafficDirection,
};
pub use reassembler::ConnectionState;
pub use request::{parse_all_requests, parse_http_request, RequestParseResult};
