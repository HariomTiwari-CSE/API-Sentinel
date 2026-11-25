//! # API-Sentinel HTTP Parser Crate (`api-sentinel-parser`)
//!
//! High-performance HTTP/1.x stream reconstruction and normalization engine.
//! Bridges the kernel-level eBPF sensor/Rust agent with downstream security
//! analytics engines:
//! - **Agam's Shadow API Discovery** (`discovery/`): Endpoint mapping & OpenAPI contract verification
//! - **Hariom's BOLA/BFLA Detection** (`detector/`): Object-level authorization & threat detection
//! - **Meet's PII Masking & Dashboard** (`masking/`, `dashboard/`): Privacy sanitization & live telemetry
//!
//! ## Public Architecture & Usage Examples
//!
//! ### 1. Stateful Stream Reassembly (`HttpParser` trait)
//! ```rust
//! use api_sentinel_parser::{HttpParser, RawFragment, StreamReassembler, TrafficDirection};
//!
//! let mut parser = StreamReassembler::new();
//! let conn_id = "10.0.0.1:45000->10.0.0.2:80";
//!
//! // Feed ingress (request) bytes
//! let req_bytes = b"GET /api/v1/users/42 HTTP/1.1\r\nHost: api.local\r\n\r\n";
//! let out1 = parser.feed_raw(conn_id, 100.0, TrafficDirection::Ingress, req_bytes);
//! assert!(out1.is_empty()); // Waiting for response
//!
//! // Feed egress (response) bytes
//! let resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
//! let out2 = parser.feed_raw(conn_id, 100.015, TrafficDirection::Egress, resp_bytes);
//! assert_eq!(out2.len(), 1);
//!
//! let record = &out2[0];
//! assert_eq!(record.path, "/api/v1/users/42");
//! assert_eq!(record.status, 200);
//! assert!((record.latency_ms - 15.0).abs() < 0.1);
//! ```
//!
//! ### 2. Record Serialization Contract
//! ```rust
//! use api_sentinel_parser::Record;
//!
//! let record = Record::new(100.0, "user_alice", "POST", "/api/items", 201);
//! let json_output = record.to_json().expect("Serialized to JSON");
//! let parsed_back = Record::from_json(&json_output).expect("Deserialized from JSON");
//! assert_eq!(record, parsed_back);
//! ```
//!
//! ### 3. Stateless Request Parsing
//! ```rust
//! use api_sentinel_parser::parse_http_request;
//!
//! let raw = b"GET /health?debug=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
//! let result = parse_http_request(raw, 100.0, "127.0.0.1", 1234, "127.0.0.1", 80);
//! assert!(result.is_complete);
//! let req = result.request.unwrap();
//! assert_eq!(req.base_path(), "/health");
//! ```

pub mod auth;
pub mod base;
pub mod models;
pub mod reassembler;
pub mod request;
pub mod response;

pub use auth::{
    decode_base64_url, decode_jwt_payload, extract_identity_and_role, DEFAULT_ANONYMOUS_USER,
    DEFAULT_USER_ROLE,
};
pub use base::HttpParser;
pub use models::{
    ConnectionKey, ParsedHTTPRequest, ParsedHTTPResponse, ParserLimits, RawFragment, Record,
    TrafficDirection,
};
pub use reassembler::{
    canonical_connection_key, parse_endpoints, ConnectionState, StreamReassembler,
};
pub use request::{
    decode_body_content, decode_body_content_with_limits, decode_chunked_body,
    decode_chunked_body_with_limits, decode_url_component, parse_all_requests,
    parse_all_requests_with_limits, parse_form_urlencoded, parse_http_request,
    parse_http_request_with_limits, parse_query_params, parse_uri_query, RequestParseResult,
};
pub use response::{
    parse_all_responses, parse_all_responses_with_limits, parse_http_response,
    parse_http_response_with_limits, ResponseParseResult,
};
