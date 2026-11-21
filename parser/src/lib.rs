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
