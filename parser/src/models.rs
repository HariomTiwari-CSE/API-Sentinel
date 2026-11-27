//! Data models and contract specifications for the API-Sentinel HTTP Parser module.
//!
//! Converted to Rust for high-performance zero-overhead packet processing and
//! seamless interoperability with the kernel eBPF / Rust ingestion agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Direction of traffic relative to the monitored service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

impl TrafficDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrafficDirection::Ingress => "ingress",
            TrafficDirection::Egress => "egress",
        }
    }
}

impl fmt::Display for TrafficDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TrafficDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "ingress" | "request" | "req" | "in" | "incoming" | "0" => {
                Ok(TrafficDirection::Ingress)
            }
            "egress" | "response" | "resp" | "out" | "outgoing" | "1" => {
                Ok(TrafficDirection::Egress)
            }
            _ => Err(format!("Unknown traffic direction: {}", s)),
        }
    }
}

/// Represents a network 4-tuple identifying a socket connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

impl ConnectionKey {
    pub fn new(
        src_ip: impl Into<String>,
        src_port: u16,
        dst_ip: impl Into<String>,
        dst_port: u16,
    ) -> Self {
        Self {
            src_ip: src_ip.into(),
            src_port,
            dst_ip: dst_ip.into(),
            dst_port,
            protocol: default_protocol(),
        }
    }

    /// Normalized forward connection identifier (e.g. "10.0.0.5:45000->10.0.0.1:8080").
    pub fn connection_id(&self) -> String {
        format!(
            "{}:{}->{}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }

    /// Reverse connection identifier for pairing the return traffic stream.
    pub fn reverse_id(&self) -> String {
        format!(
            "{}:{}->{}:{}",
            self.dst_ip, self.dst_port, self.src_ip, self.src_port
        )
    }

    /// Canonical bidirectional identifier invariant to orientation.
    pub fn bidirectional_id(&self) -> String {
        let endpoint_a = (&self.src_ip, self.src_port);
        let endpoint_b = (&self.dst_ip, self.dst_port);
        if endpoint_a <= endpoint_b {
            format!(
                "{}:{}<->{}:{}",
                self.src_ip, self.src_port, self.dst_ip, self.dst_port
            )
        } else {
            format!(
                "{}:{}<->{}:{}",
                self.dst_ip, self.dst_port, self.src_ip, self.src_port
            )
        }
    }
}

/// Raw payload fragment captured from the socket ring buffer by the Rust eBPF agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawFragment {
    pub connection_id: String,
    pub ts: f64,
    pub direction: TrafficDirection,
    #[serde(with = "serde_bytes_or_vec")]
    pub payload: Vec<u8>,
}

impl RawFragment {
    /// Construct a new `RawFragment` with payload.
    pub fn new(
        connection_id: impl Into<String>,
        ts: f64,
        direction: TrafficDirection,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            connection_id: connection_id.into(),
            ts,
            direction,
            payload: payload.into(),
        }
    }
}

mod serde_bytes_or_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Try UTF-8 string serialization if valid, otherwise byte array
        if let Ok(s) = std::str::from_utf8(bytes) {
            serializer.serialize_str(s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrBytes {
            String(String),
            Bytes(Vec<u8>),
        }

        match StringOrBytes::deserialize(deserializer)? {
            StringOrBytes::String(s) => Ok(s.into_bytes()),
            StringOrBytes::Bytes(b) => Ok(b),
        }
    }
}

/// Intermediate representation of an assembled HTTP Request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ParsedHTTPRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub raw_path: String,
    #[serde(default)]
    pub query_params: HashMap<String, Vec<String>>,
    #[serde(default = "default_http_version")]
    pub http_version: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<Vec<u8>>,
    #[serde(default)]
    pub ts: f64,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub dst_port: u16,
}

impl ParsedHTTPRequest {
    /// Return the base path of the URI without query string or fragment.
    pub fn base_path(&self) -> &str {
        if let Some(pos) = self.path.find('?') {
            &self.path[..pos]
        } else {
            &self.path
        }
    }

    /// Retrieve the first query parameter value for a given key.
    pub fn get_query_param(&self, key: &str) -> Option<&str> {
        self.query_params
            .get(key)
            .and_then(|v| v.first().map(|s| s.as_str()))
    }

    /// Retrieve all query parameter values for a given key.
    pub fn get_query_params(&self, key: &str) -> Option<&Vec<String>> {
        self.query_params.get(key)
    }

    /// Retrieve the raw, unparsed body bytes captured for this request, if present.
    pub fn raw_body_bytes(&self) -> Option<&[u8]> {
        self.raw_body.as_deref()
    }
}

fn default_http_version() -> String {
    "HTTP/1.1".to_string()
}

/// Intermediate representation of an assembled HTTP Response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ParsedHTTPResponse {
    pub status: u16,
    #[serde(default)]
    pub status_text: String,
    #[serde(default = "default_http_version")]
    pub http_version: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<Vec<u8>>,
    #[serde(default)]
    pub ts: f64,
}

impl ParsedHTTPResponse {
    /// Retrieve the raw, unparsed body bytes captured for this response, if present.
    pub fn raw_body_bytes(&self) -> Option<&[u8]> {
        self.raw_body.as_deref()
    }
}

fn default_role() -> String {
    "user".to_string()
}

/// Standardized output record produced by the HTTP Parser.
///
/// This record conforms to the project-wide contract consumed in parallel
/// by Agam's Shadow API Discovery engine and Hariom's BOLA/BFLA Detection engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub ts: f64,
    pub user: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_body: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_body: Option<serde_json::Value>,
    #[serde(default)]
    pub latency_ms: f64,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default = "default_role")]
    pub role: String,
}

impl Record {
    pub fn new(
        ts: f64,
        user: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            ts,
            user: user.into(),
            method: method.into(),
            path: path.into(),
            status,
            req_body: None,
            resp_body: None,
            latency_ms: 0.0,
            src_ip: String::new(),
            role: default_role(),
        }
    }

    /// Check if the HTTP response indicates success (2xx).
    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Check if the caller identity is unauthenticated or anonymous.
    pub fn is_anonymous(&self) -> bool {
        self.user == crate::auth::DEFAULT_ANONYMOUS_USER
    }

    /// Check if this record represents an orphan/unmatched response (e.g. captured mid-session).
    pub fn is_orphan(&self) -> bool {
        self.method == "UNKNOWN"
    }

    /// Check if this record contains a request body.
    pub fn has_request_body(&self) -> bool {
        self.req_body.is_some()
    }

    /// Check if this record contains a response body.
    pub fn has_response_body(&self) -> bool {
        self.resp_body.is_some()
    }

    /// Serialize record to compact JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize record from JSON string, ignoring unknown fields automatically.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

fn default_max_pending_requests() -> usize {
    1024
}

/// Configurable limits to protect parser against excessive memory usage and resource exhaustion attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserLimits {
    pub max_header_size: usize,
    pub max_body_size: usize,
    pub max_chunk_size: usize,
    pub max_headers_count: usize,
    pub max_line_length: usize,
    #[serde(default = "default_max_pending_requests")]
    pub max_pending_requests: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_header_size: 64 * 1024,       // 64 KB
            max_body_size: 10 * 1024 * 1024,  // 10 MB
            max_chunk_size: 10 * 1024 * 1024, // 10 MB
            max_headers_count: 100,           // 100 headers
            max_line_length: 8192,            // 8 KB
            max_pending_requests: default_max_pending_requests(),
        }
    }
}

impl ParserLimits {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    pub fn with_max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }

    pub fn with_max_headers_count(mut self, count: usize) -> Self {
        self.max_headers_count = count;
        self
    }

    pub fn with_max_line_length(mut self, length: usize) -> Self {
        self.max_line_length = length;
        self
    }

    pub fn with_max_pending_requests(mut self, count: usize) -> Self {
        self.max_pending_requests = count;
        self
    }
}

/// Categorized classification of parser and reassembly errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserErrorKind {
    /// Incomplete message; waiting for additional TCP fragments.
    IncompleteData,
    /// Malformed HTTP request line or response status line.
    MalformedStartLine,
    /// Invalid HTTP header syntax (missing colon, empty name, bare CR, whitespace before colon).
    InvalidHeader,
    /// Framing or body decoding error (conflicting Content-Length, invalid chunked encoding).
    FramingOrBodyError,
    /// Configurable `ParserLimits` violation (oversized header, line, count, or body).
    LimitViolation,
    /// Stream reassembly failure (orphan response, pending queue overflow, unrecoverable stream error).
    ReassemblyFailure,
}

impl ParserErrorKind {
    /// Return a stable snake_case string representation for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            ParserErrorKind::IncompleteData => "incomplete_data",
            ParserErrorKind::MalformedStartLine => "malformed_start_line",
            ParserErrorKind::InvalidHeader => "invalid_header",
            ParserErrorKind::FramingOrBodyError => "framing_or_body_error",
            ParserErrorKind::LimitViolation => "limit_violation",
            ParserErrorKind::ReassemblyFailure => "reassembly_failure",
        }
    }
}

impl fmt::Display for ParserErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Bounded, redacted diagnostic entry for parser and reassembly debugging.
/// Never exposes JWTs, API keys, authorization headers, or request/response bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserDiagnostic {
    pub ts: f64,
    pub connection_id: String,
    pub direction: TrafficDirection,
    pub kind: ParserErrorKind,
    pub message: String,
}

/// Classify a parser error message into a deterministic `ParserErrorKind`.
pub fn classify_error_message(msg: &str) -> ParserErrorKind {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("exceeds maximum")
        || lower.contains("limit")
        || lower.contains("queue overflow")
    {
        ParserErrorKind::LimitViolation
    } else if lower.contains("chunk")
        || lower.contains("content-length")
        || lower.contains("framing")
    {
        ParserErrorKind::FramingOrBodyError
    } else if lower.contains("header")
        || lower.contains("colon")
        || lower.contains("whitespace disallowed")
        || (lower.contains("bare cr") && lower.contains("header"))
    {
        ParserErrorKind::InvalidHeader
    } else if lower.contains("request line")
        || lower.contains("status line")
        || lower.contains("response line")
        || lower.contains("http method")
        || lower.contains("http version")
        || lower.contains("status code")
    {
        ParserErrorKind::MalformedStartLine
    } else if lower.contains("orphan") || lower.contains("reassembly") {
        ParserErrorKind::ReassemblyFailure
    } else {
        ParserErrorKind::ReassemblyFailure
    }
}

/// Produce a bounded, sanitized preview of raw diagnostic text.
///
/// Security guarantees:
/// - Strips ASCII control characters (`\r`, `\n`, `\0`, etc.) to prevent log injection.
/// - Redacts JWT-like tokens (`eyJ...` or 3-part dot-separated tokens).
/// - Redacts sensitive credential headers/parameters (`authorization`, `bearer`, `x-api-key`, `api-key`, `x-auth-token`, `cookie`, `secret`, `password`, `token`).
/// - Strictly bounds output length to `max_len` characters (UTF-8 boundary safe).
pub fn redact_sensitive_preview(raw: &str, max_len: usize) -> String {
    if max_len == 0 || raw.is_empty() {
        return String::new();
    }

    // 1. Strip control chars and normalize whitespace to single spaces
    let sanitized: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    let lower = sanitized.to_ascii_lowercase();

    // 2. Check for sensitive header/credential keywords
    const SENSITIVE_KEYWORDS: &[&str] = &[
        "authorization",
        "bearer ",
        "bearer\t",
        "x-api-key",
        "api-key",
        "api_key",
        "x-auth-token",
        "set-cookie",
        "cookie:",
        "password",
        "secret",
    ];

    for kw in SENSITIVE_KEYWORDS {
        if let Some(pos) = lower.find(kw) {
            let prefix: String = sanitized[..pos].chars().take(max_len).collect();
            let kw_clean = kw.trim();
            if prefix.is_empty() {
                return format!("[REDACTED:{}]", kw_clean);
            } else {
                return format!("{}[REDACTED:{}]", prefix, kw_clean);
            }
        }
    }

    // 3. Check for JWT-like patterns (e.g., "eyJ..." or 3 dot-separated base64 segments)
    let mut output_parts = Vec::new();
    for word in sanitized.split_whitespace() {
        let is_jwt_like = (word.starts_with("eyJ") && word.contains('.'))
            || (word.len() >= 24 && word.matches('.').count() == 2);
        if is_jwt_like {
            output_parts.push("[REDACTED_JWT]");
        } else if let Some(q_idx) = word.find('?') {
            // Strip query string in URL previews to avoid leaking ?token=... or ?api_key=...
            let base = &word[..q_idx];
            output_parts.push(base);
            output_parts.push("?[REDACTED_QUERY]");
        } else {
            output_parts.push(word);
        }
    }

    let joined = output_parts.join(" ");
    let char_count = joined.chars().count();
    if char_count > max_len {
        let truncated: String = joined.chars().take(max_len).collect();
        format!("{}...", truncated)
    } else {
        joined
    }
}
