//! Core HTTP/1.x Request Parsing Engine in Rust.
//!
//! Handles:
//! - Request-line parsing: method, URI/path, HTTP version.
//! - Case-insensitive HTTP header parsing.
//! - Content-Length and chunked Transfer-Encoding request body parsing.
//! - Hardened against malformed chunk extensions, invalid line breaks, and trailing garbage.
//! - Memory exhaustion protection via configurable `ParserLimits`.
//! - Safe JSON body decoding.
//! - Fault-tolerant handling of incomplete, malformed, and empty requests.

use std::collections::HashMap;
use crate::models::{ParsedHTTPRequest, ParserLimits};

/// Result of attempting to parse an HTTP request from a byte buffer.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestParseResult {
    pub request: Option<ParsedHTTPRequest>,
    pub bytes_consumed: usize,
    pub is_complete: bool,
    pub error: Option<String>,
}

/// Standard known HTTP methods.
pub const STANDARD_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Find the boundary separating HTTP headers from the body.
/// Returns (header_end_offset, body_start_offset).
pub fn find_header_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    if let Some(pos) = buf.windows(2).position(|window| window == b"\n\n") {
        return Some((pos, pos + 2));
    }
    None
}

/// Decode a chunked transfer-encoded payload using default limits.
pub fn decode_chunked_body(payload: &[u8]) -> (Option<Vec<u8>>, usize, bool, Option<String>) {
    decode_chunked_body_with_limits(payload, &ParserLimits::default())
}

/// Decode a chunked transfer-encoded payload with strict limits and edge-case hardening.
///
/// Hardened against:
/// - Malformed chunk extensions (invalid control characters, excessive length)
/// - Invalid hex characters, signed hex numbers (+/-), and "0x" prefixes
/// - Invalid line breaks (bare CR without LF)
/// - Excessive chunk size or total accumulated body size exceeding limits
/// Returns (decoded_bytes, wire_bytes_consumed, is_complete, error).
pub fn decode_chunked_body_with_limits(
    payload: &[u8],
    limits: &ParserLimits,
) -> (Option<Vec<u8>>, usize, bool, Option<String>) {
    let mut offset = 0;
    let mut body_chunks = Vec::new();

    while offset < payload.len() {
        let remaining = &payload[offset..];
        let (line_end, delim_len) = if let Some(pos) = remaining.windows(2).position(|w| w == b"\r\n") {
            (pos, 2)
        } else if let Some(pos) = remaining.iter().position(|&b| b == b'\n') {
            (pos, 1)
        } else {
            return (None, 0, false, None); // Incomplete chunk header line
        };

        let size_slice = &remaining[..line_end];

        // Reject bare CR inside line per RFC 7230 §3.5
        if size_slice.contains(&b'\r') {
            return (None, 0, false, Some("Invalid bare CR in chunk size line".to_string()));
        }

        let size_str = match std::str::from_utf8(size_slice) {
            Ok(s) => s.trim(),
            Err(_) => return (None, 0, false, Some("Invalid UTF-8 in chunk size".to_string())),
        };

        // Separate chunk size from optional chunk extensions (;ext_name=ext_value)
        let (hex_str, extension) = if let Some(semi) = size_str.find(';') {
            (size_str[..semi].trim(), Some(&size_str[semi + 1..]))
        } else {
            (size_str, None)
        };

        if hex_str.is_empty() {
            return (None, 0, false, Some("Empty chunk size hex".to_string()));
        }

        // RFC 7230 §4.1: Chunk size must be unsigned hex digits without sign or 0x prefix
        if hex_str.starts_with('+') || hex_str.starts_with('-') {
            return (None, 0, false, Some(format!("Invalid signed chunk size hex: {}", hex_str)));
        }
        if hex_str.to_ascii_lowercase().starts_with("0x") {
            return (None, 0, false, Some(format!("Invalid 0x prefix in chunk size hex: {}", hex_str)));
        }
        if hex_str.chars().any(|c| !c.is_ascii_hexdigit()) {
            return (None, 0, false, Some(format!("Invalid non-hex character in chunk size: {}", hex_str)));
        }

        // Validate chunk extensions if present
        if let Some(ext) = extension {
            if ext.len() > limits.max_line_length {
                return (None, 0, false, Some("Chunk extension exceeds maximum allowed line length".to_string()));
            }
            // Disallow unescaped ASCII control characters
            if ext.chars().any(|c| (c as u32) < 0x20 && c != '\t') {
                return (None, 0, false, Some("Invalid control character in chunk extension".to_string()));
            }
        }

        let chunk_size = match usize::from_str_radix(hex_str, 16) {
            Ok(size) => size,
            Err(_) => return (None, 0, false, Some(format!("Failed to parse chunk size hex: {}", hex_str))),
        };

        // Enforce maximum chunk size
        if chunk_size > limits.max_chunk_size {
            return (None, 0, false, Some(format!("Chunk size {} exceeds limit {}", chunk_size, limits.max_chunk_size)));
        }

        // Enforce maximum accumulated body size
        if body_chunks.len().saturating_add(chunk_size) > limits.max_body_size {
            return (None, 0, false, Some(format!("Accumulated chunked body exceeds limit {}", limits.max_body_size)));
        }

        offset += line_end + delim_len;

        // Final chunk of size 0 marks completion
        if chunk_size == 0 {
            if offset <= payload.len() {
                let tail = &payload[offset..];
                if let Some(end_pos) = tail.windows(4).position(|w| w == b"\r\n\r\n") {
                    return (Some(body_chunks), offset + end_pos + 4, true, None);
                }
                if let Some(end_pos) = tail.windows(2).position(|w| w == b"\n\n") {
                    return (Some(body_chunks), offset + end_pos + 2, true, None);
                }
                if tail.starts_with(b"\r\n") {
                    return (Some(body_chunks), offset + 2, true, None);
                }
                if tail.starts_with(b"\n") {
                    return (Some(body_chunks), offset + 1, true, None);
                }
            }
            return (None, 0, false, None); // Incomplete chunk trailer
        }

        // Check if full chunk data is available
        if payload.len() < offset + chunk_size {
            return (None, 0, false, None); // Incomplete chunk body
        }

        body_chunks.extend_from_slice(&payload[offset..offset + chunk_size]);
        offset += chunk_size;

        // Skip trailing CRLF/LF after chunk data
        if payload.len() >= offset + 2 && &payload[offset..offset + 2] == b"\r\n" {
            offset += 2;
        } else if payload.len() >= offset + 1 && payload[offset] == b'\n' {
            offset += 1;
        } else if payload.len() >= offset + 1 && payload[offset] == b'\r' {
            return (None, 0, false, Some("Invalid bare CR following chunk body".to_string()));
        } else if payload.len() < offset + 1 {
            return (None, 0, false, None); // Incomplete chunk terminator
        } else {
            return (None, 0, false, Some("Missing CRLF chunk delimiter after chunk data".to_string()));
        }
    }

    (None, 0, false, None)
}

/// Decode raw request body into JSON value or keep as text/None.
pub fn decode_body_content(raw_bytes: &[u8], content_type: &str) -> Option<serde_json::Value> {
    if raw_bytes.is_empty() {
        return None;
    }

    if let Ok(text) = std::str::from_utf8(raw_bytes) {
        let trimmed = text.trim();
        let ct_lower = content_type.to_lowercase();
        let is_json_header = ct_lower.contains("application/json") || ct_lower.contains("+json");
        let looks_like_json = trimmed.starts_with('{') || trimmed.starts_with('[');

        if is_json_header || looks_like_json {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return Some(val);
            }
        }
        Some(serde_json::Value::String(text.to_string()))
    } else {
        Some(serde_json::Value::String(String::from_utf8_lossy(raw_bytes).to_string()))
    }
}

/// Decode a percent-encoded URL component (key or value).
///
/// Converts `+` to space (' ') and decodes `%XX` hex sequences.
/// Preserves malformed percent sequences gracefully without panicking.
pub fn decode_url_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                    let hex_str = match std::str::from_utf8(&bytes[i + 1..i + 3]) {
                        Ok(h) => h,
                        Err(_) => {
                            decoded.push(b'%');
                            i += 1;
                            continue;
                        }
                    };
                    if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                        decoded.push(byte);
                        i += 3;
                    } else {
                        decoded.push(b'%');
                        i += 1;
                    }
                } else {
                    decoded.push(b'%');
                    i += 1;
                }
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).to_string()
}

/// Parse a query string into a map of keys to lists of values.
///
/// Supports repeated keys (e.g. `id=1&id=2`), empty values, missing `=` (e.g. `flag`),
/// percent-decoding, and proper `+` space decoding.
pub fn parse_query_params(query_str: &str) -> HashMap<String, Vec<String>> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    let trimmed = query_str.trim().trim_start_matches('?');
    if trimmed.is_empty() {
        return params;
    }

    for segment in trimmed.split('&') {
        let seg = segment.trim();
        if seg.is_empty() {
            continue;
        }

        let (raw_key, raw_val) = match seg.split_once('=') {
            Some((k, v)) => (k, v),
            None => (seg, ""),
        };

        let key = decode_url_component(raw_key.trim());
        let val = decode_url_component(raw_val.trim());

        if !key.is_empty() {
            params.entry(key).or_default().push(val);
        }
    }

    params
}

/// Extract base path and query parameters from a full URI.
pub fn parse_uri_query(uri: &str) -> (String, HashMap<String, Vec<String>>) {
    let uri_no_frag = if let Some(frag_pos) = uri.find('#') {
        &uri[..frag_pos]
    } else {
        uri
    };

    if let Some(q_pos) = uri_no_frag.find('?') {
        let base_path = uri_no_frag[..q_pos].to_string();
        let query_str = &uri_no_frag[q_pos + 1..];
        (base_path, parse_query_params(query_str))
    } else {
        (uri_no_frag.to_string(), HashMap::new())
    }
}


/// Parse a single HTTP/1.x request from a raw byte buffer using default limits.
pub fn parse_http_request(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> RequestParseResult {
    parse_http_request_with_limits(data, ts, src_ip, src_port, dst_ip, dst_port, &ParserLimits::default())
}

/// Parse a single HTTP/1.x request with configurable limits.
pub fn parse_http_request_with_limits(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    limits: &ParserLimits,
) -> RequestParseResult {
    if data.is_empty() {
        return RequestParseResult {
            request: None,
            bytes_consumed: 0,
            is_complete: false,
            error: None,
        };
    }

    // 1. Locate headers boundary with slowloris / max-size defense
    let (header_end, body_start) = match find_header_boundary(data) {
        Some((h_end, b_start)) => {
            if h_end > limits.max_header_size {
                return RequestParseResult {
                    request: None,
                    bytes_consumed: b_start,
                    is_complete: false,
                    error: Some(format!("Header section size {} exceeds maximum allowed limit {}", h_end, limits.max_header_size)),
                };
            }
            (h_end, b_start)
        }
        None => {
            // Memory limit defense: if buffer exceeds max_header_size without finding boundary, reject
            if data.len() > limits.max_header_size {
                return RequestParseResult {
                    request: None,
                    bytes_consumed: data.len(),
                    is_complete: false,
                    error: Some("Header size exceeds maximum allowed limit without delimiter".to_string()),
                };
            }

            // Check if first line exists but headers are incomplete
            if let Some(pos) = data.windows(2).position(|w| w == b"\r\n").or_else(|| data.iter().position(|&b| b == b'\n')) {
                let first_line = String::from_utf8_lossy(&data[..pos]);
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if let Some(method) = parts.first() {
                    let m_upper = method.to_uppercase();
                    if !STANDARD_HTTP_METHODS.contains(&m_upper.as_str()) {
                        return RequestParseResult {
                            request: None,
                            bytes_consumed: data.len(),
                            is_complete: false,
                            error: Some(format!("Malformed request line: {}", first_line)),
                        };
                    }
                }
            }
            return RequestParseResult {
                request: None,
                bytes_consumed: 0,
                is_complete: false,
                error: None,
            };
        }
    };

    // 2. Extract and parse header lines
    let headers_raw = String::from_utf8_lossy(&data[..header_end]);
    let lines: Vec<&str> = headers_raw.split('\n').map(|l| l.trim_end_matches('\r')).collect();

    if lines.is_empty() || lines[0].trim().is_empty() {
        return RequestParseResult {
            request: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some("Empty request line".to_string()),
        };
    }

    // Reject bare CR in request line
    if lines[0].contains('\r') {
        return RequestParseResult {
            request: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some("Invalid bare CR in request line".to_string()),
        };
    }

    // 3. Parse Request-Line: METHOD PATH HTTP_VERSION
    let request_line = lines[0].trim();
    if request_line.len() > limits.max_line_length {
        return RequestParseResult {
            request: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some("Request line exceeds maximum allowed length".to_string()),
        };
    }

    let tokens: Vec<&str> = request_line.split_whitespace().collect();

    let (method, path, http_version) = match tokens.len() {
        2 => (tokens[0].to_uppercase(), tokens[1].to_string(), "HTTP/1.1".to_string()),
        n if n >= 3 => {
            let m = tokens[0].to_uppercase();
            let v = tokens[tokens.len() - 1].to_string();
            let p = tokens[1..tokens.len() - 1].join(" ");
            (m, p, v)
        }
        _ => {
            return RequestParseResult {
                request: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Malformed request line tokens: {}", request_line)),
            };
        }
    };

    // 4. Parse Header Lines
    let mut headers = HashMap::new();
    let mut content_type = String::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut header_count = 0;

    for line in &lines[1..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.len() > limits.max_line_length {
            return RequestParseResult {
                request: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some("Header line exceeds maximum allowed length".to_string()),
            };
        }

        header_count += 1;
        if header_count > limits.max_headers_count {
            return RequestParseResult {
                request: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Header count exceeds maximum allowed limit {}", limits.max_headers_count)),
            };
        }

        if let Some((name, val)) = trimmed.split_once(':') {
            let h_name = name.trim().to_string();
            let h_val = val.trim().to_string();
            let lower_name = h_name.to_lowercase();

            if lower_name == "content-type" {
                content_type = h_val.clone();
            } else if lower_name == "content-length" {
                if let Ok(len) = h_val.parse::<usize>() {
                    content_length = Some(len);
                } else {
                    return RequestParseResult {
                        request: None,
                        bytes_consumed: body_start,
                        is_complete: false,
                        error: Some(format!("Invalid non-numeric Content-Length: {}", h_val)),
                    };
                }
            } else if lower_name == "transfer-encoding" && h_val.to_lowercase().contains("chunked") {
                is_chunked = true;
            }

            headers.entry(h_name)
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(&h_val);
                })
                .or_insert(h_val);
        }
    }

    // 5. Determine Body Boundaries and Transfer Encoding
    let available_body = &data[body_start..];
    let (raw_body_bytes, total_consumed) = if is_chunked {
        let (chunk_body, wire_consumed, complete, chunk_err) = decode_chunked_body_with_limits(available_body, limits);
        if let Some(err) = chunk_err {
            return RequestParseResult {
                request: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Chunked encoding error: {}", err)),
            };
        }
        if !complete {
            return RequestParseResult {
                request: None,
                bytes_consumed: 0,
                is_complete: false,
                error: None,
            };
        }
        (chunk_body.unwrap_or_default(), body_start + wire_consumed)
    } else if let Some(cl) = content_length {
        if cl > limits.max_body_size {
            return RequestParseResult {
                request: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Content-Length {} exceeds maximum allowed body limit {}", cl, limits.max_body_size)),
            };
        }
        if available_body.len() < cl {
            // Need more data
            return RequestParseResult {
                request: None,
                bytes_consumed: 0,
                is_complete: false,
                error: None,
            };
        }
        (available_body[..cl].to_vec(), body_start + cl)
    } else {
        (Vec::new(), body_start)
    };

    // 6. Decode Body
    let decoded_body = decode_body_content(&raw_body_bytes, &content_type);

    let (_, query_params) = parse_uri_query(&path);

    let parsed_req = ParsedHTTPRequest {
        method,
        path: path.clone(),
        raw_path: path,
        query_params,
        http_version,
        headers,
        body: decoded_body,
        ts,
        src_ip: src_ip.to_string(),
        src_port,
        dst_ip: dst_ip.to_string(),
        dst_port,
    };

    RequestParseResult {
        request: Some(parsed_req),
        bytes_consumed: total_consumed,
        is_complete: true,
        error: None,
    }
}

/// Parse all pipelined or consecutive requests present in a buffer using default limits.
pub fn parse_all_requests(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> Vec<ParsedHTTPRequest> {
    parse_all_requests_with_limits(data, ts, src_ip, src_port, dst_ip, dst_port, &ParserLimits::default())
}

/// Parse all pipelined or consecutive requests present in a buffer with limits.
pub fn parse_all_requests_with_limits(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    limits: &ParserLimits,
) -> Vec<ParsedHTTPRequest> {
    let mut requests = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];
        let res = parse_http_request_with_limits(remaining, ts, src_ip, src_port, dst_ip, dst_port, limits);
        if !res.is_complete || res.request.is_none() || res.bytes_consumed == 0 {
            break;
        }
        requests.push(res.request.unwrap());
        offset += res.bytes_consumed;
    }

    requests
}
