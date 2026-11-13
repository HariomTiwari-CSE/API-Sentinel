//! Core HTTP/1.x Request Parsing Engine in Rust.
//!
//! Handles:
//! - Request-line parsing: method, URI/path, HTTP version.
//! - Case-insensitive HTTP header parsing.
//! - Content-Length and chunked Transfer-Encoding request body parsing.
//! - Safe JSON body decoding.
//! - Fault-tolerant handling of incomplete, malformed, and empty requests.

use std::collections::HashMap;
use crate::models::ParsedHTTPRequest;

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

/// Decode a chunked transfer-encoded payload.
/// Returns (decoded_bytes, wire_bytes_consumed, is_complete, error).
pub fn decode_chunked_body(payload: &[u8]) -> (Option<Vec<u8>>, usize, bool, Option<String>) {
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
        let size_str = match std::str::from_utf8(size_slice) {
            Ok(s) => s.trim(),
            Err(_) => return (None, 0, false, Some("Invalid UTF-8 in chunk size".to_string())),
        };

        let hex_str = if let Some(semi) = size_str.find(';') {
            &size_str[..semi].trim()
        } else {
            size_str
        };

        let chunk_size = match usize::from_str_radix(hex_str, 16) {
            Ok(size) => size,
            Err(_) => return (None, 0, false, Some(format!("Invalid chunk size hex: {}", hex_str))),
        };

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
            return (None, 0, false, None);
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
        } else {
            return (None, 0, false, None); // Incomplete chunk terminator
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
        // Fallback for non-utf8 binary data: string representation or raw bytes array
        Some(serde_json::Value::String(String::from_utf8_lossy(raw_bytes).to_string()))
    }
}

/// Parse a single HTTP/1.x request from a raw byte buffer.
pub fn parse_http_request(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> RequestParseResult {
    if data.is_empty() {
        return RequestParseResult {
            request: None,
            bytes_consumed: 0,
            is_complete: false,
            error: None,
        };
    }

    // 1. Locate headers boundary
    let (header_end, body_start) = match find_header_boundary(data) {
        Some((h_end, b_start)) => (h_end, b_start),
        None => {
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

    // 3. Parse Request-Line: METHOD PATH HTTP_VERSION
    let request_line = lines[0].trim();
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

    for line in &lines[1..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
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
        let (chunk_body, wire_consumed, complete, chunk_err) = decode_chunked_body(available_body);
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

    let parsed_req = ParsedHTTPRequest {
        method,
        path,
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

/// Parse all pipelined or consecutive requests present in a buffer.
pub fn parse_all_requests(
    data: &[u8],
    ts: f64,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> Vec<ParsedHTTPRequest> {
    let mut requests = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];
        let res = parse_http_request(remaining, ts, src_ip, src_port, dst_ip, dst_port);
        if !res.is_complete || res.request.is_none() || res.bytes_consumed == 0 {
            break;
        }
        requests.push(res.request.unwrap());
        offset += res.bytes_consumed;
    }

    requests
}
