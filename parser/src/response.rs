//! Core HTTP/1.x Response Parsing Engine in Rust.
//!
//! Handles:
//! - Response Status-Line parsing: HTTP version, status code, reason phrase.
//! - Case-insensitive HTTP response header parsing.
//! - Content-Length and chunked Transfer-Encoding response body parsing.
//! - Safe JSON body decoding.
//! - Special status code semantics (204 No Content, 304 Not Modified, 1xx).
//! - Fault-tolerant handling of incomplete, malformed, and empty responses.

use std::collections::HashMap;
use crate::models::ParsedHTTPResponse;
use crate::request::{decode_body_content, decode_chunked_body, find_header_boundary};

/// Result of attempting to parse an HTTP response from a byte buffer.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResponseParseResult {
    pub response: Option<ParsedHTTPResponse>,
    pub bytes_consumed: usize,
    pub is_complete: bool,
    pub error: Option<String>,
}

/// Parse a single HTTP/1.x response from a raw byte buffer.
pub fn parse_http_response(data: &[u8], ts: f64) -> ResponseParseResult {
    if data.is_empty() {
        return ResponseParseResult {
            response: None,
            bytes_consumed: 0,
            is_complete: false,
            error: None,
        };
    }

    // 1. Locate headers boundary
    let (header_end, body_start) = match find_header_boundary(data) {
        Some((h_end, b_start)) => (h_end, b_start),
        None => {
            // Check if first line exists to validate response line prefix
            if let Some(pos) = data.windows(2).position(|w| w == b"\r\n").or_else(|| data.iter().position(|&b| b == b'\n')) {
                let first_line = String::from_utf8_lossy(&data[..pos]);
                let trimmed = first_line.trim();
                if !trimmed.to_uppercase().starts_with("HTTP/") {
                    return ResponseParseResult {
                        response: None,
                        bytes_consumed: data.len(),
                        is_complete: false,
                        error: Some(format!("Malformed response line prefix: {}", trimmed)),
                    };
                }
            }
            return ResponseParseResult {
                response: None,
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
        return ResponseParseResult {
            response: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some("Empty response line".to_string()),
        };
    }

    // 3. Parse Status-Line: HTTP_VERSION STATUS_CODE [REASON_PHRASE]
    let status_line = lines[0].trim();
    let tokens: Vec<&str> = status_line.split_whitespace().collect();

    if tokens.len() < 2 {
        return ResponseParseResult {
            response: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some(format!("Malformed status line tokens: {}", status_line)),
        };
    }

    let http_version = tokens[0].to_string();
    if !http_version.to_uppercase().starts_with("HTTP/") {
        return ResponseParseResult {
            response: None,
            bytes_consumed: body_start,
            is_complete: false,
            error: Some(format!("Invalid HTTP version in status line: {}", tokens[0])),
        };
    }

    let status_code: u16 = match tokens[1].parse::<u16>() {
        Ok(code) if (100..=599).contains(&code) => code,
        _ => {
            return ResponseParseResult {
                response: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Invalid status code in status line: {}", tokens[1])),
            };
        }
    };

    let status_text = if tokens.len() >= 3 {
        tokens[2..].join(" ")
    } else {
        default_status_text(status_code).to_string()
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

            headers
                .entry(h_name)
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(&h_val);
                })
                .or_insert(h_val);
        }
    }

    // 5. Determine Body Boundaries
    // RFC 7230 §3.3.3: 1xx, 204, 304 MUST NOT include a message body.
    let available_body = &data[body_start..];
    let (raw_body_bytes, total_consumed) = if status_code == 204 || status_code == 304 || (100..200).contains(&status_code) {
        (Vec::new(), body_start)
    } else if is_chunked {
        let (chunk_body, wire_consumed, complete, chunk_err) = decode_chunked_body(available_body);
        if let Some(err) = chunk_err {
            return ResponseParseResult {
                response: None,
                bytes_consumed: body_start,
                is_complete: false,
                error: Some(format!("Chunked encoding error: {}", err)),
            };
        }
        if !complete {
            return ResponseParseResult {
                response: None,
                bytes_consumed: 0,
                is_complete: false,
                error: None,
            };
        }
        (chunk_body.unwrap_or_default(), body_start + wire_consumed)
    } else if let Some(cl) = content_length {
        if available_body.len() < cl {
            // Incomplete body, need more packets
            return ResponseParseResult {
                response: None,
                bytes_consumed: 0,
                is_complete: false,
                error: None,
            };
        }
        (available_body[..cl].to_vec(), body_start + cl)
    } else {
        // Without Content-Length or chunked encoding, body is empty
        (Vec::new(), body_start)
    };

    // 6. Decode Body safely
    let decoded_body = decode_body_content(&raw_body_bytes, &content_type);

    let parsed_resp = ParsedHTTPResponse {
        status: status_code,
        status_text,
        http_version,
        headers,
        body: decoded_body,
        ts,
    };

    ResponseParseResult {
        response: Some(parsed_resp),
        bytes_consumed: total_consumed,
        is_complete: true,
        error: None,
    }
}

/// Helper to provide standard HTTP reason phrase if missing.
fn default_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Parse all pipelined or consecutive responses present in a buffer.
pub fn parse_all_responses(data: &[u8], ts: f64) -> Vec<ParsedHTTPResponse> {
    let mut responses = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];
        let res = parse_http_response(remaining, ts);
        if !res.is_complete || res.response.is_none() || res.bytes_consumed == 0 {
            break;
        }
        responses.push(res.response.unwrap());
        offset += res.bytes_consumed;
    }

    responses
}
