//! Authentication and caller identity extraction utilities.
//!
//! Extracts caller identifier and role claims from HTTP headers (JWT Bearer tokens,
//! API keys, or custom headers) without adding heavyweight third-party crypto dependencies.

use std::collections::HashMap;

pub const DEFAULT_ANONYMOUS_USER: &str = "anonymous";
pub const DEFAULT_USER_ROLE: &str = "user";

/// Safely decode a base64url-encoded string (with or without padding).
pub fn decode_base64_url(input: &str) -> Result<Vec<u8>, String> {
    let clean = input.trim();
    let mut padded = clean.replace('-', "+").replace('_', "/");
    let rem = padded.len() % 4;
    if rem > 0 {
        padded.push_str(&"=".repeat(4 - rem));
    }

    let chars: Vec<u8> = padded.bytes().collect();
    let mut out = Vec::with_capacity(chars.len() * 3 / 4);

    let decode_val = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("Invalid base64 character: {}", b as char)),
        }
    };

    let mut i = 0;
    while i < chars.len() {
        if i + 4 > chars.len() {
            break;
        }
        let b0 = decode_val(chars[i])?;
        let b1 = decode_val(chars[i + 1])?;
        let b2 = decode_val(chars[i + 2])?;
        let b3 = decode_val(chars[i + 3])?;

        let o0 = (b0 << 2) | (b1 >> 4);
        out.push(o0);

        if chars[i + 2] != b'=' {
            let o1 = ((b1 & 0xF) << 4) | (b2 >> 2);
            out.push(o1);
        }
        if chars[i + 3] != b'=' {
            let o2 = ((b2 & 0x3) << 6) | b3;
            out.push(o2);
        }
        i += 4;
    }

    Ok(out)
}

/// Safely decode the unverified JSON payload from a JWT token.
pub fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload_bytes = decode_base64_url(parts[1]).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Extract user identity and role claim from normalized HTTP headers.
pub fn extract_identity_and_role(headers: &HashMap<String, String>) -> (String, String) {
    if headers.is_empty() {
        return (DEFAULT_ANONYMOUS_USER.to_string(), DEFAULT_USER_ROLE.to_string());
    }

    // Convert keys to lowercase for case-insensitive lookup
    let lower_headers: HashMap<String, &String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();

    // 1. Check Authorization Bearer JWT
    if let Some(auth) = lower_headers.get("authorization") {
        let auth_str = auth.trim();
        if auth_str.len() > 7 && auth_str[..7].eq_ignore_ascii_case("bearer ") {
            let token = auth_str[7..].trim();
            if let Some(claims) = decode_jwt_payload(token) {
                let user = claims.get("sub")
                    .or_else(|| claims.get("user"))
                    .or_else(|| claims.get("username"))
                    .or_else(|| claims.get("user_id"))
                    .or_else(|| claims.get("email"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| DEFAULT_ANONYMOUS_USER.to_string());

                let role = claims.get("role")
                    .or_else(|| claims.get("scope"))
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            Some(s.to_string())
                        } else if let Some(arr) = v.as_array() {
                            arr.first().and_then(|item| item.as_str()).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());

                return (user, role);
            }
        }
    }

    // 2. Check direct User-ID headers
    for user_header in &["x-user-id", "x-user", "x-username"] {
        if let Some(user_val) = lower_headers.get(*user_header) {
            let user = user_val.trim();
            if !user.is_empty() {
                let role = lower_headers
                    .get("x-user-role")
                    .or_else(|| lower_headers.get("x-role"))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());
                return (user.to_string(), role);
            }
        }
    }

    // 3. Check API-Key headers
    for key_header in &["x-api-key", "api-key", "x-auth-token"] {
        if let Some(key_val) = lower_headers.get(*key_header) {
            let key = key_val.trim();
            if !key.is_empty() {
                let key_id = if key.len() > 8 {
                    format!("key_{}", &key[..8])
                } else {
                    format!("key_{}", key)
                };
                let role = lower_headers
                    .get("x-role")
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());
                return (key_id, role);
            }
        }
    }

    (DEFAULT_ANONYMOUS_USER.to_string(), DEFAULT_USER_ROLE.to_string())
}

