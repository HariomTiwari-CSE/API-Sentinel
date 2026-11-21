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
    let unpadded = clean.trim_end_matches('=');
    if unpadded.is_empty() {
        return Ok(Vec::new());
    }
    if unpadded.len() % 4 == 1 {
        return Err("Invalid base64 length".to_string());
    }

    let mut padded = unpadded.replace('-', "+").replace('_', "/");
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
            _ => Err("Invalid base64 character".to_string()),
        }
    };

    let mut i = 0;
    while i < chars.len() {
        if i + 4 > chars.len() {
            break;
        }

        // Padding validation within a 4-byte block
        if chars[i] == b'=' || chars[i + 1] == b'=' {
            return Err("Invalid base64 padding".to_string());
        }
        if chars[i + 2] == b'=' && chars[i + 3] != b'=' {
            return Err("Invalid base64 padding".to_string());
        }
        if (chars[i + 2] == b'=' || chars[i + 3] == b'=') && i + 4 < chars.len() {
            return Err("Invalid base64 padding".to_string());
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
///
/// Ensures:
/// 1. The token has 2 or 3 parts (`header.payload` or `header.payload.signature`).
/// 2. Payload is valid Base64URL and valid JSON.
/// 3. RFC 7519 Section 4: The JWT claims set MUST be a JSON object (primitives/arrays rejected).
/// 4. Oversized tokens (>64KB) are rejected to prevent DoS.
pub fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let clean = token.trim();
    if clean.is_empty() || clean.len() > 64 * 1024 {
        return None;
    }

    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }

    let payload_str = parts[1].trim();
    if payload_str.is_empty() {
        return None;
    }

    let payload_bytes = decode_base64_url(payload_str).ok()?;
    let val: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    if val.is_object() {
        Some(val)
    } else {
        None
    }
}

/// Extract user identity and role claim from normalized HTTP headers.
///
/// ### Deterministic Precedence Hierarchy:
/// 1. **Tier 1 (Highest): Authorization Bearer JWT**
///    - If valid Bearer JWT is present:
///      - `user`: `sub` > `user` > `username` > `user_id` > `email` (string or integer)
///      - `role`: `role` > `scope` (string or array)
///      - If JWT role is absent: fallback to `X-User-Role` / `X-Role` headers before defaulting to `"user"`
///      - If JWT user is absent: defaults to `"anonymous"`
/// 2. **Tier 2: Direct User Headers (`X-User-Id`, `X-User`, `X-Username`)**
///    - Evaluated if Bearer JWT is missing, malformed, or invalid.
///    - `role`: `X-User-Role` > `X-Role` > `"user"`
/// 3. **Tier 3: API-Key Headers (`X-API-Key`, `api-key`, `X-Auth-Token`)**
///    - Evaluated if neither Tier 1 nor Tier 2 yielded an identity.
///    - Identity formatted as `key_<prefix>` (first 8 Unicode chars).
///    - `role`: `X-Role` > `X-User-Role` > `"user"`
/// 4. **Tier 4 (Lowest): Anonymous Fallback**
///    - Returns `("anonymous", "user")`.
pub fn extract_identity_and_role(headers: &HashMap<String, String>) -> (String, String) {
    if headers.is_empty() {
        return (
            DEFAULT_ANONYMOUS_USER.to_string(),
            DEFAULT_USER_ROLE.to_string(),
        );
    }

    // Normalize keys to lowercase; if duplicate casings exist, prefer non-empty values
    let mut lower_headers: HashMap<String, String> = HashMap::with_capacity(headers.len());
    for (k, v) in headers {
        let lk = k.to_lowercase();
        let trimmed = v.trim();
        match lower_headers.get(&lk) {
            None => {
                lower_headers.insert(lk, trimmed.to_string());
            }
            Some(existing) if existing.is_empty() && !trimmed.is_empty() => {
                lower_headers.insert(lk, trimmed.to_string());
            }
            _ => {}
        }
    }

    let get_first_header = |names: &[&str]| -> Option<&str> {
        for name in names {
            if let Some(val) = lower_headers.get(*name) {
                if !val.is_empty() {
                    return Some(val.as_str());
                }
            }
        }
        None
    };

    // 1. Tier 1: Check Authorization Bearer JWT
    if let Some(auth_val) = lower_headers.get("authorization") {
        let auth_str = auth_val.trim();
        let is_bearer = if auth_str.len() >= 6 && auth_str[..6].eq_ignore_ascii_case("bearer") {
            if auth_str.len() == 6 {
                false
            } else {
                let rest = &auth_str[6..];
                rest.starts_with(' ') || rest.starts_with('\t')
            }
        } else {
            false
        };

        if is_bearer {
            let token = auth_str[6..].trim();
            if !token.is_empty() {
                if let Some(claims) = decode_jwt_payload(token) {
                    let user_opt = claims
                        .get("sub")
                        .or_else(|| claims.get("user"))
                        .or_else(|| claims.get("username"))
                        .or_else(|| claims.get("user_id"))
                        .or_else(|| claims.get("email"))
                        .and_then(|v| {
                            if let Some(s) = v.as_str() {
                                let trimmed = s.trim();
                                if !trimmed.is_empty() {
                                    Some(trimmed.to_string())
                                } else {
                                    None
                                }
                            } else if let Some(n) = v.as_i64() {
                                Some(n.to_string())
                            } else if let Some(u) = v.as_u64() {
                                Some(u.to_string())
                            } else {
                                None
                            }
                        });

                    let role_opt = claims
                        .get("role")
                        .or_else(|| claims.get("scope"))
                        .and_then(|v| {
                            if let Some(s) = v.as_str() {
                                let trimmed = s.trim();
                                if !trimmed.is_empty() {
                                    Some(trimmed.to_string())
                                } else {
                                    None
                                }
                            } else if let Some(arr) = v.as_array() {
                                arr.iter().find_map(|item| {
                                    item.as_str().and_then(|s| {
                                        let trimmed = s.trim();
                                        if !trimmed.is_empty() {
                                            Some(trimmed.to_string())
                                        } else {
                                            None
                                        }
                                    })
                                })
                            } else {
                                None
                            }
                        });

                    let role = role_opt
                        .or_else(|| {
                            get_first_header(&["x-user-role", "x-role"])
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());

                    let user = user_opt.unwrap_or_else(|| DEFAULT_ANONYMOUS_USER.to_string());

                    return (user, role);
                }
            }
        }
    }

    // 2. Tier 2: Check direct User-ID headers
    if let Some(user_val) = get_first_header(&["x-user-id", "x-user", "x-username"]) {
        let role = get_first_header(&["x-user-role", "x-role"])
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());
        return (user_val.to_string(), role);
    }

    // 3. Tier 3: Check API-Key headers
    if let Some(key_val) = get_first_header(&["x-api-key", "api-key", "x-auth-token"]) {
        let prefix: String = key_val.chars().take(8).collect();
        let key_id = format!("key_{}", prefix);
        let role = get_first_header(&["x-role", "x-user-role"])
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_USER_ROLE.to_string());
        return (key_id, role);
    }

    // 4. Tier 4: Fallback
    (
        DEFAULT_ANONYMOUS_USER.to_string(),
        DEFAULT_USER_ROLE.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_url_clean_and_unpadded() {
        assert_eq!(decode_base64_url("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_base64_url("YQ").unwrap(), b"a");
        assert_eq!(decode_base64_url("YWI").unwrap(), b"ab");
        assert_eq!(decode_base64_url("YWJj").unwrap(), b"abc");
        assert_eq!(decode_base64_url("YWJjZA").unwrap(), b"abcd");
    }

    #[test]
    fn test_decode_base64_url_with_padding() {
        assert_eq!(decode_base64_url("YQ==").unwrap(), b"a");
        assert_eq!(decode_base64_url("YWI=").unwrap(), b"ab");
        assert_eq!(decode_base64_url("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn test_decode_base64_url_invalid_length_or_chars() {
        assert!(decode_base64_url("Y").is_err());
        assert!(decode_base64_url("YWJjZ").is_err());
        let err = decode_base64_url("Y@==").unwrap_err();
        // Secrets / characters are NOT leaked in error
        assert!(!err.contains('@'));
        assert_eq!(err, "Invalid base64 character");
    }

    #[test]
    fn test_decode_jwt_payload_non_object_rejected() {
        // String primitive: "hello" -> Base64URL: ImhlbGxvIg
        assert!(decode_jwt_payload("header.ImhlbGxvIg.sig").is_none());
        // Number primitive: 12345 -> Base64URL: MTIzNDU
        assert!(decode_jwt_payload("header.MTIzNDU.sig").is_none());
        // Array: [1, 2] -> Base64URL: WzEsIDJd
        assert!(decode_jwt_payload("header.WzEsIDJd.sig").is_none());
        // Boolean: true -> Base64URL: dHJ1ZQ
        assert!(decode_jwt_payload("header.dHJ1ZQ.sig").is_none());
    }
}
