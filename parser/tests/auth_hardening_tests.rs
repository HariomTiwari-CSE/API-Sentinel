//! Day 9: Hardened Authentication & Identity Extraction Tests.
//!
//! Verifies:
//! 1. Malformed JWT handling (empty, missing dots, 4+ parts, invalid Base64URL, non-JSON bytes, primitives/arrays).
//! 2. JWT user claims (string sub, whitespace sub, empty sub, positive/zero/negative/u64 integers, fallback user claims).
//! 3. JWT role & scope claims (string role, array scope, whitespace trimming, fallback to explicit role headers, JWT role precedence).
//! 4. API-key and role headers (casing variations, whitespace trimming, empty/whitespace handling, short keys, UTF-8 multibyte).
//! 5. Deterministic precedence hierarchy (Tier 1 JWT > Tier 2 User-ID > Tier 3 API-Key > Tier 4 Anonymous).
//! 6. Zero secret leakage (error messages and logs never leak tokens or invalid characters).
//! 7. End-to-end integration through StreamReassembler and Record emission.

use api_sentinel_parser::{
    decode_base64_url, decode_jwt_payload, extract_identity_and_role, ConnectionKey, RawFragment,
    StreamReassembler, TrafficDirection, DEFAULT_ANONYMOUS_USER, DEFAULT_USER_ROLE,
};
use std::collections::HashMap;

/// Helper to create a base64url encoded string from raw bytes
fn to_base64_url(input: &[u8]) -> String {
    let base64_std = |b: &[u8]| -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            let b0 = b[i];
            let b1 = if i + 1 < b.len() { b[i + 1] } else { 0 };
            let b2 = if i + 2 < b.len() { b[i + 2] } else { 0 };

            out.push(CHARS[(b0 >> 2) as usize] as char);
            out.push(CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if i + 1 < b.len() {
                out.push(CHARS[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
            }
            if i + 2 < b.len() {
                out.push(CHARS[(b2 & 0x3F) as usize] as char);
            }
            i += 3;
        }
        out
    };

    base64_std(input).replace('+', "-").replace('/', "_")
}

fn build_jwt(claims_json: &str) -> String {
    let header_b64 = to_base64_url(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload_b64 = to_base64_url(claims_json.as_bytes());
    format!("{}.{}.mock_signature", header_b64, payload_b64)
}

// =========================================================================
// 1. Malformed JWT & Base64URL Resilience Tests
// =========================================================================

#[test]
fn test_malformed_jwt_structure_no_panic() {
    // Empty or whitespace
    assert!(decode_jwt_payload("").is_none());
    assert!(decode_jwt_payload("   ").is_none());

    // Missing dots (1 part)
    assert!(decode_jwt_payload("notajwtatall").is_none());

    // 1 dot only with empty/invalid payload
    assert!(decode_jwt_payload("header.").is_none());
    assert!(decode_jwt_payload(".payload").is_none());
    assert!(decode_jwt_payload(".").is_none());

    // More than 2 dots (4+ parts)
    assert!(decode_jwt_payload("a.b.c.d").is_none());
    assert!(decode_jwt_payload("header.payload.sig.extra.junk").is_none());

    // Consecutive dots
    assert!(decode_jwt_payload("header..signature").is_none());
    assert!(decode_jwt_payload("..").is_none());

    // Invalid Base64 characters in payload
    assert!(decode_jwt_payload("header.invalid*chars!here.sig").is_none());

    // Invalid Base64 length (% 4 == 1)
    assert!(decode_jwt_payload("header.Y.sig").is_none());

    // Invalid Base64 padding structure
    assert!(decode_jwt_payload("header.==AA.sig").is_none());
    assert!(decode_jwt_payload("header.A=AA.sig").is_none());

    // Oversized token (>64KB DoS prevention)
    let huge_token = format!("header.{}.sig", "A".repeat(70 * 1024));
    assert!(decode_jwt_payload(&huge_token).is_none());
}

#[test]
fn test_jwt_payload_non_object_primitives_rejected() {
    // RFC 7519 Section 4: A JWT Claims Set MUST be a JSON object

    // JSON Number: 12345
    let num_jwt = format!("header.{}.sig", to_base64_url(b"12345"));
    assert!(decode_jwt_payload(&num_jwt).is_none());

    // JSON Boolean: true
    let bool_jwt = format!("header.{}.sig", to_base64_url(b"true"));
    assert!(decode_jwt_payload(&bool_jwt).is_none());

    // JSON String: "just_a_string"
    let str_jwt = format!("header.{}.sig", to_base64_url(b"\"just_a_string\""));
    assert!(decode_jwt_payload(&str_jwt).is_none());

    // JSON Array: ["admin", "operator"]
    let arr_jwt = format!("header.{}.sig", to_base64_url(b"[\"admin\", \"operator\"]"));
    assert!(decode_jwt_payload(&arr_jwt).is_none());

    // JSON Null: null
    let null_jwt = format!("header.{}.sig", to_base64_url(b"null"));
    assert!(decode_jwt_payload(&null_jwt).is_none());

    // Plain non-JSON text: "this is not json at all"
    let text_jwt = format!("header.{}.sig", to_base64_url(b"this is not json at all"));
    assert!(decode_jwt_payload(&text_jwt).is_none());
}

// =========================================================================
// 2. JWT User Claim (`sub`) Variations & Fallbacks
// =========================================================================

#[test]
fn test_jwt_sub_string_variations() {
    // Normal string sub
    let mut h = HashMap::new();
    h.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"alice_99\"}")),
    );
    let (u, r) = extract_identity_and_role(&h);
    assert_eq!(u, "alice_99");
    assert_eq!(r, DEFAULT_USER_ROLE);

    // Padded string sub (whitespace trimming)
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"   bob_padded   \"}")),
    );
    let (u2, _) = extract_identity_and_role(&h2);
    assert_eq!(u2, "bob_padded");

    // Empty string sub -> falls back to anonymous
    let mut h3 = HashMap::new();
    h3.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"\"}")),
    );
    let (u3, _) = extract_identity_and_role(&h3);
    assert_eq!(u3, DEFAULT_ANONYMOUS_USER);

    // Whitespace only sub -> falls back to anonymous
    let mut h4 = HashMap::new();
    h4.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"    \"}")),
    );
    let (u4, _) = extract_identity_and_role(&h4);
    assert_eq!(u4, DEFAULT_ANONYMOUS_USER);
}

#[test]
fn test_jwt_sub_numeric_integers() {
    // Positive integer
    let mut h1 = HashMap::new();
    h1.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": 10024}")),
    );
    let (u1, _) = extract_identity_and_role(&h1);
    assert_eq!(u1, "10024");

    // Zero integer
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": 0}")),
    );
    let (u2, _) = extract_identity_and_role(&h2);
    assert_eq!(u2, "0");

    // Negative integer
    let mut h3 = HashMap::new();
    h3.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": -42}")),
    );
    let (u3, _) = extract_identity_and_role(&h3);
    assert_eq!(u3, "-42");

    // Large unsigned integer
    let mut h4 = HashMap::new();
    h4.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": 18446744073709551615}")),
    );
    let (u4, _) = extract_identity_and_role(&h4);
    assert_eq!(u4, "18446744073709551615");
}

#[test]
fn test_jwt_fallback_user_claims_when_sub_absent() {
    // "user" claim fallback
    let mut h1 = HashMap::new();
    h1.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"user\": \"carol_sec\"}")),
    );
    let (u1, _) = extract_identity_and_role(&h1);
    assert_eq!(u1, "carol_sec");

    // "username" claim fallback
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"username\": \"dave_ops\"}")),
    );
    let (u2, _) = extract_identity_and_role(&h2);
    assert_eq!(u2, "dave_ops");

    // "user_id" numeric fallback
    let mut h3 = HashMap::new();
    h3.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"user_id\": 7788}")),
    );
    let (u3, _) = extract_identity_and_role(&h3);
    assert_eq!(u3, "7788");

    // "email" fallback
    let mut h4 = HashMap::new();
    h4.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"email\": \"eve@sentinel.io\"}")),
    );
    let (u4, _) = extract_identity_and_role(&h4);
    assert_eq!(u4, "eve@sentinel.io");

    // Non-string / non-integer sub (e.g. float, bool, array, object) -> safely anonymous
    let mut h5 = HashMap::new();
    h5.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": 12.345}")),
    );
    let (u5, _) = extract_identity_and_role(&h5);
    assert_eq!(u5, DEFAULT_ANONYMOUS_USER);
}

// =========================================================================
// 3. JWT Role & Scope Claim Variations
// =========================================================================

#[test]
fn test_jwt_role_and_scope_claims() {
    // Direct string role
    let mut h1 = HashMap::new();
    h1.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"role\": \"admin\"}")
        ),
    );
    let (_, r1) = extract_identity_and_role(&h1);
    assert_eq!(r1, "admin");

    // Whitespace role trimmed
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"role\": \"   auditor   \"}")
        ),
    );
    let (_, r2) = extract_identity_and_role(&h2);
    assert_eq!(r2, "auditor");

    // Array scope: first non-empty string item
    let mut h3 = HashMap::new();
    h3.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"scope\": [\"read_only\", \"write\"]}")
        ),
    );
    let (_, r3) = extract_identity_and_role(&h3);
    assert_eq!(r3, "read_only");

    // Array scope with leading empty strings
    let mut h4 = HashMap::new();
    h4.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"scope\": [\"\", \"   \", \"operator\"]}")
        ),
    );
    let (_, r4) = extract_identity_and_role(&h4);
    assert_eq!(r4, "operator");

    // Single string scope
    let mut h5 = HashMap::new();
    h5.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"scope\": \"metrics_collector\"}")
        ),
    );
    let (_, r5) = extract_identity_and_role(&h5);
    assert_eq!(r5, "metrics_collector");

    // Empty array or invalid scope -> defaults to user role
    let mut h6 = HashMap::new();
    h6.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"u1\", \"scope\": [123, null]}")
        ),
    );
    let (_, r6) = extract_identity_and_role(&h6);
    assert_eq!(r6, DEFAULT_USER_ROLE);
}

#[test]
fn test_jwt_role_and_header_role_interaction() {
    // 1. JWT has role, header has X-Role -> JWT role wins (Tier 1 precedence)
    let mut h1 = HashMap::new();
    h1.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"alice\", \"role\": \"jwt_admin\"}")
        ),
    );
    h1.insert("X-Role".to_string(), "header_guest".to_string());
    let (u1, r1) = extract_identity_and_role(&h1);
    assert_eq!(u1, "alice");
    assert_eq!(r1, "jwt_admin");

    // 2. JWT lacks role, header has X-User-Role -> Header role is adopted
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"bob\"}")),
    );
    h2.insert("X-User-Role".to_string(), "header_auditor".to_string());
    let (u2, r2) = extract_identity_and_role(&h2);
    assert_eq!(u2, "bob");
    assert_eq!(r2, "header_auditor");

    // 3. JWT lacks role, header has X-Role -> Header role is adopted
    let mut h3 = HashMap::new();
    h3.insert(
        "Authorization".to_string(),
        format!("Bearer {}", build_jwt("{\"sub\": \"carol\"}")),
    );
    h3.insert("x-role".to_string(), "header_service".to_string());
    let (u3, r3) = extract_identity_and_role(&h3);
    assert_eq!(u3, "carol");
    assert_eq!(r3, "header_service");
}

// =========================================================================
// 4. API-Key & Role Headers: Casing, Whitespace, & Resilience
// =========================================================================

#[test]
fn test_api_key_casing_and_header_variants() {
    let variants = [
        "X-API-KEY",
        "x-api-key",
        "X-Api-Key",
        "API-KEY",
        "api-key",
        "X-AUTH-TOKEN",
        "x-auth-token",
        "X-Auth-Token",
    ];

    for header_name in &variants {
        let mut h = HashMap::new();
        h.insert(
            header_name.to_string(),
            "secret_prod_token_9999".to_string(),
        );
        let (u, r) = extract_identity_and_role(&h);
        assert_eq!(
            u, "key_secret_p",
            "Failed for header casing: {}",
            header_name
        );
        assert_eq!(r, DEFAULT_USER_ROLE);
    }
}

#[test]
fn test_api_key_whitespace_and_empty_values() {
    // Leading and trailing whitespace trimming
    let mut h1 = HashMap::new();
    h1.insert(
        "X-API-Key".to_string(),
        "   live_token_secret_123   ".to_string(),
    );
    h1.insert("X-Role".to_string(), "   admin_operator   ".to_string());
    let (u1, r1) = extract_identity_and_role(&h1);
    assert_eq!(u1, "key_live_tok");
    assert_eq!(r1, "admin_operator");

    // Empty API key -> falls back to anonymous
    let mut h2 = HashMap::new();
    h2.insert("X-API-Key".to_string(), "".to_string());
    let (u2, r2) = extract_identity_and_role(&h2);
    assert_eq!(u2, DEFAULT_ANONYMOUS_USER);
    assert_eq!(r2, DEFAULT_USER_ROLE);

    // Whitespace-only API key -> falls back to anonymous
    let mut h3 = HashMap::new();
    h3.insert("X-API-Key".to_string(), "     ".to_string());
    let (u3, r3) = extract_identity_and_role(&h3);
    assert_eq!(u3, DEFAULT_ANONYMOUS_USER);
    assert_eq!(r3, DEFAULT_USER_ROLE);

    // Short API key (< 8 characters)
    let mut h4 = HashMap::new();
    h4.insert("X-API-Key".to_string(), "abc".to_string());
    let (u4, _) = extract_identity_and_role(&h4);
    assert_eq!(u4, "key_abc");

    // Multibyte UTF-8 characters in API key
    let mut h5 = HashMap::new();
    h5.insert("X-API-Key".to_string(), "🛡️🛡️🛡️secret_token".to_string());
    let (u5, _) = extract_identity_and_role(&h5);
    assert!(u5.starts_with("key_"));
    // Valid Unicode slicing without panic
    assert!(u5.len() > 4);
}

#[test]
fn test_header_casing_deduplication_prefers_non_empty() {
    // If headers has duplicate casings where one is empty/whitespace, prefer the populated one
    let mut h = HashMap::new();
    h.insert("X-API-KEY".to_string(), "   ".to_string());
    h.insert("x-api-key".to_string(), "valid_secret_key_888".to_string());
    let (u, _) = extract_identity_and_role(&h);
    assert_eq!(u, "key_valid_se");

    let mut h2 = HashMap::new();
    h2.insert("X-User-Role".to_string(), "".to_string());
    h2.insert("x-role".to_string(), "database_admin".to_string());
    h2.insert("X-User-ID".to_string(), "admin_alex".to_string());
    let (u2, r2) = extract_identity_and_role(&h2);
    assert_eq!(u2, "admin_alex");
    assert_eq!(r2, "database_admin");
}

// =========================================================================
// 5. Deterministic Precedence Hierarchy
// =========================================================================

#[test]
fn test_deterministic_precedence_tier1_jwt_over_tier2_and_tier3() {
    let mut h = HashMap::new();
    // Tier 1: JWT
    h.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            build_jwt("{\"sub\": \"jwt_caller\", \"role\": \"jwt_role\"}")
        ),
    );
    // Tier 2: Direct User ID
    h.insert("X-User-Id".to_string(), "header_caller".to_string());
    h.insert("X-User-Role".to_string(), "header_user_role".to_string());
    // Tier 3: API Key
    h.insert("X-API-Key".to_string(), "apikey_caller_secret".to_string());
    h.insert("X-Role".to_string(), "apikey_role".to_string());

    let (u, r) = extract_identity_and_role(&h);
    assert_eq!(
        u, "jwt_caller",
        "Tier 1 JWT must take precedence for identity"
    );
    assert_eq!(r, "jwt_role", "Tier 1 JWT role must take precedence");
}

#[test]
fn test_deterministic_precedence_tier2_userid_over_tier3_apikey() {
    let mut h = HashMap::new();
    // Tier 2: Direct User ID
    h.insert("X-User-Id".to_string(), "direct_operator".to_string());
    h.insert("X-User-Role".to_string(), "lead_engineer".to_string());
    // Tier 3: API Key
    h.insert("X-API-Key".to_string(), "apikey_secret_9999".to_string());
    h.insert("X-Role".to_string(), "api_role".to_string());

    let (u, r) = extract_identity_and_role(&h);
    assert_eq!(
        u, "direct_operator",
        "Tier 2 User ID must take precedence over API Key"
    );
    assert_eq!(
        r, "lead_engineer",
        "Tier 2 User Role must take precedence over X-Role"
    );
}

#[test]
fn test_deterministic_fallback_on_malformed_higher_tiers() {
    // 1. Malformed JWT falls through to Tier 2 (User-ID)
    let mut h1 = HashMap::new();
    h1.insert(
        "Authorization".to_string(),
        "Bearer malformed.token.garbage".to_string(),
    );
    h1.insert("X-User-Id".to_string(), "fallback_user".to_string());
    h1.insert("X-User-Role".to_string(), "auditor".to_string());

    let (u1, r1) = extract_identity_and_role(&h1);
    assert_eq!(u1, "fallback_user");
    assert_eq!(r1, "auditor");

    // 2. Malformed JWT + Whitespace User-ID falls through to Tier 3 (API-Key)
    let mut h2 = HashMap::new();
    h2.insert(
        "Authorization".to_string(),
        "Bearer not-a-valid-token".to_string(),
    );
    h2.insert("X-User-Id".to_string(), "    ".to_string());
    h2.insert("X-API-Key".to_string(), "live_backup_key_456".to_string());
    h2.insert("X-Role".to_string(), "service_role".to_string());

    let (u2, r2) = extract_identity_and_role(&h2);
    assert_eq!(u2, "key_live_bac");
    assert_eq!(r2, "service_role");

    // 3. Malformed JWT + Empty User-ID + Empty API-Key falls through to Tier 4 (Anonymous)
    let mut h3 = HashMap::new();
    h3.insert("Authorization".to_string(), "Bearer broken".to_string());
    h3.insert("X-User-Id".to_string(), "".to_string());
    h3.insert("X-API-Key".to_string(), "   ".to_string());

    let (u3, r3) = extract_identity_and_role(&h3);
    assert_eq!(u3, DEFAULT_ANONYMOUS_USER);
    assert_eq!(r3, DEFAULT_USER_ROLE);
}

// =========================================================================
// 6. Zero Secret Leakage Verification
// =========================================================================

#[test]
fn test_no_secret_leakage_in_base64_error_messages() {
    let secret = "super_sensitive_token_content!#%&";
    let res = decode_base64_url(secret);
    assert!(res.is_err());
    let err_msg = res.unwrap_err();

    // The error message must be generic and NEVER leak any part of the secret
    assert_eq!(err_msg, "Invalid base64 character");
    assert!(!err_msg.contains(secret));
    assert!(!err_msg.contains('!'));
    assert!(!err_msg.contains('#'));
    assert!(!err_msg.contains('%'));
}

#[test]
fn test_api_key_truncation_never_exposes_full_secret() {
    let full_secret = "app_sec_token_994827461938475629103948572619";
    let mut h = HashMap::new();
    h.insert("X-API-Key".to_string(), full_secret.to_string());

    let (extracted_id, _) = extract_identity_and_role(&h);
    // Extracted ID is only a prefix identifier
    assert_eq!(extracted_id, "key_app_sec_");
    assert_ne!(extracted_id, format!("key_{}", full_secret));
    assert!(!extracted_id.contains("994827461938475629103948572619"));
}

// =========================================================================
// 7. End-to-End Reassembler & Record Verification
// =========================================================================

#[test]
fn test_end_to_end_reassembler_emits_hardened_auth_records() {
    let mut reassembler = StreamReassembler::new();
    let conn = "10.0.0.99:45678->10.0.0.1:8080";

    // 1. Ingress request with hardened Bearer JWT
    let token = build_jwt("{\"sub\": \"sec_analyst_404\", \"role\": \"tier3_soc\"}");
    let req_raw = format!(
        "GET /api/v1/security/incidents HTTP/1.1\r\n\
         Host: sentinel.internal\r\n\
         Authorization: Bearer {}\r\n\
         X-User-Id: spoofed_user\r\n\
         X-API-Key: spoofed_key\r\n\r\n",
        token
    );

    let frag_req = RawFragment {
        ts: 100.0,
        connection_id: conn.to_string(),
        direction: TrafficDirection::Ingress,
        payload: req_raw.into_bytes(),
    };
    let out_req = reassembler.process_fragment(frag_req);
    assert!(out_req.is_empty(), "Request should wait for response");

    // 2. Egress response
    let resp_raw = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"incidents\":[]}";
    let frag_resp = RawFragment {
        ts: 100.012,
        connection_id: "10.0.0.1:8080->10.0.0.99:45678".to_string(),
        direction: TrafficDirection::Egress,
        payload: resp_raw.as_bytes().to_vec(),
    };
    let records = reassembler.process_fragment(frag_resp);
    assert_eq!(records.len(), 1);

    let record = &records[0];
    assert_eq!(
        record.user, "sec_analyst_404",
        "JWT sub must be emitted in Record"
    );
    assert_eq!(
        record.role, "tier3_soc",
        "JWT role must be emitted in Record"
    );
    assert_eq!(record.method, "GET");
    assert_eq!(record.path, "/api/v1/security/incidents");
    assert_eq!(record.status, 200);
    assert!((record.latency_ms - 12.0).abs() < 1e-4);
    assert_eq!(record.src_ip, "10.0.0.99");
}
