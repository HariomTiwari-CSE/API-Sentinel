//! Data models and contract specifications for the API-Sentinel HTTP Parser module.
//!
//! Converted to Rust for high-performance zero-overhead packet processing and
//! seamless interoperability with the kernel eBPF / Rust ingestion agent.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

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
    pub fn new(src_ip: impl Into<String>, src_port: u16, dst_ip: impl Into<String>, dst_port: u16) -> Self {
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
        format!("{}:{}->{}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }

    /// Reverse connection identifier for pairing the return traffic stream.
    pub fn reverse_id(&self) -> String {
        format!("{}:{}->{}:{}", self.dst_ip, self.dst_port, self.src_ip, self.src_port)
    }

    /// Canonical bidirectional identifier invariant to orientation.
    pub fn bidirectional_id(&self) -> String {
        let endpoint_a = (&self.src_ip, self.src_port);
        let endpoint_b = (&self.dst_ip, self.dst_port);
        if endpoint_a <= endpoint_b {
            format!("{}:{}<->{}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        } else {
            format!("{}:{}<->{}:{}", self.dst_ip, self.dst_port, self.src_ip, self.src_port)
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

mod serde_bytes_or_vec {
    use serde::{Deserializer, Serializer, Deserialize};

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
    #[serde(default = "default_http_version")]
    pub http_version: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
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
    #[serde(default)]
    pub ts: f64,
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

    /// Serialize record to compact JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize record from JSON string, ignoring unknown fields automatically.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}
