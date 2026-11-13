"""Unit tests for the API-Sentinel HTTP Parser foundation and data contracts (Day 1)."""

import base64
import json
import unittest

from parser import (
    BaseHTTPParser,
    ConnectionKey,
    ConnectionState,
    ParsedHTTPRequest,
    ParsedHTTPResponse,
    RawFragment,
    Record,
    TrafficDirection,
    extract_identity_and_role,
)


class TestRecordContract(unittest.TestCase):
    """Test suite verifying the Record model contract."""

    def test_record_instantiation_defaults(self):
        record = Record(
            ts=1731312000.0,
            user="user_42",
            method="GET",
            path="/api/orders/1002",
            status=200,
        )
        self.assertEqual(record.ts, 1731312000.0)
        self.assertEqual(record.user, "user_42")
        self.assertEqual(record.method, "GET")
        self.assertEqual(record.path, "/api/orders/1002")
        self.assertEqual(record.status, 200)
        self.assertIsNone(record.req_body)
        self.assertIsNone(record.resp_body)
        self.assertEqual(record.latency_ms, 0.0)
        self.assertEqual(record.src_ip, "")
        self.assertEqual(record.role, "user")
        self.assertTrue(record.ok)

    def test_record_ok_status_variations(self):
        self.assertTrue(Record(ts=1.0, user="u", method="GET", path="/", status=200).ok)
        self.assertTrue(Record(ts=1.0, user="u", method="POST", path="/", status=201).ok)
        self.assertTrue(Record(ts=1.0, user="u", method="DELETE", path="/", status=204).ok)

        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=301).ok)
        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=400).ok)
        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=401).ok)
        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=403).ok)
        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=404).ok)
        self.assertFalse(Record(ts=1.0, user="u", method="GET", path="/", status=500).ok)

    def test_record_serialization_roundtrip(self):
        original = Record(
            ts=1731312000.1,
            user="user_55",
            method="POST",
            path="/api/auth/login",
            status=200,
            req_body={"username": "alice"},
            resp_body={"token": "xyz789"},
            latency_ms=15.6,
            src_ip="192.168.1.50",
            role="admin",
        )
        as_dict = original.to_dict()
        self.assertEqual(as_dict["user"], "user_55")
        self.assertEqual(as_dict["role"], "admin")
        self.assertEqual(as_dict["latency_ms"], 15.6)

        reconstructed = Record.from_dict(as_dict)
        self.assertEqual(reconstructed, original)

        as_json = original.to_json()
        parsed_json = json.loads(as_json)
        self.assertEqual(parsed_json["user"], "user_55")
        self.assertEqual(parsed_json["req_body"], {"username": "alice"})

    def test_record_from_dict_ignores_extra_fields(self):
        raw_data = {
            "ts": 1731312000.1,
            "user": "user_10",
            "method": "GET",
            "path": "/health",
            "status": 200,
            "extra_field_1": "untracked",
            "another_random_key": 12345,
        }
        record = Record.from_dict(raw_data)
        self.assertEqual(record.user, "user_10")
        self.assertEqual(record.path, "/health")
        self.assertFalse(hasattr(record, "extra_field_1"))


class TestConnectionAndFragments(unittest.TestCase):
    """Test suite verifying network connection keys and raw fragment models."""

    def test_traffic_direction_normalization(self):
        self.assertEqual(TrafficDirection.from_str("ingress"), TrafficDirection.INGRESS)
        self.assertEqual(TrafficDirection.from_str("REQUEST"), TrafficDirection.INGRESS)
        self.assertEqual(TrafficDirection.from_str("in"), TrafficDirection.INGRESS)

        self.assertEqual(TrafficDirection.from_str("egress"), TrafficDirection.EGRESS)
        self.assertEqual(TrafficDirection.from_str("RESPONSE"), TrafficDirection.EGRESS)
        self.assertEqual(TrafficDirection.from_str("out"), TrafficDirection.EGRESS)

        with self.assertRaises(ValueError):
            TrafficDirection.from_str("invalid_direction")

    def test_connection_key_identifiers(self):
        key = ConnectionKey(
            src_ip="10.0.0.5",
            src_port=45000,
            dst_ip="10.0.0.1",
            dst_port=8080,
        )
        self.assertEqual(key.connection_id, "10.0.0.5:45000->10.0.0.1:8080")
        self.assertEqual(key.reverse_id, "10.0.0.1:8080->10.0.0.5:45000")
        key_reversed = ConnectionKey(
            src_ip="10.0.0.1",
            src_port=8080,
            dst_ip="10.0.0.5",
            dst_port=45000,
        )
        self.assertEqual(key.bidirectional_id, key_reversed.bidirectional_id)

    def test_raw_fragment_creation(self):
        fragment = RawFragment(
            connection_id="conn_1",
            ts=1731312000.0,
            direction=TrafficDirection.INGRESS,
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )
        self.assertEqual(fragment.connection_id, "conn_1")
        self.assertEqual(fragment.direction, TrafficDirection.INGRESS)
        self.assertTrue(fragment.payload.startswith(b"GET"))

    def test_raw_fragment_from_dict(self):
        data = {
            "connection_id": "conn_2",
            "ts": 1731312001.5,
            "direction": "response",
            "payload": "HTTP/1.1 200 OK\r\n\r\n",
        }
        fragment = RawFragment.from_dict(data)
        self.assertEqual(fragment.direction, TrafficDirection.EGRESS)
        self.assertIsInstance(fragment.payload, bytes)
        self.assertEqual(fragment.payload, b"HTTP/1.1 200 OK\r\n\r\n")


class TestAuthExtraction(unittest.TestCase):
    """Test suite verifying user and role extraction from HTTP headers."""

    def test_extract_from_jwt_bearer(self):
        claims = {"sub": "user_777", "role": "security_admin", "exp": 1999999999}
        payload_json = json.dumps(claims).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_json).decode("utf-8").rstrip("=")
        mock_token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload_b64}.mocksignature"

        headers = {"Authorization": f"Bearer {mock_token}"}
        user, role = extract_identity_and_role(headers)
        self.assertEqual(user, "user_777")
        self.assertEqual(role, "security_admin")

    def test_extract_from_api_key_headers(self):
        headers = {"X-API-Key": "live_apikey_secret_9999"}
        user, role = extract_identity_and_role(headers)
        self.assertEqual(user, "key_live_api")
        self.assertEqual(role, "user")

    def test_extract_from_user_id_headers(self):
        headers = {
            "X-User-ID": "admin_master",
            "X-User-Role": "superadmin",
        }
        user, role = extract_identity_and_role(headers)
        self.assertEqual(user, "admin_master")
        self.assertEqual(role, "superadmin")

    def test_extract_anonymous_fallback(self):
        headers = {"Host": "api.example.com", "Accept": "application/json"}
        user, role = extract_identity_and_role(headers)
        self.assertEqual(user, "anonymous")
        self.assertEqual(role, "user")

    def test_extract_empty_headers(self):
        user, role = extract_identity_and_role({})
        self.assertEqual(user, "anonymous")
        self.assertEqual(role, "user")


class TestConnectionStateReassembler(unittest.TestCase):
    """Test suite verifying connection buffer tracking and latency measurement."""

    def test_connection_state_buffering(self):
        state = ConnectionState(connection_id="conn_abc")
        state.append_ingress(b"GET /api/test ", ts=100.0)
        state.append_ingress(b"HTTP/1.1\r\n\r\n", ts=100.1)
        self.assertEqual(bytes(state.ingress_buffer), b"GET /api/test HTTP/1.1\r\n\r\n")
        self.assertEqual(state.last_activity, 100.1)

        state.append_egress(b"HTTP/1.1 200 OK\r\n\r\n", ts=100.15)
        self.assertEqual(bytes(state.egress_buffer), b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertEqual(state.last_activity, 100.15)

    def test_latency_calculation(self):
        state = ConnectionState(connection_id="conn_abc")
        req = ParsedHTTPRequest(method="GET", path="/test", ts=100.0)
        resp = ParsedHTTPResponse(status=200, ts=100.025)

        latency = state.calculate_latency_ms(req, resp)
        self.assertEqual(latency, 25.0)

    def test_clear_connection_state(self):
        state = ConnectionState(connection_id="conn_abc")
        state.append_ingress(b"data", ts=1.0)
        state.append_egress(b"data", ts=2.0)
        state.clear()
        self.assertEqual(len(state.ingress_buffer), 0)
        self.assertEqual(len(state.egress_buffer), 0)


class TestBaseParserInterface(unittest.TestCase):
    """Test suite verifying BaseHTTPParser protocol implementation."""

    class DummyParser(BaseHTTPParser):
        def __init__(self):
            self.records = []

        def feed_fragment(self, fragment: RawFragment) -> list[Record]:
            return self.records

        def reset(self, connection_id=None) -> None:
            pass

        def active_connections(self) -> list[str]:
            return ["conn_dummy"]

    def test_feed_raw_wrapper(self):
        parser = self.DummyParser()
        records = parser.feed_raw(
            connection_id="test_conn",
            ts=1731312000.0,
            direction="ingress",
            payload="GET / HTTP/1.1\r\n\r\n",
        )
        self.assertEqual(records, [])
        self.assertEqual(parser.active_connections(), ["conn_dummy"])


if __name__ == "__main__":
    unittest.main()
