"""Unit tests for the Core HTTP/1.x Request Parser (Day 2)."""

import json
import unittest

from parser.models import ParsedHTTPRequest
from parser.request import (
    CaseInsensitiveDict,
    RequestParseResult,
    parse_all_requests,
    parse_http_request,
)


class TestRequestLineParsing(unittest.TestCase):
    """Test suite for HTTP/1.x request line parsing."""

    def test_standard_get_request(self):
        raw = b"GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        res = parse_http_request(raw, ts=100.0, src_ip="10.0.0.1", src_port=50000)
        self.assertTrue(res.is_complete)
        self.assertIsNotNone(res.request)
        req = res.request
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/api/v1/users")
        self.assertEqual(req.http_version, "HTTP/1.1")
        self.assertEqual(req.src_ip, "10.0.0.1")
        self.assertEqual(req.src_port, 50000)
        self.assertEqual(res.bytes_consumed, len(raw))

    def test_methods_matrix(self):
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"):
            raw = f"{method} /resource HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
            res = parse_http_request(raw)
            self.assertTrue(res.is_complete, f"Failed for {method}")
            self.assertEqual(res.request.method, method)

    def test_path_with_query_parameters(self):
        raw = b"GET /api/orders?status=active&sort=desc&limit=10 HTTP/1.1\r\nHost: api.local\r\n\r\n"
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.path, "/api/orders?status=active&sort=desc&limit=10")

    def test_http_10_version(self):
        raw = b"GET /index.html HTTP/1.0\r\nHost: legacy.local\r\n\r\n"
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.http_version, "HTTP/1.0")

    def test_lenient_newline_separators(self):
        # Support lenient LF line endings
        raw = b"GET /lenient HTTP/1.1\nHost: test\n\n"
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.path, "/lenient")


class TestHeaderParsing(unittest.TestCase):
    """Test suite for HTTP headers and case-insensitive resolution."""

    def test_case_insensitive_header_lookup(self):
        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "application/json"
        headers["X-API-KEY"] = "secret123"

        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["CONTENT-TYPE"], "application/json")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers.get("x-api-key"), "secret123")
        self.assertIn("content-type", headers)
        self.assertIn("Content-Type", headers)

    def test_whitespace_trimming_in_headers(self):
        raw = b"GET /test HTTP/1.1\r\n  Host:   api.trimmed.local   \r\n  X-Custom:   hello world  \r\n\r\n"
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        headers = res.request.headers
        self.assertEqual(headers.get("host"), "api.trimmed.local")
        self.assertEqual(headers.get("x-custom"), "hello world")

    def test_repeated_headers_joined_with_comma(self):
        raw = (
            b"GET /test HTTP/1.1\r\n"
            b"Host: test\r\n"
            b"Accept: text/html\r\n"
            b"Accept: application/xhtml+xml\r\n"
            b"Accept: application/xml;q=0.9\r\n\r\n"
        )
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(
            res.request.headers.get("Accept"),
            "text/html, application/xhtml+xml, application/xml;q=0.9",
        )


class TestBodyParsing(unittest.TestCase):
    """Test suite for Content-Length, chunked transfer-encoding, and JSON parsing."""

    def test_post_with_content_length_json(self):
        payload = {"order_id": 1002, "items": ["itemA", "itemB"], "total": 49.99}
        body_bytes = json.dumps(payload).encode("utf-8")
        raw = (
            f"POST /api/orders HTTP/1.1\r\n"
            f"Host: crapi.local\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n\r\n"
        ).encode("utf-8") + body_bytes

        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.body, payload)
        self.assertEqual(res.bytes_consumed, len(raw))

    def test_partial_body_waits_for_data(self):
        raw = (
            b"POST /api/orders HTTP/1.1\r\n"
            b"Host: crapi.local\r\n"
            b"Content-Length: 100\r\n\r\n"
            b"short body"
        )
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)
        self.assertIsNone(res.request)
        self.assertEqual(res.bytes_consumed, 0)

    def test_chunked_transfer_encoding_single_chunk(self):
        chunk_data = b'{"msg": "chunked hello"}'
        chunk_size_hex = f"{len(chunk_data):x}".encode()
        raw = (
            b"POST /stream HTTP/1.1\r\n"
            b"Host: stream.local\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Type: application/json\r\n\r\n"
            + chunk_size_hex + b"\r\n"
            + chunk_data + b"\r\n"
            b"0\r\n\r\n"
        )
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.body, {"msg": "chunked hello"})
        self.assertEqual(res.bytes_consumed, len(raw))

    def test_chunked_transfer_encoding_multi_chunk(self):
        raw = (
            b"PUT /upload HTTP/1.1\r\n"
            b"Host: upload.local\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWiki\r\n"
            b"5\r\npedia\r\n"
            b"0\r\n\r\n"
        )
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.body, "Wikipedia")

    def test_chunked_incomplete_waits_for_data(self):
        raw = (
            b"POST /stream HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"10\r\npartial chunk"
        )
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)

    def test_malformed_json_falls_back_gracefully(self):
        bad_json = b"{bad: json,,,}"
        header_str = (
            "POST /api/raw HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(bad_json)}\r\n\r\n"
        )
        raw = header_str.encode("utf-8") + bad_json
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.body, "{bad: json,,,}")

    def test_plain_text_body(self):
        raw = (
            b"POST /log HTTP/1.1\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 12\r\n\r\n"
            b"Hello World!"
        )
        res = parse_http_request(raw)
        self.assertTrue(res.is_complete)
        self.assertEqual(res.request.body, "Hello World!")


class TestResilienceAndMalformedInput(unittest.TestCase):
    """Test suite verifying parser resilience against malformed, partial, and empty streams."""

    def test_empty_buffer(self):
        res = parse_http_request(b"")
        self.assertFalse(res.is_complete)
        self.assertIsNone(res.request)
        self.assertEqual(res.bytes_consumed, 0)

    def test_headers_incomplete(self):
        raw = b"GET /api/incomplete HTTP/1.1\r\nHost: api.local"
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)
        self.assertIsNone(res.request)
        self.assertEqual(res.bytes_consumed, 0)

    def test_malformed_first_line_garbage(self):
        raw = b"GARBAGE_RANDOM_BYTES_WITHOUT_HTTP_METHOD\r\nMore: data\r\n\r\n"
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)
        self.assertIsNotNone(res.error)

    def test_invalid_content_length_header(self):
        raw = b"POST /invalid HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\nbody"
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)
        self.assertIsNotNone(res.error)

    def test_negative_content_length(self):
        raw = b"POST /invalid HTTP/1.1\r\nContent-Length: -5\r\n\r\nbody"
        res = parse_http_request(raw)
        self.assertFalse(res.is_complete)
        self.assertIsNotNone(res.error)


class TestPipelinedRequests(unittest.TestCase):
    """Test suite for parsing multiple pipelined requests from a single buffer."""

    def test_consecutive_pipelined_requests(self):
        req1 = b"GET /api/first HTTP/1.1\r\nHost: test.local\r\n\r\n"
        req2 = b"POST /api/second HTTP/1.1\r\nHost: test.local\r\nContent-Length: 4\r\n\r\nping"
        req3 = b"GET /api/third HTTP/1.1\r\nHost: test.local\r\n\r\n"
        stream = req1 + req2 + req3

        requests = parse_all_requests(stream, ts=100.0, src_ip="10.0.0.9")
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[0].path, "/api/first")
        self.assertEqual(requests[0].method, "GET")
        self.assertEqual(requests[1].path, "/api/second")
        self.assertEqual(requests[1].method, "POST")
        self.assertEqual(requests[1].body, "ping")
        self.assertEqual(requests[2].path, "/api/third")
        self.assertEqual(requests[2].method, "GET")


if __name__ == "__main__":
    unittest.main()
