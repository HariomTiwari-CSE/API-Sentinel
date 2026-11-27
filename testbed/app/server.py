"""Lightweight crAPI-compatible vulnerable Flask testbed for API-Sentinel.

Run with:
    python -m testbed.app.server

Intentional vulnerabilities (for testing detector/, discovery/, ratelimit/, masking/):
- API1 (BOLA): /workshop/api/shop/orders/{order_id}, /identity/api/v2/vehicle/{vehicle_id}/location,
  and /community/api/v2/posts/{post_id} do not verify resource ownership.
- API5 (BFLA): /identity/api/v2/admin/videos and /identity/api/v2/admin/users do not check role == "admin".
- API4 (Rate Limit): /workshop/api/shop/coupons/validate has no throttling.
- API9 (Shadow / Zombie): /api/v1/debug/users and /api/v1/orders/export-legacy are undocumented in openapi.yaml.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from flask import Flask, jsonify, request

_USERS: dict[str, dict[str, Any]] = {
    "user_101": {
        "user": "user_101",
        "email": "alice@crapi.local",
        "password": "alice-password-123",
        "role": "user",
        "phone": "+1-415-555-0101",
        "ssn": "123-45-6789",
    },
    "user_102": {
        "user": "user_102",
        "email": "bob@crapi.local",
        "password": "bob-password-456",
        "role": "user",
        "phone": "+1-415-555-0102",
        "ssn": "987-65-4321",
    },
    "user_103": {
        "user": "user_103",
        "email": "carol@crapi.local",
        "password": "carol-password-789",
        "role": "user",
        "phone": "+1-415-555-0103",
        "ssn": "555-12-3456",
    },
    "admin_1": {
        "user": "admin_1",
        "email": "secops@crapi.local",
        "password": "admin-super-secret",
        "role": "admin",
        "phone": "+1-415-555-0199",
        "ssn": "000-11-2222",
    },
}

_PRODUCTS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "name": "OBD-II Telemetry Dongle", "price": 79.99, "stock": 42},
    2: {"id": 2, "name": "Ceramic Brake Pad Set", "price": 149.50, "stock": 18},
    3: {"id": 3, "name": "Synthetic Motor Oil 5W-30", "price": 39.00, "stock": 120},
}

_ORDERS: dict[int, dict[str, Any]] = {
    1001: {
        "id": 1001,
        "owner": "user_101",
        "product_id": 1,
        "product": "OBD-II Telemetry Dongle",
        "total": 79.99,
        "email": "alice@crapi.local",
        "card_number": "4111-1111-1111-1111",
        "address": "101 Market St, San Francisco, CA",
    },
    1002: {
        "id": 1002,
        "owner": "user_102",
        "product_id": 2,
        "product": "Ceramic Brake Pad Set",
        "total": 149.50,
        "email": "bob@crapi.local",
        "card_number": "5500-0000-0000-0004",
        "address": "202 Mission St, San Francisco, CA",
    },
    1003: {
        "id": 1003,
        "owner": "user_102",
        "product_id": 3,
        "product": "Synthetic Motor Oil 5W-30",
        "total": 39.00,
        "email": "bob@crapi.local",
        "card_number": "5500-0000-0000-0004",
        "address": "202 Mission St, San Francisco, CA",
    },
    1004: {
        "id": 1004,
        "owner": "user_103",
        "product_id": 2,
        "product": "Ceramic Brake Pad Set",
        "total": 149.50,
        "email": "carol@crapi.local",
        "card_number": "4242-4242-4242-4242",
        "address": "303 Howard St, San Francisco, CA",
    },
    1005: {
        "id": 1005,
        "owner": "user_103",
        "product_id": 1,
        "product": "OBD-II Telemetry Dongle",
        "total": 79.99,
        "email": "carol@crapi.local",
        "card_number": "4242-4242-4242-4242",
        "address": "303 Howard St, San Francisco, CA",
    },
}

_VEHICLES: dict[int, dict[str, Any]] = {
    2001: {"id": 2001, "owner": "user_101", "vin": "1HGCM82633A004352", "lat": 37.7749, "lon": -122.4194},
    2002: {"id": 2002, "owner": "user_102", "vin": "2HGFG12648H543210", "lat": 37.7849, "lon": -122.4094},
    2003: {"id": 2003, "owner": "user_103", "vin": "3VWFE21C04M000001", "lat": 37.7949, "lon": -122.3994},
}

_POSTS: dict[int, dict[str, Any]] = {
    3001: {"id": 3001, "owner": "user_101", "title": "Battery checkup", "private_note": "VIN 1HGCM82633A004352"},
    3002: {"id": 3002, "owner": "user_102", "title": "Brake inspection", "private_note": "Call +1-415-555-0102"},
}


def make_jwt(user: str, role: str) -> str:
    """Create a deterministic JWT readable by parser/src/auth.rs."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_bytes = json.dumps({"sub": user, "role": role, "iat": 1731312000}).encode()
    payload = base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
    return f"{header}.{payload}.crapi_test_sig"


def decode_caller(authorization: str | None) -> tuple[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return "anonymous", "user"
    token = authorization.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return "anonymous", "user"
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(padded).decode())
        return str(claims.get("sub", "anonymous")), str(claims.get("role", "user"))
    except Exception:
        return "anonymous", "user"


def create_testbed_app() -> Flask:
    app = Flask("crapi-testbed")
    orders = {k: dict(v) for k, v in _ORDERS.items()}
    state = {"next_order_id": 1006}

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "crapi-testbed", "ts": time.time()})

    @app.post("/identity/api/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        email = body.get("email", "")
        password = body.get("password", "")
        for info in _USERS.values():
            if info["email"] == email and info["password"] == password:
                return jsonify(
                    {
                        "token": make_jwt(info["user"], info["role"]),
                        "user": info["user"],
                        "role": info["role"],
                    }
                )
        return jsonify({"detail": "Invalid credentials"}), 401

    @app.get("/identity/api/v2/user/dashboard")
    def user_dashboard():
        user, role = decode_caller(request.headers.get("Authorization"))
        if user not in _USERS:
            return jsonify({"detail": "Unauthorized"}), 401
        profile = dict(_USERS[user])
        profile.pop("password", None)
        profile["role"] = role
        return jsonify(profile)

    @app.get("/identity/api/v2/vehicle/<int:vehicle_id>/location")
    def vehicle_location(vehicle_id: int):
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        # Intentional BOLA (API1): omits vehicle["owner"] == user check
        vehicle = _VEHICLES.get(vehicle_id)
        if not vehicle:
            return jsonify({"detail": "Vehicle not found"}), 404
        return jsonify(vehicle)

    @app.get("/identity/api/v2/admin/videos")
    def admin_videos():
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        # Intentional BFLA (API5): omits role == "admin" check
        return jsonify(
            {
                "videos": [
                    {
                        "id": 1,
                        "title": "Internal Fleet Diagnostics",
                        "url": "https://internal.crapi.local/v1.mp4",
                    }
                ]
            }
        )

    @app.get("/identity/api/v2/admin/users")
    def admin_users():
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        # Intentional BFLA (API5): exposes user directory to non-admin callers
        return jsonify({"users": [dict(u) for u in _USERS.values()]})

    @app.get("/workshop/api/shop/products")
    def list_products():
        return jsonify({"items": list(_PRODUCTS.values())})

    @app.get("/workshop/api/shop/products/<int:product_id>")
    def get_product(product_id: int):
        product = _PRODUCTS.get(product_id)
        if not product:
            return jsonify({"detail": "Product not found"}), 404
        return jsonify(product)

    @app.get("/workshop/api/shop/orders")
    def list_my_orders():
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        owned = [o for o in orders.values() if o["owner"] == user]
        return jsonify({"orders": owned})

    @app.post("/workshop/api/shop/orders")
    def create_order():
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user not in _USERS:
            return jsonify({"detail": "Unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        product = _PRODUCTS.get(body.get("product_id"))
        if not product:
            return jsonify({"detail": "Product not found"}), 404
        oid = state["next_order_id"]
        state["next_order_id"] += 1
        order = {
            "id": oid,
            "owner": user,
            "product_id": product["id"],
            "product": product["name"],
            "total": product["price"],
            "email": _USERS[user]["email"],
            "card_number": "4111-1111-1111-1111",
            "address": "500 Howard St, San Francisco, CA",
        }
        orders[oid] = order
        return jsonify(order), 201

    @app.get("/workshop/api/shop/orders/<int:order_id>")
    def get_order(order_id: int):
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        # Intentional BOLA (API1): omits order["owner"] == user check
        order = orders.get(order_id)
        if not order:
            return jsonify({"detail": "Order not found"}), 404
        return jsonify(order)

    @app.post("/workshop/api/shop/coupons/validate")
    def validate_coupon():
        # Intentional API4 (No rate limit): allows automated coupon brute-forcing
        body = request.get_json(silent=True) or {}
        code = str(body.get("code", ""))
        valid = code.upper() in {"CRAPI50", "SENTINEL20"}
        return jsonify({"code": code, "valid": valid, "discount_pct": 20 if valid else 0})

    @app.get("/community/api/v2/posts/<int:post_id>")
    def get_post(post_id: int):
        user, _ = decode_caller(request.headers.get("Authorization"))
        if user == "anonymous":
            return jsonify({"detail": "Unauthorized"}), 401
        # Intentional BOLA (API1): returns any post including private notes
        post = _POSTS.get(post_id)
        if not post:
            return jsonify({"detail": "Post not found"}), 404
        return jsonify(post)

    # --- Intentional Shadow & Zombie APIs (omitted from openapi.yaml) ---

    @app.get("/api/v1/debug/users")
    def shadow_debug_users():
        # Shadow API (API9): undocumented internal debug endpoint left enabled
        return jsonify(
            {
                "source": "internal-debug",
                "client_host": request.remote_addr or "127.0.0.1",
                "users": list(_USERS.values()),
            }
        )

    @app.get("/api/v1/orders/export-legacy")
    def zombie_export_orders():
        # Zombie API (API9): deprecated v1 export endpoint still active
        return jsonify({"deprecated": True, "orders": list(orders.values())})

    return app


app = create_testbed_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
