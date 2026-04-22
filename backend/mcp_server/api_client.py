"""Thin HTTP client wrapping the Flint VPN Manager REST API at localhost:5000."""

from __future__ import annotations

import httpx

DEFAULT_BASE_URL = "http://localhost:5000"
TIMEOUT = 30.0


class APIError(Exception):
    """Raised when the Flint VPN Manager API returns a non-2xx response."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class FlintAPI:
    """Synchronous HTTP client for the Flint VPN Manager REST API."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=TIMEOUT)

    def _request(self, method: str, path: str, **kwargs) -> dict | list | None:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code == 401:
            raise APIError(401, "Session locked. Call flint_unlock first.")
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("error", resp.text)
            except Exception:
                msg = resp.text
            raise APIError(resp.status_code, msg)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    def get(self, path: str, **params) -> dict | list:
        return self._request("GET", path, params=params)

    def post(self, path: str, json: dict | None = None) -> dict | list:
        return self._request("POST", path, json=json)

    def put(self, path: str, json: dict | None = None) -> dict | list:
        return self._request("PUT", path, json=json)

    def delete(self, path: str) -> dict | list | None:
        return self._request("DELETE", path)
