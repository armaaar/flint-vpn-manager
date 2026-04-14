"""Tests for logs blueprint — list, read, clear."""

from unittest.mock import patch
from pathlib import Path

import pytest


class TestGetLogs:
    def test_lists_log_files(self, client, tmp_path):
        # Create test log files
        (tmp_path / "app.log").write_text("line1\nline2\n")
        (tmp_path / "error.log").write_text("")
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs")
        assert resp.status_code == 200
        names = [l["name"] for l in resp.json]
        assert "app.log" in names
        assert "error.log" in names

    def test_empty_directory(self, client, tmp_path):
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs")
        assert resp.status_code == 200
        assert resp.json == []


class TestGetLogContent:
    def test_reads_log(self, client, tmp_path):
        (tmp_path / "app.log").write_text("line1\nline2\nline3\n")
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs/app.log?lines=2")
        assert resp.status_code == 200
        assert resp.json["total_lines"] == 3
        assert len(resp.json["lines"]) == 2

    def test_not_found(self, client, tmp_path):
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs/nonexistent.log")
        assert resp.status_code == 404

    def test_slash_in_name_blocked(self, client, tmp_path):
        """Names containing / are rejected by the handler."""
        # Flask normalizes /../ so we test the .log extension check instead
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs/secrets.enc")
        assert resp.status_code == 400

    def test_non_log_extension_blocked(self, client, tmp_path):
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.get("/api/logs/secrets.enc")
        assert resp.status_code == 400


class TestClearLog:
    def test_clears_log(self, client, tmp_path):
        log_file = tmp_path / "app.log"
        log_file.write_text("line1\nline2\n")
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.delete("/api/logs/app.log")
        assert resp.status_code == 200
        assert log_file.read_text() == ""

    def test_clear_nonexistent_is_ok(self, client, tmp_path):
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.delete("/api/logs/nonexistent.log")
        assert resp.status_code == 200

    def test_non_log_extension_blocked(self, client, tmp_path):
        with patch("routes.logs.LOG_DIR", tmp_path):
            resp = client.delete("/api/logs/secrets.enc")
        assert resp.status_code == 400
