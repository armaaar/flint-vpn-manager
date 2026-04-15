"""Tests for adblock_service.py — blocklist download and merge logic."""

from unittest.mock import patch, MagicMock

import pytest

from services.adblock_service import download_and_merge_blocklists


class TestDownloadAndMergeBlocklists:
    """Tests for download_and_merge_blocklists()."""

    def test_returns_none_when_no_sources(self):
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"adblock": {}}
            content, count, failed = download_and_merge_blocklists()
        assert content is None
        assert count == 0
        assert failed == []

    def test_custom_domains_only(self):
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": [],
                    "custom_domains": ["ads.example.com", "tracker.example.org"],
                }
            }
            content, count, failed = download_and_merge_blocklists()
        assert content is not None
        assert count == 2
        assert failed == []

    def test_ipv6_entries_included(self):
        """Each domain should produce both 0.0.0.0 (IPv4) and :: (IPv6) entries."""
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": [],
                    "custom_domains": ["ads.example.com"],
                }
            }
            content, count, failed = download_and_merge_blocklists()

        assert "0.0.0.0 ads.example.com" in content
        assert ":: ads.example.com" in content

    def test_ipv6_dual_stack_format(self):
        """Every domain gets two consecutive lines: IPv4 then IPv6."""
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": [],
                    "custom_domains": ["ad.test", "tracker.test"],
                }
            }
            content, count, failed = download_and_merge_blocklists()

        lines = [l for l in content.splitlines() if l and not l.startswith("#")]
        # Each domain produces 2 lines (IPv4 + IPv6)
        assert len(lines) == 4
        # Check pairing: each domain has its IPv4 line followed by IPv6
        assert "0.0.0.0 ad.test" in lines
        assert ":: ad.test" in lines
        assert "0.0.0.0 tracker.test" in lines
        assert ":: tracker.test" in lines

    def test_deduplicates_domains(self):
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": [],
                    "custom_domains": [
                        "ads.example.com",
                        "ADS.EXAMPLE.COM",  # duplicate (case-insensitive)
                        "ads.example.com",  # exact duplicate
                    ],
                }
            }
            content, count, failed = download_and_merge_blocklists()
        assert count == 1  # Only one unique domain

    def test_skips_invalid_custom_domains(self):
        """Domains without a dot are skipped."""
        with patch("services.adblock_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": [],
                    "custom_domains": ["localhost", "nodot", "valid.com"],
                }
            }
            content, count, failed = download_and_merge_blocklists()
        assert count == 1
        assert "valid.com" in content

    def test_downloads_and_parses_hosts_format(self):
        """Test parsing of standard hosts-file format from remote blocklists."""
        mock_resp = MagicMock()
        mock_resp.text = (
            "# Comment line\n"
            "0.0.0.0 ads.example.com\n"
            "0.0.0.0 tracker.example.com\n"
            "0.0.0.0 localhost\n"  # should be skipped
        )
        mock_resp.status_code = 200

        with patch("services.adblock_service.sm") as mock_sm, \
             patch("requests.get", return_value=mock_resp):
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": ["hagezi-light"],
                    "custom_domains": [],
                }
            }
            content, count, failed = download_and_merge_blocklists()

        assert count == 2  # ads + tracker, not localhost
        assert failed == []
        assert "ads.example.com" in content
        assert "tracker.example.com" in content
        assert "localhost" not in content.split("# Sources")[1]  # Not in domain entries

    def test_reports_failed_sources(self):
        """Failed downloads should be reported but not crash."""
        import requests

        with patch("services.adblock_service.sm") as mock_sm, \
             patch("requests.get", side_effect=requests.RequestException("timeout")):
            mock_sm.get_config.return_value = {
                "adblock": {
                    "blocklist_sources": ["hagezi-light"],
                    "custom_domains": ["fallback.com"],
                }
            }
            content, count, failed = download_and_merge_blocklists()

        assert "hagezi-light" in failed
        assert count == 1  # Only the custom domain
