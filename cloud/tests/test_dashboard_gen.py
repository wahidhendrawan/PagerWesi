"""Tests for the dashboard generation module."""
from __future__ import annotations

from cloud.dashboard_gen import generate_dashboard


def _finding_dict(control_id="TEST-001", status="fail", resource="test:r"):
    return {
        "control_id": control_id,
        "status": status,
        "severity": "high",
        "resource": resource,
        "evidence": "test evidence",
        "title": "Test finding",
    }


class TestGenerateDashboard:
    def test_creates_html_files(self, tmp_path):
        """Should create index, controls, and providers pages."""
        findings = [_finding_dict(), _finding_dict("TEST-002", "pass")]
        generate_dashboard(findings, str(tmp_path / "site"))

        assert (tmp_path / "site" / "index.html").exists()
        assert (tmp_path / "site" / "controls.html").exists()
        assert (tmp_path / "site" / "providers.html").exists()

    def test_index_contains_summary(self, tmp_path):
        """Index page should contain summary statistics."""
        findings = [
            _finding_dict("A-001", "pass"),
            _finding_dict("A-002", "fail"),
            _finding_dict("A-003", "error"),
        ]
        generate_dashboard(findings, str(tmp_path / "site"))
        content = (tmp_path / "site" / "index.html").read_text()
        assert "Total: 3" in content
        assert "PASS: 1" in content
        assert "FAIL: 1" in content
        assert "ERROR: 1" in content

    def test_controls_page_lists_findings(self, tmp_path):
        """Controls page should list each finding."""
        findings = [_finding_dict("AWS-S3-001", "fail")]
        generate_dashboard(findings, str(tmp_path / "site"))
        content = (tmp_path / "site" / "controls.html").read_text()
        assert "AWS-S3-001" in content
        assert "FAIL" in content

    def test_providers_page_groups(self, tmp_path):
        """Providers page should group by provider."""
        findings = [
            _finding_dict("AWS-S3-001", "fail"),
            _finding_dict("AZURE-KV-001", "pass"),
        ]
        generate_dashboard(findings, str(tmp_path / "site"))
        content = (tmp_path / "site" / "providers.html").read_text()
        assert "aws" in content.lower()
        assert "azure" in content.lower()

    def test_empty_findings(self, tmp_path):
        """Should handle empty findings gracefully."""
        generate_dashboard([], str(tmp_path / "site"))
        assert (tmp_path / "site" / "index.html").exists()
        content = (tmp_path / "site" / "index.html").read_text()
        assert "Total: 0" in content

    def test_html_escaping(self, tmp_path):
        """Should escape HTML entities in evidence."""
        findings = [{
            "control_id": "TEST-001",
            "status": "fail",
            "severity": "high",
            "resource": "test:resource",
            "evidence": "xss <script>alert(1)</script>",
            "title": "XSS test",
        }]
        generate_dashboard(findings, str(tmp_path / "site"))
        content = (tmp_path / "site" / "controls.html").read_text()
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_creates_output_directory(self, tmp_path):
        """Should create output directory if it doesn't exist."""
        output = tmp_path / "nested" / "path" / "site"
        generate_dashboard([_finding_dict()], str(output))
        assert output.exists()
