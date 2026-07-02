"""Tests for the secrets scanner module."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from cloud.secrets_scanner import (
    _is_binary,
    run_audit,
    scan_path,
)


@pytest.fixture
def scan_args():
    return SimpleNamespace(control=[], mode="audit", path=None)


@pytest.fixture
def temp_tree(tmp_path):
    """Create a temporary directory tree with test files."""
    src = tmp_path / "src"
    src.mkdir()
    return tmp_path


def test_detects_aws_access_key(temp_tree, scan_args):
    """Should detect AWS access key patterns."""
    (temp_tree / "config.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 1
    assert findings[0].status.value == "fail"
    assert "AWS Access Key" in findings[0].evidence


def test_detects_private_key(temp_tree, scan_args):
    """Should detect private key headers."""
    (temp_tree / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 1
    assert "Private Key" in findings[0].evidence


def test_detects_github_token(temp_tree, scan_args):
    """Should detect GitHub personal access tokens."""
    (temp_tree / "env.sh").write_text(
        'export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"\n',
        encoding="utf-8",
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) >= 1
    assert any("GitHub Token" in f.evidence for f in findings)


def test_detects_gitlab_token(temp_tree, scan_args):
    """Should detect GitLab personal access tokens."""
    (temp_tree / "ci.yml").write_text(
        'token: "glpat-ABCDEFGHIJKLMNOPQRST"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) >= 1
    assert any("GitLab Token" in f.evidence for f in findings)


def test_detects_database_url(temp_tree, scan_args):
    """Should detect database connection strings."""
    (temp_tree / "settings.py").write_text(
        'DB_URL = "postgresql://user:secretpass@db.example.com:5432/mydb"\n',
        encoding="utf-8",
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) >= 1
    assert any("Database URL" in f.evidence for f in findings)


def test_detects_password_in_quotes(temp_tree, scan_args):
    """Should detect password assignments in quotes."""
    (temp_tree / "config.ini").write_text(
        'password = "my_super_secret_password"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) >= 1


def test_skips_binary_files(temp_tree, scan_args):
    """Should skip binary files."""
    binary_file = temp_tree / "data.bin"
    binary_file.write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE")
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_skips_ignored_extensions(temp_tree, scan_args):
    """Should skip files with ignored extensions."""
    (temp_tree / "image.png").write_text(
        'AKIAIOSFODNN7EXAMPLE', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_skips_ignored_directories(temp_tree, scan_args):
    """Should skip ignored directories like .git and node_modules."""
    git_dir = temp_tree / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        'AKIAIOSFODNN7EXAMPLE', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_allowlist_example_comments(temp_tree, scan_args):
    """Should not flag secrets in example/test comments."""
    (temp_tree / "docs.py").write_text(
        '# Example: password = "changeme_placeholder"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_allowlist_placeholder_values(temp_tree, scan_args):
    """Should not flag CHANGEME/PLACEHOLDER values."""
    (temp_tree / "env.example").write_text(
        'API_KEY = "CHANGEME"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_no_findings_for_clean_code(temp_tree, scan_args):
    """Should return no findings for clean code."""
    (temp_tree / "main.py").write_text(
        'import os\nname = os.environ.get("NAME")\nprint(name)\n',
        encoding="utf-8",
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_run_audit_with_invalid_path(scan_args):
    """Should return error finding for invalid path."""
    scan_args.path = "/nonexistent/path/xyz"
    findings = run_audit(scan_args)
    assert len(findings) == 1
    assert findings[0].status.value == "error"


def test_run_audit_default_cwd(temp_tree, scan_args, monkeypatch):
    """Should use current working directory when no path specified."""
    monkeypatch.chdir(temp_tree)
    (temp_tree / "safe.py").write_text("x = 1\n", encoding="utf-8")
    findings = run_audit(scan_args)
    assert len(findings) == 0


def test_skips_large_files(temp_tree, scan_args):
    """Should skip files exceeding size limit."""
    large_file = temp_tree / "large.txt"
    # Write content larger than 1 MiB
    large_file.write_text("AKIAIOSFODNN7EXAMPLE\n" * 100000, encoding="utf-8")
    findings = scan_path(str(temp_tree), scan_args)
    assert len(findings) == 0


def test_is_binary_detects_null_bytes():
    """Should correctly identify binary files."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
        f.write(b"\x00\x01\x02\x03")
        path = f.name
    try:
        assert _is_binary(path) is True
    finally:
        os.unlink(path)


def test_is_binary_identifies_text():
    """Should correctly identify text files."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("This is plain text\n")
        path = f.name
    try:
        assert _is_binary(path) is False
    finally:
        os.unlink(path)


def test_severity_levels(temp_tree, scan_args):
    """Critical patterns should have CRITICAL severity."""
    (temp_tree / "creds.py").write_text(
        'key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    findings = scan_path(str(temp_tree), scan_args)
    assert findings[0].severity.value == "critical"
