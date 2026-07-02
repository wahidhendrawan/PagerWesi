"""Input validation and sanitization utilities for secure coding.

Provides validation for user inputs, file paths, hostnames, and other
data that could be attack vectors if not properly validated.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

# Maximum acceptable sizes
MAX_PATH_LENGTH = 4096
MAX_HOSTNAME_LENGTH = 253
MAX_PORT = 65535
MAX_POLICY_SIZE = 1024 * 1024  # 1 MiB
MAX_MANIFEST_SIZE = 50 * 1024 * 1024  # 50 MiB
MAX_CONTROL_ID_LENGTH = 64
MAX_ENDPOINT_COUNT = 1000

# Valid patterns
_CONTROL_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9\-]{2,63}$")
_PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9_\-./]+$")
_REGION_PATTERN = re.compile(r"^[a-z]{2,4}-[a-z]+-\d{1,2}$")
_HOSTNAME_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)
_SAFE_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._\-]+$")


class ValidationError(ValueError):
    """Raised when input validation fails."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"Validation error for '{field}': {message}")


def validate_path(
    path: str | Path,
    *,
    must_exist: bool = False,
    allow_symlinks: bool = False,
) -> Path:
    """Validate and resolve a filesystem path securely.

    Args:
        path: The path to validate.
        must_exist: Whether the path must already exist.
        allow_symlinks: Whether to allow symbolic links.

    Returns:
        Resolved Path object.

    Raises:
        ValidationError: If the path is invalid or unsafe.
    """
    if not path:
        raise ValidationError("path", "Path cannot be empty")

    str_path = str(path)
    if len(str_path) > MAX_PATH_LENGTH:
        raise ValidationError("path", f"Path exceeds maximum length of {MAX_PATH_LENGTH}")

    # Check for null bytes (path traversal attack)
    if "\x00" in str_path:
        raise ValidationError("path", "Path contains null bytes")

    resolved = Path(str_path).resolve()

    if must_exist and not resolved.exists():
        raise ValidationError("path", f"Path does not exist: {resolved}")

    if not allow_symlinks and Path(str_path).is_symlink():
        raise ValidationError("path", "Symbolic links are not allowed")

    return resolved


def validate_hostname(hostname: str) -> str:
    """Validate a hostname or IP address.

    Args:
        hostname: The hostname to validate.

    Returns:
        The validated hostname.

    Raises:
        ValidationError: If the hostname is invalid.
    """
    if not hostname:
        raise ValidationError("hostname", "Hostname cannot be empty")

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValidationError(
            "hostname",
            f"Hostname exceeds maximum length of {MAX_HOSTNAME_LENGTH}",
        )

    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Validate as hostname
    if not _HOSTNAME_PATTERN.match(hostname):
        raise ValidationError("hostname", f"Invalid hostname format: {hostname}")

    return hostname


def validate_port(port: int | str) -> int:
    """Validate a network port number.

    Args:
        port: The port number to validate.

    Returns:
        The validated port as integer.

    Raises:
        ValidationError: If the port is invalid.
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError) as exc:
        raise ValidationError("port", f"Invalid port number: {port}") from exc

    if not (1 <= port_int <= MAX_PORT):
        raise ValidationError("port", f"Port must be between 1 and {MAX_PORT}, got {port_int}")

    return port_int


def validate_endpoint(endpoint: str) -> tuple[str, int]:
    """Validate a host:port endpoint string.

    Args:
        endpoint: The endpoint string (e.g., "example.com:443").

    Returns:
        Tuple of (hostname, port).

    Raises:
        ValidationError: If the endpoint is invalid.
    """
    if not endpoint:
        raise ValidationError("endpoint", "Endpoint cannot be empty")

    parts = endpoint.rsplit(":", 1)
    if len(parts) != 2:
        raise ValidationError("endpoint", f"Endpoint must be in host:port format: {endpoint}")

    hostname = validate_hostname(parts[0])
    port = validate_port(parts[1])
    return hostname, port


def validate_endpoints(endpoints_str: str) -> list[tuple[str, int]]:
    """Validate a comma-separated list of endpoints.

    Args:
        endpoints_str: Comma-separated endpoints (e.g., "a.com:443,b.com:8080").

    Returns:
        List of validated (hostname, port) tuples.

    Raises:
        ValidationError: If any endpoint is invalid or too many provided.
    """
    if not endpoints_str:
        raise ValidationError("endpoints", "Endpoints string cannot be empty")

    parts = [e.strip() for e in endpoints_str.split(",") if e.strip()]
    if len(parts) > MAX_ENDPOINT_COUNT:
        raise ValidationError(
            "endpoints", f"Too many endpoints ({len(parts)}), maximum is {MAX_ENDPOINT_COUNT}"
        )

    return [validate_endpoint(ep) for ep in parts]


def validate_control_id(control_id: str) -> str:
    """Validate a control ID format.

    Args:
        control_id: The control ID to validate.

    Returns:
        The validated control ID.

    Raises:
        ValidationError: If the control ID format is invalid.
    """
    if not control_id:
        raise ValidationError("control_id", "Control ID cannot be empty")

    if len(control_id) > MAX_CONTROL_ID_LENGTH:
        raise ValidationError(
            "control_id",
            f"Control ID exceeds maximum length of {MAX_CONTROL_ID_LENGTH}",
        )

    if not _CONTROL_ID_PATTERN.match(control_id):
        raise ValidationError(
            "control_id",
            f"Control ID must match pattern [A-Z][A-Z0-9-]{{2,63}}: {control_id}",
        )

    return control_id


def validate_aws_profile(profile: str) -> str:
    """Validate an AWS profile name.

    Args:
        profile: The AWS profile name.

    Returns:
        The validated profile name.

    Raises:
        ValidationError: If the profile name contains invalid characters.
    """
    if not profile:
        raise ValidationError("profile", "Profile name cannot be empty")

    if not _PROFILE_PATTERN.match(profile):
        raise ValidationError("profile", f"Invalid profile name format: {profile}")

    return profile


def validate_aws_region(region: str) -> str:
    """Validate an AWS region identifier.

    Args:
        region: The AWS region (e.g., "us-east-1").

    Returns:
        The validated region.

    Raises:
        ValidationError: If the region format is invalid.
    """
    if not region:
        raise ValidationError("region", "Region cannot be empty")

    if not _REGION_PATTERN.match(region):
        raise ValidationError("region", f"Invalid region format: {region}")

    return region


def validate_webhook_url(url: str) -> str:
    """Validate a webhook URL for security.

    Args:
        url: The webhook URL to validate.

    Returns:
        The validated URL.

    Raises:
        ValidationError: If the URL is invalid or uses an unsafe scheme.
    """
    if not url:
        raise ValidationError("url", "URL cannot be empty")

    parsed = urlparse(url)

    if parsed.scheme not in ("https",):
        raise ValidationError("url", f"Only HTTPS URLs are allowed, got scheme: {parsed.scheme}")

    if not parsed.hostname:
        raise ValidationError("url", "URL must have a valid hostname")

    # Prevent SSRF to internal networks
    hostname = parsed.hostname
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # It's a hostname, not an IP — validate the hostname format
        if not _HOSTNAME_PATTERN.match(hostname):
            raise ValidationError(
                "url", f"Invalid hostname in URL: {hostname}"
            ) from None
    else:
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValidationError(
                "url",
                "URLs pointing to private/internal networks are not allowed",
            )

    return url


def validate_file_size(path: Path, max_size: int, label: str = "file") -> None:
    """Validate that a file does not exceed a size limit.

    Args:
        path: Path to the file.
        max_size: Maximum allowed size in bytes.
        label: Human-readable label for error messages.

    Raises:
        ValidationError: If the file exceeds the size limit.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValidationError(label, f"Cannot stat file: {exc}") from exc

    if size > max_size:
        raise ValidationError(
            label,
            f"File size ({size} bytes) exceeds maximum ({max_size} bytes)",
        )


def sanitize_evidence(evidence: str, max_length: int = 500) -> str:
    """Sanitize finding evidence string to prevent injection.

    Strips control characters and limits length.

    Args:
        evidence: Raw evidence string.
        max_length: Maximum allowed length.

    Returns:
        Sanitized evidence string.
    """
    if not evidence:
        return ""
    # Remove control characters except newline and tab
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", evidence)
    return cleaned[:max_length]
