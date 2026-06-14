from types import SimpleNamespace
from unittest.mock import MagicMock

from cloud.aws_harden import _check_aws_services
from cloud.core import Status


def options(control):
    return SimpleNamespace(control=[control], mode="audit")


def session_with(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def test_cloudtrail_requires_active_multi_region_trail():
    client = MagicMock()
    client.describe_trails.return_value = {
        "trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True}]
    }
    client.get_trail_status.return_value = {"IsLogging": True}
    findings = _check_aws_services(session_with(client), "123", options("AWS-CT-001"))
    assert findings[0].status == Status.PASS


def test_config_requires_active_recorder():
    client = MagicMock()
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"recording": False}]
    }
    findings = _check_aws_services(session_with(client), "123", options("AWS-CONFIG-001"))
    assert findings[0].status == Status.FAIL


def test_guardduty_requires_detector():
    client = MagicMock()
    client.list_detectors.return_value = {"DetectorIds": []}
    findings = _check_aws_services(session_with(client), "123", options("AWS-GD-001"))
    assert findings[0].status == Status.FAIL


def test_kms_rotation_failure_is_reported():
    client = MagicMock()
    client.list_keys.return_value = {"Keys": [{"KeyId": "key-1"}]}
    client.describe_key.return_value = {
        "KeyMetadata": {"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT"}
    }
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    findings = _check_aws_services(session_with(client), "123", options("AWS-KMS-001"))
    assert findings[0].status == Status.FAIL
