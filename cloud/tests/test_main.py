from argparse import Namespace
from io import StringIO
from unittest.mock import MagicMock, patch

from cloud.core import Finding, Severity, Status
from cloud.main import load_provider, main, write_report


def finding(status=Status.PASS):
    return Finding("TEST-001", "Test control", status, Severity.HIGH, "resource", "evidence")


def test_main_success():
    module = MagicMock()
    module.CONTROL_IDS = set()
    module.run_audit.return_value = [finding()]
    with patch("cloud.main.load_provider", return_value=module):
        assert main(["aws"]) == 0


def test_main_returns_failure_exit_code():
    module = MagicMock()
    module.CONTROL_IDS = set()
    module.run_audit.return_value = [finding(Status.FAIL)]
    with patch("cloud.main.load_provider", return_value=module):
        assert main(["aws", "--format", "json"]) == 1


def test_apply_requires_confirmation():
    assert main(["aws", "--mode", "apply"]) == 2


def test_load_provider_reports_internal_dependency():
    error = ModuleNotFoundError("missing boto3", name="boto3")
    with patch("cloud.main.importlib.import_module", side_effect=error):
        try:
            load_provider("aws")
        except RuntimeError as exc:
            assert "boto3" in str(exc)
        else:
            raise AssertionError("RuntimeError was not raised")


def test_sarif_report_contains_failed_result():
    stream = StringIO()
    write_report([finding(Status.FAIL)], "sarif", stream)
    assert '"ruleId": "TEST-001"' in stream.getvalue()


def test_provider_receives_options():
    module = MagicMock()
    module.CONTROL_IDS = {"AWS-S3-001"}
    module.run_audit.return_value = []
    with patch("cloud.main.load_provider", return_value=module):
        assert main(["aws", "--workers", "2", "--control", "AWS-S3-001"]) == 0
    options: Namespace = module.run_audit.call_args.args[0]
    assert options.workers == 2
    assert options.control == ["AWS-S3-001"]
    assert options.regions is None
    assert options.profiles is None


def test_unknown_control_is_rejected():
    module = MagicMock()
    module.CONTROL_IDS = {"AWS-S3-001"}
    with patch("cloud.main.load_provider", return_value=module):
        assert main(["aws", "--control", "NOT-REAL"]) == 2
    module.run_audit.assert_not_called()
