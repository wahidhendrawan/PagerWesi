import os
import subprocess
from pathlib import Path

import yaml

ACTION = Path(__file__).resolve().parent.parent / "action" / "action.yml"


def _steps() -> list[dict]:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]


def _run_audit_step(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess, Path]:
    script = next(step["run"] for step in _steps() if step.get("id") == "audit")
    stub = tmp_path / "pagerwesi" / "bin" / "pagerwesi"
    stub.parent.mkdir(parents=True)
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RUNNER_TEMP/argv"\n', encoding="utf-8")
    stub.chmod(0o755)
    output = tmp_path / "github_output"
    output.touch()
    defaults = {"PROVIDER": "secrets", "SCAN_PATH": "", "ENDPOINTS": "", "FORMAT": "text",
                "LOG_LEVEL": "info"}
    result = subprocess.run(
        # Same flags GitHub uses for `shell: bash`.
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(output),
             **defaults, **env},
        capture_output=True,
        text=True,
        check=False,
    )
    return result, output


def test_action_inputs_never_interpolated_into_shell():
    steps = _steps()
    assert all("${{" not in step.get("run", "") for step in steps)
    install = next(step["run"] for step in steps if step["name"] == "Install PagerWesi")
    assert '"$GITHUB_ACTION_PATH/..' in install


def test_action_passes_hostile_input_as_one_argument(tmp_path):
    hostile = "$(touch pwned); `touch pwned2`"
    result, output = _run_audit_step(tmp_path, SCAN_PATH=hostile, FORMAT="json")

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "pwned").exists() and not (tmp_path / "pwned2").exists()
    argv = (tmp_path / "argv").read_text(encoding="utf-8").splitlines()
    assert argv == ["secrets", "--format", "json", "--output", "pagerwesi-report.json",
                    "--log-level", "info", "--path", hostile]
    assert output.read_text(encoding="utf-8") == "report=pagerwesi-report.json\n"


def test_action_rejects_unknown_format_before_writing_outputs(tmp_path):
    result, output = _run_audit_step(tmp_path, FORMAT="json\nreport=/etc/passwd")

    assert result.returncode == 2
    assert output.read_text(encoding="utf-8") == ""
    assert not (tmp_path / "argv").exists()
