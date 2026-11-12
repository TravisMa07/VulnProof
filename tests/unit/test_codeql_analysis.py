"""Default checks use a trusted fake tool, never CodeQL or application execution."""

import hashlib
import importlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from vulnproof.cli import main
from vulnproof.ingest import ingest_sarif
from vulnproof.provenance import capture_source
from vulnproof.provenance.models import CapturedFile
from vulnproof.static import AnalysisDocument, AnalysisFailure, analyze_capture
from vulnproof.static.analysis import fixture_manifest
from vulnproof.static.models import QUERY_RELATIVE, CommandRecord
from vulnproof.static.process import run_command
from vulnproof.static.sarif import normalize_sarif

ROOT = Path(__file__).resolve().parents[2]
analysis_module = importlib.import_module("vulnproof.static.analysis")
process_module = importlib.import_module("vulnproof.static.process")


def location(line: int, *, uri: str = "app.py") -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%", "index": 0},
            "region": {"startLine": line},
        }
    }


def sarif() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.3"}},
                "artifacts": [{"location": {"uri": "app.py", "uriBaseId": "%SRCROOT%"}}],
                "results": [
                    {
                        "ruleId": "py/path-injection",
                        "locations": [location(19)],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {"location": location(n)} for n in (6, 6, 14, 19)
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }


def encode(value: object) -> bytes:
    return json.dumps(value).encode()


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    root = tmp_path / "fixture"
    root.mkdir()
    shutil.copyfile(ROOT / "fixtures/cwe22/vulnerable/app.py", root / "app.py")
    ingestion = tmp_path / "ingestion.json"
    ingestion.write_text(ingest_sarif(b'{"version":"2.1.0","runs":[]}').model_dump_json())
    capture_source(ingestion, root, tmp_path / "capture")
    return tmp_path / "capture" / "snapshot"


@pytest.fixture
def bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bundle = tmp_path / "trusted-fake-bundle"
    query = bundle / QUERY_RELATIVE
    query.parent.mkdir(parents=True)
    query.write_text("// Synthetic trusted test query\n")
    (query.parents[2] / "qlpack.yml").write_text("name: codeql/python-queries\nversion: 1.8.13\n")
    from dataclasses import replace

    monkeypatch.setattr(
        analysis_module,
        "PATH_QUERY",
        replace(analysis_module.PATH_QUERY, sha256=hashlib.sha256(query.read_bytes()).hexdigest()),
    )
    (bundle / "sarif.json").write_bytes(encode(sarif()))
    (bundle / "control.json").write_text("{}")
    executable = bundle / "codeql"
    executable.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """
import json, pathlib, sys
bundle = pathlib.Path(__file__).parent
control = json.loads((bundle / "control.json").read_text())
stage = "version" if sys.argv[1] == "version" else ("extract" if sys.argv[2] == "create" else "query")
with (bundle / "calls.jsonl").open("a") as stream:
    import os
    stream.write(json.dumps({"args": sys.argv[1:], "cwd": os.getcwd(), "env_keys": sorted(os.environ), "python_path": os.environ.get("PYTHONPATH")}) + "\\n")
if control.get("fail") == stage:
    print("synthetic command failure", flush=True)
    sys.exit(7)
if control.get("flood") == stage:
    print("x" * 4096, flush=True)
if stage == "version":
    print(json.dumps({"version": control.get("version", "2.27.3")}))
elif stage == "extract":
    database = pathlib.Path(sys.argv[3]); database.mkdir()
    source = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--source-root=")))
    (database / "source.txt").write_text(str(source))
    if control.get("tamper"):
        app = source / "app.py"; app.chmod(0o644); app.write_text("modified source\\n")
else:
    output = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--output=")))
    if control.get("oversized"):
        output.write_bytes(b"x" * 2048)
    elif control.get("malformed"):
        output.write_text("{broken")
    else:
        output.write_bytes((bundle / "sarif.json").read_bytes())
"""
    )
    executable.chmod(0o755)
    return bundle


def test_completed_analysis_is_source_bound_not_finding_bound(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    report = analyze_capture(capture, tmp_path / "out", bundle)
    assert report.outcome == "completed"
    assert report.normalization == "complete"
    assert report.source.state == "matched"
    assert len(report.results) == 1
    assert [loc.start_line for loc in report.results[0].paths[0].path.locations] == [6, 6, 14, 19]
    assert "finding_id" not in report.model_dump_json()
    assert "assessment" not in report.model_dump_json()
    assert report.raw_sarif and report.raw_sarif.truncated is False
    assert AnalysisDocument.model_validate_json(report.model_dump_json()) == report
    calls = [json.loads(line) for line in (bundle / "calls.jsonl").read_text().splitlines()]
    assert "--build-mode=none" in calls[1]["args"]
    assert "--max-paths=4" in calls[2]["args"]
    assert str(capture / "source") not in calls[1]["args"]
    assert "--command" not in " ".join(calls[1]["args"])
    assert calls[0]["cwd"] == str(tmp_path / "out" / "work")


@pytest.mark.parametrize(
    "key", ["CODEQL_SEARCH_PATH", "PYTHONPATH", "JAVA_TOOL_OPTIONS", "GITHUB_TOKEN"]
)
def test_environment_is_not_inherited(
    capture: Path, bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    monkeypatch.setenv(key, "synthetic-untrusted-value")
    assert analyze_capture(capture, tmp_path / "out", bundle).outcome == "completed"
    if key == "PYTHONPATH":
        assert all(
            json.loads(line)["python_path"] == str(bundle / "python/tools")
            for line in (bundle / "calls.jsonl").read_text().splitlines()
        )
        return
    assert all(
        key not in json.loads(line)["env_keys"]
        for line in (bundle / "calls.jsonl").read_text().splitlines()
    )


@pytest.mark.parametrize(
    "control,code",
    [
        ({"version": "other"}, "codeql_version"),
        ({"fail": "extract"}, "command_failed"),
        ({"fail": "query"}, "command_failed"),
        ({"malformed": True}, "invalid_sarif"),
        ({"tamper": True}, "source_changed"),
    ],
)
def test_failed_attempt_keeps_diagnostics_without_results(
    capture: Path, bundle: Path, tmp_path: Path, control: dict[str, Any], code: str
) -> None:
    (bundle / "control.json").write_text(json.dumps(control))
    report = analyze_capture(capture, tmp_path / "out", bundle)
    assert report.outcome == "failed"
    assert report.normalization == "not_attempted"
    assert report.source.state == "unverified"
    assert not report.results
    assert report.diagnostics[0].code == code
    assert (tmp_path / "out" / "analysis.json").is_file()


def test_missing_tool_and_modified_query_fail_explicitly(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    missing = analyze_capture(capture, tmp_path / "missing", tmp_path / "no-bundle")
    assert missing.diagnostics[0].code == "codeql_missing"
    (bundle / QUERY_RELATIVE).write_text("modified query")
    rejected = analyze_capture(capture, tmp_path / "changed-query", bundle)
    assert rejected.diagnostics[0].code == "query_mismatch"


def test_log_and_sarif_limits_are_explicit(
    capture: Path, bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_module, "MAX_LOG_BYTES", 128)
    (bundle / "control.json").write_text('{"flood":"extract"}')
    report = analyze_capture(capture, tmp_path / "log", bundle)
    assert report.commands[-1].outcome == "output_limit"
    assert report.commands[-1].log.truncated is True
    assert report.commands[-1].log.size_bytes == 128
    monkeypatch.setattr(process_module, "MAX_SARIF_BYTES", 128)
    monkeypatch.setattr(analysis_module, "MAX_SARIF_BYTES", 128)
    (bundle / "control.json").write_text('{"oversized":true}')
    report = analyze_capture(capture, tmp_path / "sarif", bundle)
    assert report.outcome == "failed"
    assert report.raw_sarif and report.raw_sarif.truncated is True
    assert report.raw_sarif.size_bytes == 128


def test_unknown_modified_capture_and_existing_output_are_rejected(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(FileExistsError):
        analyze_capture(capture, out, bundle)
    app = capture / "source/app.py"
    app.chmod(0o644)
    app.write_text("modified")
    with pytest.raises(ValueError):
        analyze_capture(capture, tmp_path / "bad", bundle)
    assert not (tmp_path / "bad").exists()


def test_unapproved_content_not_just_bad_manifest_is_rejected(tmp_path: Path, bundle: Path) -> None:
    root = tmp_path / "unapproved"
    root.mkdir()
    (root / "app.py").write_text("# Not an approved fixture\n")
    ingestion = tmp_path / "in.json"
    ingestion.write_text(ingest_sarif(b'{"version":"2.1.0","runs":[]}').model_dump_json())
    capture_source(ingestion, root, tmp_path / "capture")
    with pytest.raises(AnalysisFailure) as exc:
        analyze_capture(tmp_path / "capture/snapshot", tmp_path / "out", bundle)
    assert exc.value.code == "unapproved_fixture"
    assert not (bundle / "calls.jsonl").exists()


def test_empty_results_are_observations_not_safety(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    raw = sarif()
    raw["runs"][0]["results"] = []
    (bundle / "sarif.json").write_bytes(encode(raw))
    report = analyze_capture(capture, tmp_path / "out", bundle)
    assert report.outcome == "completed"
    assert report.normalization == "complete"
    assert not report.results
    assert "safe" not in report.model_dump_json()


def test_fixture_manifest_matches_both_reviewed_trees(tmp_path: Path) -> None:
    from vulnproof.provenance.filesystem import open_root, scan_tree
    from vulnproof.provenance.models import fingerprint

    expected = {f.fingerprint for f in fixture_manifest().fixtures}
    actual: set[str] = set()
    for variant in ("vulnerable", "patched"):
        with open_root(ROOT / "fixtures/cwe22" / variant) as fd:
            actual.add(fingerprint(scan_tree(fd).files))
    assert actual == expected


FILES = (
    CapturedFile(path="app.py", sha256="a" * 64, size_bytes=100, executable=False, line_count=40),
)


def test_alternatives_keep_result_boundaries_and_order() -> None:
    raw = sarif()
    result = raw["runs"][0]["results"][0]
    result["codeFlows"][0]["threadFlows"].append(
        {"locations": [{"location": location(n)} for n in (14, 18, 19)]}
    )
    raw["runs"][0]["results"].append(json.loads(json.dumps(result)))
    results, notes = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert not notes
    assert len(results) == 2
    assert all(len(r.paths) == 2 for r in results)
    assert len({p.path.id for r in results for p in r.paths}) == 4
    assert [loc.start_line for loc in results[0].paths[1].path.locations] == [14, 18, 19]


@pytest.mark.parametrize(
    "uri",
    [
        "../outside.py",
        "/outside/app.py",
        "https://example.org/app.py",
        "%252e%252e/app.py",
        "a\\app.py",
        "app.py?",
        "app%00.py",
    ],
)
def test_unresolvable_nodes_do_not_get_silently_dropped(uri: str) -> None:
    raw = sarif()
    node = raw["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][1]
    node["location"]["physicalLocation"]["artifactLocation"] = {"uri": uri}
    results, _ = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert not results[0].paths
    assert results[0].observed_paths == 1
    assert results[0].diagnostics[0].code == "path_unavailable"


@pytest.mark.parametrize(
    "mode", ["no_flow", "one_node", "bad_index", "wrong_sink", "bad_line", "wrong_rule"]
)
def test_incomplete_or_incompatible_observations_are_retained(mode: str) -> None:
    raw = sarif()
    result = raw["runs"][0]["results"][0]
    thread = result["codeFlows"][0]["threadFlows"][0]
    if mode == "no_flow":
        result.pop("codeFlows")
    elif mode == "one_node":
        thread["locations"] = [{"location": location(19)}]
    elif mode == "bad_index":
        thread["locations"][0]["location"]["physicalLocation"]["artifactLocation"]["index"] = 9
    elif mode == "wrong_sink":
        thread["locations"][-1] = {"location": location(18)}
    elif mode == "bad_line":
        thread["locations"][0] = {"location": location(100)}
    else:
        result["ruleId"] = "other/query"
    results, _ = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert len(results) == 1
    assert not results[0].paths
    assert results[0].diagnostics


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b"\xff",
        b'{"version":"2.1.0","runs":[],"x":NaN}',
        b'{"version":"2.1.0","version":"2.1.0","runs":[]}',
        b"[" * 65 + b"0" + b"]" * 65,
    ],
)
def test_bad_sarif_fails_without_a_no_path_observation(raw: bytes) -> None:
    with pytest.raises(AnalysisFailure):
        normalize_sarif(raw, Path("/fixed/source"), FILES)


def test_contract_rejects_false_success(capture: Path, bundle: Path, tmp_path: Path) -> None:
    report = analyze_capture(capture, tmp_path / "out", bundle)
    data = json.loads(report.model_dump_json())
    data["source"]["state"] = "unverified"
    with pytest.raises(ValidationError):
        AnalysisDocument.model_validate_json(json.dumps(data))


def test_cli_partial_and_failed_results(capture: Path, bundle: Path, tmp_path: Path) -> None:
    args = ["analyze", "--capture", str(capture), "--codeql-bundle", str(bundle), "--output"]
    assert main([*args, str(tmp_path / "ok")]) == 0
    raw = sarif()
    raw["runs"][0]["results"][0].pop("codeFlows")
    (bundle / "sarif.json").write_bytes(encode(raw))
    assert main([*args, str(tmp_path / "partial")]) == 1
    (bundle / "control.json").write_text('{"fail":"extract"}')
    assert main([*args, str(tmp_path / "failed")]) == 1


def test_process_timeout_stops_descendants(tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()
    (tmp_path / "diagnostics").mkdir()
    marker = tmp_path / "must-not-exist"
    child = f"import time; from pathlib import Path; time.sleep(0.5); Path({str(marker)!r}).write_text('alive')"
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-I','-c',{child!r}]); print('ready',flush=True); time.sleep(30)"
    records: list[CommandRecord] = []
    with pytest.raises(AnalysisFailure):
        run_command(
            [sys.executable, "-I", "-c", parent],
            stage="extract",
            root=tmp_path,
            env=dict(os.environ),
            timeout=0.15,
            records=records,
        )
    time.sleep(0.6)
    assert not marker.exists()
    assert records[-1].outcome == "timed_out"


def test_interruption_retains_failed_report(
    capture: Path, bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(*args: object, **kwargs: object) -> bytes:
        raise KeyboardInterrupt

    monkeypatch.setattr(analysis_module, "run_command", interrupt)
    with pytest.raises(KeyboardInterrupt):
        analyze_capture(capture, tmp_path / "out", bundle)
    report = AnalysisDocument.model_validate_json((tmp_path / "out/analysis.json").read_bytes())
    assert report.outcome == "failed"
    assert report.diagnostics[0].code == "analysis_interrupted"


@pytest.mark.parametrize("uri", ["/fixed/source/app.py", "file:///fixed/source/app.py"])
def test_absolute_locations_only_within_exact_analysis_root(uri: str) -> None:
    raw = sarif()
    result = raw["runs"][0]["results"][0]
    for node in result["codeFlows"][0]["threadFlows"][0]["locations"]:
        node["location"]["physicalLocation"]["artifactLocation"]["uri"] = uri
    results, notes = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert not notes
    assert len(results[0].paths) == 1


def test_artifact_index_only_and_conflicting_rule_references() -> None:
    raw = sarif()
    result = raw["runs"][0]["results"][0]
    for node in result["codeFlows"][0]["threadFlows"][0]["locations"]:
        node["location"]["physicalLocation"]["artifactLocation"] = {"index": 0}
    results, _ = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert len(results[0].paths) == 1
    result["rule"] = {"id": "other/query"}
    results, _ = normalize_sarif(encode(raw), Path("/fixed/source"), FILES)
    assert not results[0].paths
    assert results[0].diagnostics[0].code == "result_unavailable"


@pytest.mark.parametrize(
    "metadata",
    ["failed_invocation", "malformed_invocation", "wrong_version", "external_properties"],
)
def test_invalid_run_metadata_fails_the_analysis(metadata: str) -> None:
    raw = sarif()
    run = raw["runs"][0]
    if metadata == "failed_invocation":
        run["invocations"] = [{"executionSuccessful": False}]
    elif metadata == "malformed_invocation":
        run["invocations"] = [{"executionSuccessful": "true"}]
    elif metadata == "wrong_version":
        run["tool"]["driver"]["semanticVersion"] = "other"
    else:
        run["externalPropertyFileReferences"] = {}
    with pytest.raises(AnalysisFailure):
        normalize_sarif(encode(raw), Path("/fixed/source"), FILES)


def test_notifications_and_missing_path_remain_partial(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    raw = sarif()
    raw["runs"][0]["invocations"] = [
        {
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": "Synthetic warning"}}
            ],
        }
    ]
    raw["runs"][0]["results"][0].pop("codeFlows")
    (bundle / "sarif.json").write_bytes(encode(raw))
    report = analyze_capture(capture, tmp_path / "out", bundle)
    assert report.outcome == "completed"
    assert report.normalization == "partial"
    assert report.diagnostics[0].code == "codeql_notification"
    assert report.results[0].diagnostics[0].code == "paths_unavailable"


def test_retained_artifact_hashes_match_actual_bytes(
    capture: Path, bundle: Path, tmp_path: Path
) -> None:
    root = tmp_path / "out"
    report = analyze_capture(capture, root, bundle)
    assert report.raw_sarif is not None
    for artifact in [report.raw_sarif, *(c.log for c in report.commands)]:
        data = (root / artifact.path).read_bytes()
        assert hashlib.sha256(data).hexdigest() == artifact.sha256
        assert len(data) == artifact.size_bytes


def test_process_interruption_records_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "work").mkdir()
    (tmp_path / "diagnostics").mkdir()

    class InterruptSelector:
        def __enter__(self) -> InterruptSelector:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def register(self, *args: object) -> None:
            pass

        def get_map(self) -> bool:
            return True

        def select(self, timeout: float) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(process_module.selectors, "DefaultSelector", InterruptSelector)
    records: list[CommandRecord] = []
    with pytest.raises(KeyboardInterrupt):
        run_command(
            [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
            stage="extract",
            root=tmp_path,
            env=dict(os.environ),
            timeout=5,
            records=records,
        )
    assert records[0].outcome == "interrupted"
    assert records[0].return_code is not None
