"""Real filesystem and synthetic Git repositories; no application code executes."""

import hashlib
import importlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from vulnproof.cli import main
from vulnproof.ingest import ingest_sarif
from vulnproof.provenance import CaptureFailure, ProvenanceDocument, capture_source, verify_capture
from vulnproof.provenance.filesystem import Tree
from vulnproof.provenance.models import CapturedFile, fingerprint

capture_module = importlib.import_module("vulnproof.provenance.capture")
filesystem_module = importlib.import_module("vulnproof.provenance.filesystem")


def ingestion(
    path: Path,
    *,
    finding_path: str = "app.py",
    line: int = 1,
    revision: str | None = None,
    partial: bool = False,
) -> Path:
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "Semgrep"}},
        "invocations": [{"executionSuccessful": True}],
        "results": [
            {
                "ruleId": "example.rule",
                "message": {"text": "Synthetic finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding_path},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
        ],
    }
    if revision is not None:
        run["versionControlProvenance"] = [{"revisionId": revision}]
    if partial:
        run["results"].append({})
    raw = json.dumps({"version": "2.1.0", "runs": [run]}).encode()
    path.write_text(ingest_sarif(raw).model_dump_json(indent=2) + "\n")
    return path


@pytest.fixture
def source(tmp_path: Path) -> Path:
    source = tmp_path / "application"
    source.mkdir()
    (source / "app.py").write_bytes(b"# Synthetic source; never imported\nanswer = 42\n")
    (source / "pkg").mkdir()
    (source / "pkg" / "helper.py").write_text("value = 1\n")
    return source


def git(root: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git-dependent test requires Git")
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    result = subprocess.run(
        [
            executable,
            "-c",
            "user.name=VulnProof Test",
            "-c",
            "user.email=test@example.invalid",
            "-C",
            str(root),
            *args,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()


def commit_source(source: Path) -> str:
    git(source, "-c", "init.templateDir=", "init", "-q")
    git(source, "add", "--", ".")
    git(source, "commit", "-qm", "Synthetic fixture")
    return git(source, "rev-parse", "HEAD")


def test_capture_preserves_bytes_and_unknown_scanner_identity(source: Path, tmp_path: Path) -> None:
    original = ingestion(tmp_path / "ingestion.json")
    before = original.read_bytes()
    result = capture_source(original, source, tmp_path / "result")
    published = tmp_path / "result" / "snapshot"
    assert original.read_bytes() == before
    assert (published / "ingestion.json").read_bytes() == before
    assert (published / "source" / "app.py").read_bytes() == (source / "app.py").read_bytes()
    assert result.ingestion_sha256 == hashlib.sha256(before).hexdigest()
    assert result.snapshot.files[0].path == "app.py"
    assert all(binding.source.state == "unverified" for binding in result.bindings)
    assert all(binding.source.observed_snapshot_id is None for binding in result.bindings)
    assert all(
        binding.source.expected_snapshot_id == result.snapshot.id for binding in result.bindings
    )
    assert result.bindings[0].location == "present"
    assert result.git.state == "unknown"
    assert result.snapshot.commit_id is None
    assert result.snapshot.dirty is None
    assert verify_capture(published) == result
    assert ProvenanceDocument.model_validate_json(result.model_dump_json()) == result
    assert (published / "source").stat().st_mode & 0o222 == 0
    assert (published / "source" / "app.py").stat().st_mode & 0o222 == 0
    assert not list((tmp_path / "result").glob(".pending-*"))


def test_deterministic_manifest_independent_of_root_and_mtime(source: Path, tmp_path: Path) -> None:
    original = ingestion(tmp_path / "in.json")
    a = capture_source(original, source, tmp_path / "a")
    other = tmp_path / "different-root"
    shutil.copytree(source, other)
    os.utime(other / "app.py", (100, 100))
    b = capture_source(original, other, tmp_path / "b")
    assert a.model_dump_json() == b.model_dump_json()
    (other / "pkg" / "helper.py").write_text("value = 2\n")
    c = capture_source(original, other, tmp_path / "c")
    assert c.snapshot.fingerprint != a.snapshot.fingerprint


@pytest.mark.parametrize("change", ["bytes", "rename", "execute_bit", "add", "delete"])
def test_content_identity_changes(source: Path, tmp_path: Path, change: str) -> None:
    original = ingestion(tmp_path / "in.json")
    before = capture_source(original, source, tmp_path / "before")
    file = source / "pkg" / "helper.py"
    if change == "bytes":
        file.write_text("changed\n")
    elif change == "rename":
        file.rename(source / "renamed.py")
    elif change == "execute_bit":
        file.chmod(0o755)
    elif change == "add":
        (source / "new.py").write_text("new\n")
    else:
        file.unlink()
    after = capture_source(original, source, tmp_path / "after")
    assert before.snapshot.fingerprint != after.snapshot.fingerprint


def test_exclusions_are_fixed_and_auditable(source: Path, tmp_path: Path) -> None:
    for name in (".cache", ".venv", "__pycache__"):
        (source / name).symlink_to(tmp_path / "outside", target_is_directory=True)
    original = ingestion(tmp_path / "in.json")
    result = capture_source(original, source, tmp_path / "out")
    assert set(result.excluded_paths) == {".cache", ".venv", "__pycache__"}
    assert len(result.files) == 2
    assert not (tmp_path / "out" / "snapshot" / "source" / ".cache").exists()


@pytest.mark.parametrize("kind", ["file_link", "directory_link", "fifo"])
def test_links_and_special_files_reject_entire_capture(
    source: Path, tmp_path: Path, kind: str
) -> None:
    outside = tmp_path / "private"
    outside.write_text("not captured")
    if kind == "file_link":
        (source / "link").symlink_to(outside)
    elif kind == "directory_link":
        (source / "link").symlink_to(tmp_path, target_is_directory=True)
    else:
        os.mkfifo(source / "fifo")
    original = ingestion(tmp_path / "in.json")
    with pytest.raises(CaptureFailure):
        capture_source(original, source, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_root_and_ancestor_symlinks_rejected(source: Path, tmp_path: Path) -> None:
    linked = tmp_path / "alias"
    linked.symlink_to(source, target_is_directory=True)
    original = ingestion(tmp_path / "in.json")
    for path in (linked, linked / "pkg"):
        with pytest.raises(OSError):
            capture_source(original, path, tmp_path / "out")
        assert not (tmp_path / "out").exists()


def test_output_cannot_be_inside_source_or_preexisting(source: Path, tmp_path: Path) -> None:
    original = ingestion(tmp_path / "in.json")
    with pytest.raises(CaptureFailure, match="outside"):
        capture_source(original, source, source / ".cache" / "out")
    existing = tmp_path / "out"
    existing.mkdir()
    (existing / "owner.txt").write_text("retain")
    with pytest.raises(FileExistsError):
        capture_source(original, source, existing)
    assert (existing / "owner.txt").read_text() == "retain"


@pytest.mark.parametrize(
    "path,line,expected",
    [
        ("missing.py", 1, "missing"),
        ("app.py", 100, "line_out_of_range"),
    ],
)
def test_missing_or_stale_location_retained(
    source: Path, tmp_path: Path, path: str, line: int, expected: str
) -> None:
    original = ingestion(tmp_path / "in.json", finding_path=path, line=line)
    result = capture_source(original, source, tmp_path / "out")
    assert result.bindings[0].location == expected
    assert result.bindings[0].reasons
    assert result.bindings[0].source.state == "unverified"
    assert verify_capture(tmp_path / "out" / "snapshot") == result


def test_clean_and_dirty_git_snapshots(source: Path, tmp_path: Path) -> None:
    commit = commit_source(source)
    original = ingestion(tmp_path / "in.json")
    clean = capture_source(original, source, tmp_path / "clean", expected_commit=commit)
    assert clean.snapshot.commit_id == commit
    assert clean.snapshot.dirty is False
    assert clean.bindings[0].source.state == "unverified"
    (source / "app.py").write_text("# Local edit\n")
    dirty = capture_source(original, source, tmp_path / "dirty")
    assert dirty.snapshot.commit_id == commit
    assert dirty.snapshot.dirty is True
    assert dirty.snapshot.fingerprint != clean.snapshot.fingerprint
    with pytest.raises(CaptureFailure, match="required clean revision"):
        capture_source(original, source, tmp_path / "reject", expected_commit=commit)
    assert not (tmp_path / "reject").exists()


def test_git_scope_is_source_subdirectory(source: Path, tmp_path: Path) -> None:
    commit_source(source)
    original = ingestion(tmp_path / "in.json", finding_path="helper.py")
    (source / "app.py").write_text("# Unrelated edit outside selected scope\n")
    result = capture_source(original, source / "pkg", tmp_path / "out")
    assert result.snapshot.dirty is False
    assert result.git.source_prefix == "pkg"


@pytest.mark.parametrize("change", ["untracked", "deleted", "mode"])
def test_git_dirty_checks_membership_and_modes(source: Path, tmp_path: Path, change: str) -> None:
    commit_source(source)
    if change == "untracked":
        (source / "extra.py").write_text("extra\n")
    elif change == "deleted":
        (source / "pkg" / "helper.py").unlink()
    else:
        (source / "app.py").chmod(0o755)
    result = capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert result.snapshot.dirty is True


@pytest.mark.parametrize("expected", ["short", "-HEAD", "a" * 40])
def test_required_revision_mismatch(source: Path, tmp_path: Path, expected: str) -> None:
    commit_source(source)
    with pytest.raises(CaptureFailure):
        capture_source(
            ingestion(tmp_path / "in.json"), source, tmp_path / "out", expected_commit=expected
        )
    assert not (tmp_path / "out").exists()


def test_reported_revision_mismatch_is_rejected(source: Path, tmp_path: Path) -> None:
    commit_source(source)
    with pytest.raises(CaptureFailure) as exc:
        capture_source(ingestion(tmp_path / "in.json", revision="a" * 40), source, tmp_path / "out")
    assert exc.value.code == "revision_mismatch"
    assert not (tmp_path / "out").exists()


def test_non_git_cannot_meet_explicit_revision(source: Path, tmp_path: Path) -> None:
    with pytest.raises(CaptureFailure) as exc:
        capture_source(
            ingestion(tmp_path / "in.json"), source, tmp_path / "out", expected_commit="a" * 40
        )
    assert exc.value.code == "revision_unknown"


def test_git_clean_filters_and_fsmonitor_are_not_executed(source: Path, tmp_path: Path) -> None:
    commit_source(source)
    marker = tmp_path / "must-not-exist"
    git(source, "config", "filter.test.clean", f"touch {marker}")
    git(source, "config", "filter.test.required", "true")
    git(source, "config", "core.fsmonitor", f"touch {marker}")
    (source / ".git" / "info").mkdir(exist_ok=True)
    (source / ".git" / "info" / "attributes").write_text("app.py filter=test\n")
    os.utime(source / "app.py", (1, 1))
    result = capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert result.snapshot.dirty is False
    assert not marker.exists()


def test_source_changes_and_interruption_cleanup(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ingestion(tmp_path / "in.json")
    real_scan = capture_module.scan_tree
    calls = 0

    def change_after_copy(descriptor: int, destination: Path | None = None) -> Tree:
        nonlocal calls
        result = real_scan(descriptor, destination)
        calls += 1
        if calls == 1:
            (source / "app.py").write_text("# Changed during capture\n")
        return cast(Tree, result)

    monkeypatch.setattr(capture_module, "scan_tree", change_after_copy)
    with pytest.raises(CaptureFailure, match="changed"):
        capture_source(original, source, tmp_path / "changed")
    assert not (tmp_path / "changed").exists()

    def interrupt(*args: object) -> Tree:
        raise KeyboardInterrupt

    monkeypatch.setattr(capture_module, "scan_tree", interrupt)
    with pytest.raises(KeyboardInterrupt):
        capture_source(original, source, tmp_path / "interrupted")
    assert not (tmp_path / "interrupted").exists()


@pytest.mark.parametrize(
    "limit,value",
    [
        ("MAX_FILE_BYTES", 4),
        ("MAX_FILES", 1),
        ("MAX_TOTAL_BYTES", 4),
        ("MAX_DEPTH", 0),
        ("MAX_ENTRIES", 1),
    ],
)
def test_capture_limits(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, value: int
) -> None:
    monkeypatch.setattr(filesystem_module, limit, value)
    with pytest.raises(CaptureFailure) as exc:
        capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert exc.value.code == "source_limit"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("target", ["source", "ingestion", "metadata", "extra_file"])
def test_capture_tampering_detected(source: Path, tmp_path: Path, target: str) -> None:
    capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    root = tmp_path / "out" / "snapshot"
    if target == "source":
        file = root / "source" / "app.py"
        file.chmod(0o644)
        file.write_text("tampered\n")
    elif target == "ingestion":
        file = root / "ingestion.json"
        file.chmod(0o644)
        file.write_text("{}")
    elif target == "metadata":
        file = root / "provenance.json"
        file.chmod(0o644)
        file.write_text("{}")
    else:
        (root / "source").chmod(0o755)
        (root / "source" / "new.py").write_text("new\n")
    with pytest.raises(CaptureFailure) as exc:
        verify_capture(root)
    assert exc.value.code == "invalid_capture"


def test_modified_ingestion_cannot_rebind_original_findings(source: Path, tmp_path: Path) -> None:
    original = ingestion(tmp_path / "in.json")
    data = json.loads(original.read_text())
    data["findings"][0]["finding"]["location"]["path"] = "pkg/helper.py"
    original.write_text(json.dumps(data))
    with pytest.raises(CaptureFailure) as exc:
        capture_source(original, source, tmp_path / "out")
    assert exc.value.code == "invalid_ingestion"
    assert not (tmp_path / "out").exists()


def test_contract_rejects_hash_and_binding_changes(source: Path, tmp_path: Path) -> None:
    doc = capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    data = json.loads(doc.model_dump_json())
    data["snapshot"]["fingerprint"] = "a" * 64
    with pytest.raises(ValidationError):
        ProvenanceDocument.model_validate_json(json.dumps(data))
    data = json.loads(doc.model_dump_json())
    data["bindings"][0]["source"]["state"] = "matched"
    data["bindings"][0]["source"]["observed_snapshot_id"] = doc.snapshot.id
    with pytest.raises(ValidationError):
        ProvenanceDocument.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("missing,expected", [(False, 0), (True, 1)])
def test_capture_and_verify_cli(source: Path, tmp_path: Path, missing: bool, expected: int) -> None:
    original = ingestion(tmp_path / "in.json", finding_path="absent.py" if missing else "app.py")
    out = tmp_path / "out"
    assert (
        main(
            [
                "capture",
                "--ingestion",
                str(original),
                "--source-root",
                str(source),
                "--output",
                str(out),
            ]
        )
        == expected
    )
    assert main(["verify-source", "--capture", str(out / "snapshot")]) == 0
    assert (
        main(
            [
                "capture",
                "--ingestion",
                str(original),
                "--source-root",
                str(source),
                "--output",
                str(out),
            ]
        )
        == 2
    )


def test_partial_ingestion_remains_visible(source: Path, tmp_path: Path) -> None:
    original = ingestion(tmp_path / "in.json", partial=True)
    assert (
        main(
            [
                "capture",
                "--ingestion",
                str(original),
                "--source-root",
                str(source),
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 1
    )
    doc = verify_capture(tmp_path / "out" / "snapshot")
    assert any(d.code == "ingestion_partial" for d in doc.diagnostics)


def test_fingerprint_v1_known_vector() -> None:
    file = CapturedFile(
        path="a.py",
        sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        size_bytes=3,
        executable=False,
        line_count=1,
    )
    assert (
        fingerprint((file,)) == "ac3816e2960d98f08677cf15ef20adf619fc85a3fb86bb62d5e7816e9e1c8709"
    )


@pytest.mark.parametrize("revision", ["main", "a" * 40])
def test_unknown_reported_revision_stays_explicit(
    source: Path, tmp_path: Path, revision: str
) -> None:
    result = capture_source(
        ingestion(tmp_path / "in.json", revision=revision), source, tmp_path / "out"
    )
    expected = "reported_revision_unknown" if revision == "main" else "reported_revision_unverified"
    assert any(d.code == expected for d in result.diagnostics)


def test_git_unavailable_is_optional(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit_source(source)
    git_module = importlib.import_module("vulnproof.provenance.git")
    monkeypatch.setattr(git_module.shutil, "which", lambda name: None)
    result = capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert result.snapshot.commit_id is None
    assert result.snapshot.dirty is None


@pytest.mark.parametrize("name", ["bad:name.py", "bad\nname.py"])
def test_unsupported_source_names_fail_explicitly(source: Path, tmp_path: Path, name: str) -> None:
    (source / name).write_text("data")
    with pytest.raises(CaptureFailure) as exc:
        capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert exc.value.code == "invalid_source_path"


def test_symlink_swap_between_stat_and_open_is_not_followed(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("outside data")
    real_open = os.open
    swapped = False

    def swap(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal swapped
        if path == "pkg" and dir_fd is not None and not swapped:
            swapped = True
            (source / "pkg").rename(source / "saved-pkg")
            (source / "pkg").symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(OSError):
        capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert swapped
    assert not (tmp_path / "out").exists()


def test_git_metadata_change_rejects_capture(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit_source(source)
    real_observe = capture_module.observe_git
    calls = 0

    def change_after_observation(root: Path) -> Any:
        nonlocal calls
        result = real_observe(root)
        calls += 1
        if calls == 1:
            git(source, "commit", "--allow-empty", "-qm", "Concurrent HEAD change")
        return result

    monkeypatch.setattr(capture_module, "observe_git", change_after_observation)
    with pytest.raises(CaptureFailure, match="Git identity changed"):
        capture_source(ingestion(tmp_path / "in.json"), source, tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_source_line_endings_are_counted_without_rewriting(
    source: Path, tmp_path: Path, newline: bytes
) -> None:
    data = newline.join([b"first", b"second", b""])
    (source / "app.py").write_bytes(data)
    result = capture_source(ingestion(tmp_path / "in.json", line=2), source, tmp_path / "out")
    assert result.bindings[0].location == "present"
    assert next(f for f in result.files if f.path == "app.py").line_count == 2
    assert (tmp_path / "out" / "snapshot" / "source" / "app.py").read_bytes() == data
