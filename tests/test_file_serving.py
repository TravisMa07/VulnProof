from pathlib import Path

import pytest

from vulnproof.correlation.file_reads import serving_arguments


@pytest.mark.parametrize(
    ("source", "family", "expected"),
    [
        ("from flask import send_file\nsend_file(name)", "send_file", 1),
        ("from flask import send_file as deliver\ndeliver(path_or_file=name)", "send_file", 1),
        ("import flask as f\nf.send_file(name)", "send_file", 1),
        ('from flask import send_from_directory as d\nd("/files", name)', "send_from_directory", 1),
        (
            'import flask\nflask.send_from_directory(directory="/files", path=name)',
            "send_from_directory",
            1,
        ),
        ("from other import send_file\nsend_file(name)", "send_file", 0),
        ("from flask import send_file\nsend_file = custom\nsend_file(name)", "send_file", 0),
        (
            "from flask import send_file\nfrom other import send_file\nsend_file(name)",
            "send_file",
            0,
        ),
        (
            "from flask import send_file\ndef view(send_file):\n return send_file(name)",
            "send_file",
            0,
        ),
        ("import flask\nflask.send_file = custom\nflask.send_file(name)", "send_file", 0),
        ("from flask import send_file\nsend_file(*args)", "send_file", 0),
        ("from flask import send_file\nsend_file(name, **options)", "send_file", 0),
        ("from flask import send_file\nsend_file(name)", "send_from_directory", 0),
    ],
)
def test_resolved_arguments(tmp_path: Path, source: str, family: str, expected: int) -> None:
    (tmp_path / "app.py").write_text(source)
    found = serving_arguments(tmp_path, "app.py", family)
    assert len(found) == expected
    for loc in found:
        assert loc.start_column and loc.end_column
        line = source.splitlines()[loc.start_line - 1]
        assert line[loc.start_column - 1 : loc.end_column - 1] == "name"


def test_directory_argument_not_filename(tmp_path: Path) -> None:
    source = (
        'from flask import send_from_directory\nsend_from_directory(user_directory, "manual.txt")'
    )
    (tmp_path / "app.py").write_text(source)
    loc = serving_arguments(tmp_path, "app.py", "send_from_directory")[0]
    assert loc.start_column and loc.end_column
    assert source.splitlines()[1][loc.start_column - 1 : loc.end_column - 1] == '"manual.txt"'
