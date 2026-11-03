"""Shared value records. Validation does not read files or authenticate evidence."""

from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
Text = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CommitId = Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
ImageId = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]*$")]
Positive = Annotated[int, Field(gt=0)]
NonNegative = Annotated[int, Field(ge=0)]


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value == "."
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or ":" in value
        or str(path) != value
        or "\x00" in value
    ):
        raise ValueError("expected a normalized, relative POSIX path without root escapes")
    return value


RelativePath = Annotated[Text, AfterValidator(relative_path)]


class Contract(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
    )


class Reason(Contract):
    code: Identifier
    message: Text


class ToolIdentity(Contract):
    name: Text
    version: Text | None = None
    rule_pack: Text | None = None


class SourceLocation(Contract):
    path: RelativePath
    start_line: Positive
    end_line: Positive | None = None
    start_column: Positive | None = None
    end_column: Positive | None = None

    @model_validator(mode="after")
    def ordered_region(self) -> Self:
        end = self.end_line or self.start_line
        if end < self.start_line:
            raise ValueError("end_line precedes start_line")
        if (
            end == self.start_line
            and self.start_column is not None
            and self.end_column is not None
            and self.end_column < self.start_column
        ):
            raise ValueError("end_column precedes start_column")
        return self

    def overlaps(self, other: SourceLocation) -> bool:
        if self.path != other.path:
            return False
        left_end = self.end_line or self.start_line
        right_end = other.end_line or other.start_line
        if left_end < other.start_line or right_end < self.start_line:
            return False
        if self.start_line == left_end == other.start_line == right_end:
            if self.end_column is not None and other.start_column is not None:
                if self.end_column <= other.start_column:
                    return False
            if other.end_column is not None and self.start_column is not None:
                if other.end_column <= self.start_column:
                    return False
        return True


class SourceFile(Contract):
    path: RelativePath
    sha256: Sha256


class SourceSnapshot(Contract):
    id: Identifier
    fingerprint: Sha256 | None = None
    commit_id: CommitId | None = None
    dirty: bool | None = None
    files: tuple[SourceFile, ...] = ()

    @model_validator(mode="after")
    def unique_files(self) -> Self:
        paths = [item.path for item in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("snapshot contains duplicate file paths")
        return self


class SourceBinding(Contract):
    expected_snapshot_id: Identifier
    observed_snapshot_id: Identifier | None = None
    state: Literal["matched", "unverified", "mismatched"] = "unverified"
    reason: Reason

    @model_validator(mode="after")
    def observed_identity_required(self) -> Self:
        if self.state != "unverified" and self.observed_snapshot_id is None:
            raise ValueError("matched/mismatched bindings require an observed snapshot")
        return self


class Artifact(Contract):
    id: Identifier
    path: RelativePath
    media_type: Text
    sha256: Sha256 | None = None
    size_bytes: NonNegative | None = None
    truncated: bool | None = None
