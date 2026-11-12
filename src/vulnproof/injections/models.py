"""Versioned plans separate source evidence, operator declarations and observations."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.investigation.contracts import GetRequest
from vulnproof.models.common import Contract, RelativePath, Sha256

Capability = Literal["command", "sql", "template"]


class Endpoint(Contract):
    capability: Capability
    file: RelativePath
    handler: str = Field(min_length=1, max_length=256)
    request: GetRequest
    control_sha256: Sha256
    synthetic_sql_state: bool = False

    @model_validator(mode="after")
    def query_only(self) -> Self:
        if self.request.schema_version != "1.0":
            raise ValueError("Injection validation currently supports GET/query inputs only")
        if not self.request.control_value or len(self.request.control_value) > 1024:
            raise ValueError("Expected a bounded nonempty legitimate query value")
        if self.capability == "sql" and not self.synthetic_sql_state:
            raise ValueError("SQL validation requires explicitly synthetic database state")
        return self


class Configuration(Contract):
    schema_version: Literal["1.0"] = "1.0"
    endpoints: tuple[Endpoint, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def unique(self) -> Self:
        keys = [(e.capability, e.file, e.handler) for e in self.endpoints]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate endpoint profile")
        return self


class ValidationRequest(Contract):
    capability: Capability
    request: GetRequest
    control_sha256: Sha256

    @model_validator(mode="after")
    def query_only(self) -> Self:
        if self.request.schema_version != "1.0":
            raise ValueError("Expected GET/query validation")
        return self


class Entry(Contract):
    finding_id: str
    original_ref: str
    rule_id: str | None
    duplicate_of: str | None = None
    capability: Capability | None = None
    status: Literal["draft", "blocked"] = "blocked"
    reasons: tuple[str, ...] = ()
    result_id: str | None = None
    path_ids: tuple[str, ...] = ()
    endpoint: Endpoint | None = None
    prerequisites: tuple[str, ...] = ("prepared_application", "explicit_execution_authorization")

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.status == "draft" and (
            self.reasons or not self.result_id or not self.path_ids or not self.endpoint
        ):
            raise ValueError("Draft requires unambiguous static and invocation evidence")
        return self


class Plans(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["injection-planning-v1"] = "injection-planning-v1"
    scan_sha256: Sha256
    source_fingerprint: Sha256
    configuration_sha256: Sha256 | None
    investigations: dict[str, Sha256]
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    entries: tuple[Entry, ...]
    execution_authorized: Literal[False] = False


class ResponseObservation(Contract):
    method: Literal["GET"]
    target: str = Field(min_length=1, max_length=16384)
    request_body_bytes: Literal[0]
    request_body_sha256: Sha256
    request_headers_sha256: Sha256
    status: int = Field(ge=100, le=599)
    body_bytes: int = Field(ge=0, le=65536)
    body_sha256: Sha256
    truncated: Literal[False]
    marker_present: bool


class ProbeObservation(ResponseObservation):
    role: Literal["negative", "probe"]


class ValidationObservation(Contract):
    capability: Capability
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    control: ResponseObservation
    control_valid: bool
    attempts: tuple[ProbeObservation, ...] = Field(max_length=2)
