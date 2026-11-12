"""Versioned application/invocation identity, independent of vulnerability oracles."""

import json
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from vulnproof.models.common import Contract, ImageId, Sha256, relative_path

Classification = Literal["confirmed", "inconclusive", "unsupported", "failed"]


class Decision(Contract):
    classification: Classification
    reason: str = Field(min_length=1)


class FixedParameter(Contract):
    name: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=4096)


class GetRequest(Contract):
    schema_version: Literal["1.0", "1.1"]
    route: str
    query_key: str
    fixed_query: tuple[FixedParameter, ...] = Field(max_length=64)
    control_value: str

    @model_validator(mode="after")
    def constructible(self) -> Self:
        from vulnproof.runner.control_driver import request_target

        request_target(self.model_dump(mode="json"), self.control_value)
        return self

    def target(self, value: str) -> str:
        from vulnproof.runner.control_driver import request_target

        return request_target(self.model_dump(mode="json"), value)


class ApplicationProfile(Contract):
    schema_version: Literal["1.0"] = "1.0"
    adapter: Literal["python-flask-object-v1"] = "python-flask-object-v1"
    source_fingerprint: Sha256
    entry_point: str = Field(min_length=1)
    image_id: ImageId
    preparation_sha256: Sha256

    @field_validator("entry_point")
    @classmethod
    def application_object(cls, value: str) -> str:
        file, separator, symbol = value.partition(":")
        if not separator or not relative_path(file).endswith(".py") or not symbol.isidentifier():
            raise ValueError("Expected captured Python file:application_symbol")
        return value


class HttpInvocation(Contract):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["http"] = "http"
    method: Literal["GET"] = "GET"
    request_target: str = Field(min_length=1)
    expected_status: Literal[200] = 200
    expected_body_sha256: Sha256
    input_location: Literal["query", "path"]
    input_name: str = Field(min_length=1)
    request_profile: GetRequest | None = None

    @field_validator("request_target")
    @classmethod
    def local_target(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("Expected a local HTTP request target")
        return value

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.request_profile:
            profile = self.request_profile
            kind = "path" if profile.schema_version == "1.1" else "query"
            if (
                profile.target(profile.control_value) != self.request_target
                or profile.query_key != self.input_name
                or kind != self.input_location
            ):
                raise ValueError("Invocation differs from its request profile")
        elif self.input_location != "query":
            raise ValueError("Path invocation requires a structured profile")
        return self


class ExecutionContext(Contract):
    schema_version: Literal["1.0"] = "1.0"
    application: ApplicationProfile
    invocation: HttpInvocation


def invocation_from_request(
    request: dict[str, str], profile: dict[str, Any] | None
) -> HttpInvocation:
    parsed = GetRequest.model_validate_json(json.dumps(profile)) if profile else None
    return HttpInvocation(
        request_target=request["request_target"],
        expected_body_sha256=request["body_sha256"],
        input_location="path" if parsed and parsed.schema_version == "1.1" else "query",
        input_name=parsed.query_key if parsed else request["query_key"],
        request_profile=parsed,
    )
