"""Installed, reviewed mappings only. Repository content cannot register executable code."""

from dataclasses import dataclass
from types import MappingProxyType

from .query_policy import PACK_VERSION, QUERY_ID, QUERY_RELATIVE, QUERY_SHA256


@dataclass(frozen=True)
class QuerySpec:
    id: str
    pack_version: str
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class RuleMapping:
    producer: str
    rule_id: str
    sink_family: str
    query_id: str
    validator_id: str


PATH_QUERY = QuerySpec(QUERY_ID, PACK_VERSION, QUERY_RELATIVE, QUERY_SHA256)
QUERIES = MappingProxyType({PATH_QUERY.id: PATH_QUERY})
RULE = "vulnproof.repository.request-file-read"
ROUTE_RULE = "vulnproof.repository.route-file-read"
SERVING_RULES = MappingProxyType(
    {
        "vulnproof.repository.send-file": "send_file",
        "vulnproof.repository.send-from-directory": "send_from_directory",
    }
)
RULES = tuple(
    RuleMapping("Semgrep OSS", rule, family, PATH_QUERY.id, "cwe22-file-read-v1")
    for rule, family in ((RULE, "open"), (ROUTE_RULE, "open"), *SERVING_RULES.items())
)


def mapping_for(producer: str | None, rule_id: str | None) -> RuleMapping | None:
    return next((m for m in RULES if (m.producer, m.rule_id) == (producer, rule_id)), None)
