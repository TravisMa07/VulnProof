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
# Official bundled queries, fixed by installed policy rather than repository input.
INJECTION_QUERIES = MappingProxyType(
    {
        "command": QuerySpec(
            "py/command-line-injection",
            "1.8.13",
            "qlpacks/codeql/python-queries/1.8.13/Security/CWE-078/CommandInjection.ql",
            "aaa9684ea22778f9bd8e032dc825adb7cf48f01203174c6e0b014b9d9ba1922c",
        ),
        "sql": QuerySpec(
            "py/sql-injection",
            "1.8.13",
            "qlpacks/codeql/python-queries/1.8.13/Security/CWE-089/SqlInjection.ql",
            "e8324e568041a22d5d3a4ea21ef52ef791d67a699352273edda350caeca84964",
        ),
        "template": QuerySpec(
            "py/template-injection",
            "1.8.13",
            "qlpacks/codeql/python-queries/1.8.13/Security/CWE-074/TemplateInjection.ql",
            "256cb0700d0810562a9e6a79718c40a8861a60b80f1c5966c0ff70506ea6a714",
        ),
    }
)
QUERIES = MappingProxyType({q.id: q for q in (PATH_QUERY, *INJECTION_QUERIES.values())})
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


INJECTION_RULES = MappingProxyType(
    {
        key: RuleMapping(
            "Semgrep OSS",
            f"vulnproof.repository.{key}-injection",
            key,
            query.id,
            f"{key}-injection-v1",
        )
        for key, query in INJECTION_QUERIES.items()
    }
)
