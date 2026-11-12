"""Reviewed built-in oracle dispatch. No dynamic imports or repository plugins."""

from types import MappingProxyType

from vulnproof.injections.oracles import command, sql, template
from vulnproof.investigation.assessment import Oracle

from .cwe22 import assess_path_traversal

VALIDATORS: MappingProxyType[str, Oracle] = MappingProxyType(
    {
        "cwe22-file-read-v1": assess_path_traversal,
        "command-injection-v1": command,
        "sql-injection-v1": sql,
        "template-injection-v1": template,
    }
)
