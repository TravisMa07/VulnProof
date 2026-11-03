"""Regenerate the reviewed JSON Schema from the evidence models."""

import json
from pathlib import Path

from vulnproof.models import EvidenceBundle


def schema_text() -> str:
    schema = EvidenceBundle.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:vulnproof:evidence-bundle:1.0"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    destination = Path(__file__).resolve().parents[1] / "schemas/evidence-bundle-v1.schema.json"
    destination.write_text(schema_text())
    print(destination)
