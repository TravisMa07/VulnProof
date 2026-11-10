"""Export the report contract without reading evidence or running tools."""

import json
from pathlib import Path

from vulnproof.reporting import ReportDocument


def schema_text() -> str:
    schema = ReportDocument.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:vulnproof:report:1.0"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    (root / "schemas/report-v1.schema.json").write_text(schema_text())
