"""One escaping boundary for all evidence values displayed in HTML."""

import unicodedata
from html import escape


def text(value: object) -> str:
    if value is None:
        return "unknown"
    rendered = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf") and c not in "\n\t" else c
        for c in str(value)
    )
    return escape(rendered, quote=True)
