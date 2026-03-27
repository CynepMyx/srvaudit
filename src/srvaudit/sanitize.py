from __future__ import annotations

import shlex


def sanitize_fix_command(template: str, **values: str) -> str:
    for key, value in values.items():
        safe_value = shlex.quote(value)
        template = template.replace(f"{{{key}}}", safe_value)
    return template
