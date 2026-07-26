from typing import Any


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> Any:
    """Prevent spreadsheet applications from evaluating exported text as formulas."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(_FORMULA_PREFIXES):
        return f"'{value}"
    return value
