from __future__ import annotations

from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker


class SchemaInvalidError(ValueError):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("SCHEMA_INVALID")

    def __repr__(self) -> str:
        return "SchemaInvalidError('SCHEMA_INVALID')"


def _is_date_time(value: object) -> bool:
    if type(value) is not str:
        return False
    text = cast(str, value)
    if not text.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
        return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)
    except Exception:
        return False


def _format_checker() -> FormatChecker:
    checker = FormatChecker()
    checker.checks("date-time")(_is_date_time)
    return checker


def _require_exact_json_tree(value: object, active: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return
    if value_type is list:
        items = cast(list[object], value)
        marker = id(value)
        if marker in active:
            raise SchemaInvalidError() from None
        active.add(marker)
        try:
            for item in items:
                _require_exact_json_tree(item, active)
        finally:
            active.remove(marker)
        return
    if value_type is dict:
        mapping = cast(dict[object, object], value)
        marker = id(value)
        if marker in active:
            raise SchemaInvalidError() from None
        active.add(marker)
        try:
            for key, item in mapping.items():
                if type(key) is not str:
                    raise SchemaInvalidError() from None
                _require_exact_json_tree(item, active)
        finally:
            active.remove(marker)
        return
    raise SchemaInvalidError() from None


def _schema_path() -> Path:
    proof_root = Path(__file__).resolve().parents[2]
    return proof_root / "spec" / "v0.1.0" / "contracts.schema.json"


def load_schema() -> dict:
    try:
        path = _schema_path()
        if path.is_symlink() or not path.is_file():
            raise SchemaInvalidError()
        raw = path.read_bytes()
        schema = json.loads(raw.decode("utf-8"))
        _require_exact_json_tree(schema, set())
        if type(schema) is not dict:
            raise SchemaInvalidError()
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SchemaInvalidError()
        if schema.get("$id") != "urn:agent-authority-sim:contracts:0.1.0":
            raise SchemaInvalidError()
        refs = schema.get("oneOf")
        if type(refs) is not list or len(refs) != 8:
            raise SchemaInvalidError()
        Draft202012Validator.check_schema(schema)
        return schema
    except Exception:
        raise SchemaInvalidError() from None


def validate_document(document: dict) -> None:
    try:
        if type(document) is not dict:
            raise SchemaInvalidError()
        _require_exact_json_tree(document, set())
        schema = load_schema()
        validator = Draft202012Validator(
            schema,
            format_checker=_format_checker(),
        )
        validator.validate(document)
    except Exception:
        raise SchemaInvalidError() from None
