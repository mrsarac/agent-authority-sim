import json
import hashlib
from typing import Any

def _validate_strict(value: Any) -> None:
    """Strictly validates types for the simulator's canonical JSON."""
    if value is None:
        return
    if isinstance(value, bool):
        if type(value) is not bool:
            raise TypeError("Only exact bool accepted")
        return
    if isinstance(value, int):
        if type(value) is not int:
            raise TypeError("Only exact int accepted")
        return
    if isinstance(value, str):
        if type(value) is not str:
            raise TypeError("Only exact str accepted")
        return
    if isinstance(value, list):
        if type(value) is not list:
            raise TypeError("Only exact list accepted")
        for item in value:
            _validate_strict(item)
        return
    if isinstance(value, dict):
        if type(value) is not dict:
            raise TypeError("Only exact dict accepted")
        for k, v in value.items():
            if type(k) is not str:
                raise TypeError("Keys must be exact str")
            _validate_strict(v)
        return

    raise TypeError("Rejected type for canonical JSON")

def canonical_bytes(value: Any) -> bytes:
    """Returns canonical JSON bytes."""
    try:
        _validate_strict(value)
        json_str = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(',', ':'),
            allow_nan=False
        )
        return json_str.encode('utf-8')
    except (TypeError, ValueError, RecursionError) as e:
        # Wrap everything in a generic TypeError to avoid privacy leaks
        raise TypeError("Canonical serialization failed") from None

def sha256_digest(bytes_: bytes) -> str:
    """Returns sha256 digest with prefix."""
    if type(bytes_) is not bytes:
        raise TypeError("sha256_digest accepts exact built-in bytes only")

    h = hashlib.sha256(bytes_).hexdigest()
    return f"sha256:{h}"
