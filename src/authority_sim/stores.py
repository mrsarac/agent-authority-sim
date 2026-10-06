from __future__ import annotations


class StoreError(ValueError):
    def __init__(self) -> None:
        super().__init__("STORE_INVALID")


class UntrustedConflict(StoreError):
    def __init__(self) -> None:
        ValueError.__init__(self, "UNTRUSTED_CONFLICT")


class AcceptedContradiction(StoreError):
    def __init__(self) -> None:
        ValueError.__init__(self, "ACCEPTED_CONTRADICTION")


class StoreMissing(StoreError):
    def __init__(self) -> None:
        ValueError.__init__(self, "STORE_MISSING")


def _require_store_id(store_id: object) -> str:
    if type(store_id) is not str or not store_id or store_id.strip() != store_id:
        raise StoreError() from None
    return store_id


def _capture_bytes(data: object) -> bytes:
    if type(data) is bytes:
        return data
    if type(data) is bytearray:
        try:
            return bytes(data)
        except Exception:
            raise StoreError() from None
    raise StoreError() from None


def _find(entries: tuple[tuple[str, bytes], ...], store_id: str) -> bytes | None:
    for existing_id, existing_bytes in entries:
        if existing_id == store_id:
            return existing_bytes
    return None


def _without(
    entries: tuple[tuple[str, bytes], ...],
    store_id: str,
) -> tuple[tuple[str, bytes], ...]:
    return tuple(entry for entry in entries if entry[0] != store_id)


def _with_entry(
    entries: tuple[tuple[str, bytes], ...],
    store_id: str,
    data: bytes,
) -> tuple[tuple[str, bytes], ...]:
    return tuple(sorted(entries + ((store_id, data),), key=lambda entry: entry[0]))


class ImmutableStore:
    __slots__ = ("__untrusted", "__canonical")
    __untrusted: tuple[tuple[str, bytes], ...]
    __canonical: tuple[tuple[str, bytes], ...]

    def __init__(self) -> None:
        object.__setattr__(self, "_ImmutableStore__untrusted", ())
        object.__setattr__(self, "_ImmutableStore__canonical", ())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("STORE_INVALID")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("STORE_INVALID")

    def store(self, store_id: str, data: bytes | bytearray) -> None:
        stable_id = _require_store_id(store_id)
        stable_bytes = _capture_bytes(data)

        canonical_bytes = _find(self.__canonical, stable_id)
        if canonical_bytes is not None:
            if canonical_bytes == stable_bytes:
                return
            raise AcceptedContradiction() from None

        untrusted_bytes = _find(self.__untrusted, stable_id)
        if untrusted_bytes is not None:
            if untrusted_bytes == stable_bytes:
                return
            raise UntrustedConflict() from None

        object.__setattr__(
            self,
            "_ImmutableStore__untrusted",
            _with_entry(self.__untrusted, stable_id, stable_bytes),
        )

    def store_canonical(self, store_id: str, data: bytes | bytearray) -> None:
        stable_id = _require_store_id(store_id)
        stable_bytes = _capture_bytes(data)

        canonical_bytes = _find(self.__canonical, stable_id)
        if canonical_bytes is not None:
            if canonical_bytes == stable_bytes:
                return
            raise AcceptedContradiction() from None

        untrusted_bytes = _find(self.__untrusted, stable_id)
        if untrusted_bytes is not None and untrusted_bytes != stable_bytes:
            raise UntrustedConflict() from None

        object.__setattr__(
            self,
            "_ImmutableStore__untrusted",
            _without(self.__untrusted, stable_id),
        )
        object.__setattr__(
            self,
            "_ImmutableStore__canonical",
            _with_entry(self.__canonical, stable_id, stable_bytes),
        )

    def get(self, store_id: str) -> bytes:
        stable_id = _require_store_id(store_id)
        canonical_bytes = _find(self.__canonical, stable_id)
        if canonical_bytes is not None:
            return canonical_bytes
        untrusted_bytes = _find(self.__untrusted, stable_id)
        if untrusted_bytes is not None:
            return untrusted_bytes
        raise StoreMissing() from None
