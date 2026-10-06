from __future__ import annotations

from datetime import datetime, timedelta, timezone


_ERROR = "CLOCK_INVALID"


def _clock_error() -> ValueError:
    return ValueError(_ERROR)


def _require_worker_id(worker_id: object) -> str:
    if type(worker_id) is not str or not worker_id or worker_id.strip() != worker_id:
        raise _clock_error() from None
    return worker_id


def _require_delta(delta: object) -> timedelta:
    if type(delta) is not timedelta:
        raise _clock_error() from None
    return delta


class FakeClock:
    __slots__ = ("__authority_time", "__worker_skews")
    __authority_time: datetime
    __worker_skews: tuple[tuple[str, timedelta], ...]

    def __init__(self, initial_authority_time: datetime) -> None:
        if type(initial_authority_time) is not datetime:
            raise _clock_error() from None
        try:
            offset = initial_authority_time.utcoffset()
        except Exception:
            raise _clock_error() from None
        if (
            initial_authority_time.tzinfo is None
            or type(offset) is not timedelta
            or offset != timedelta(0)
        ):
            raise _clock_error() from None
        try:
            stable_authority_time = datetime(
                initial_authority_time.year,
                initial_authority_time.month,
                initial_authority_time.day,
                initial_authority_time.hour,
                initial_authority_time.minute,
                initial_authority_time.second,
                initial_authority_time.microsecond,
                tzinfo=timezone.utc,
                fold=initial_authority_time.fold,
            )
        except Exception:
            raise _clock_error() from None
        object.__setattr__(self, "_FakeClock__authority_time", stable_authority_time)
        object.__setattr__(self, "_FakeClock__worker_skews", ())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_ERROR)

    def authority_as_of(self) -> datetime:
        return self.__authority_time

    def worker_time(self, worker_id: str) -> datetime:
        stable_worker_id = _require_worker_id(worker_id)
        skew = timedelta(0)
        for existing_id, existing_skew in self.__worker_skews:
            if existing_id == stable_worker_id:
                skew = existing_skew
                break
        try:
            return self.__authority_time + skew
        except Exception:
            raise _clock_error() from None

    def advance_authority(self, delta: timedelta) -> None:
        stable_delta = _require_delta(delta)
        if stable_delta < timedelta(0):
            raise _clock_error() from None
        try:
            next_time = self.__authority_time + stable_delta
        except Exception:
            raise _clock_error() from None
        object.__setattr__(self, "_FakeClock__authority_time", next_time)

    def skew_worker(self, worker_id: str, delta: timedelta) -> None:
        stable_worker_id = _require_worker_id(worker_id)
        stable_delta = _require_delta(delta)
        retained = tuple(
            entry for entry in self.__worker_skews if entry[0] != stable_worker_id
        )
        object.__setattr__(
            self,
            "_FakeClock__worker_skews",
            retained + ((stable_worker_id, stable_delta),),
        )
