from __future__ import annotations

from dataclasses import dataclass


_ERROR = "WORKSPACE_INVALID"


def _workspace_error() -> ValueError:
    return ValueError(_ERROR)


def _require_exact_text(value: object) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise _workspace_error() from None
    return value


@dataclass(frozen=True, slots=True)
class WorkspaceId:
    value: str

    def __post_init__(self) -> None:
        _require_exact_text(self.value)

    def __repr__(self) -> str:
        return "WorkspaceId(...)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class WorkspacePath:
    logical_path: str

    def __post_init__(self) -> None:
        value = _require_exact_text(self.logical_path)
        if (
            value.startswith(("/", "~"))
            or "\\" in value
            or "\0" in value
            or (len(value) >= 2 and value[1] == ":")
        ):
            raise _workspace_error() from None
        segments = value.split("/")
        for segment in segments:
            if (
                not segment
                or segment in (".", "..")
                or segment.strip() != segment
                or segment.startswith(("link:", "symlink:"))
                or "->" in segment
            ):
                raise _workspace_error() from None

    def __repr__(self) -> str:
        return "WorkspacePath(...)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class BoundWorkspacePath:
    workspace_id: WorkspaceId
    path: WorkspacePath

    def __post_init__(self) -> None:
        if type(self.workspace_id) is not WorkspaceId:
            raise _workspace_error() from None
        if type(self.path) is not WorkspacePath:
            raise _workspace_error() from None

    def __repr__(self) -> str:
        return "BoundWorkspacePath(...)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class SyntheticWorkspace:
    workspace_id: WorkspaceId

    def __post_init__(self) -> None:
        if type(self.workspace_id) is not WorkspaceId:
            raise _workspace_error() from None

    def resolve(
        self,
        workspace_id: WorkspaceId,
        path: WorkspacePath,
    ) -> BoundWorkspacePath:
        if type(workspace_id) is not WorkspaceId:
            raise _workspace_error() from None
        if type(path) is not WorkspacePath:
            raise _workspace_error() from None
        if workspace_id.value != self.workspace_id.value:
            raise _workspace_error() from None
        return BoundWorkspacePath(self.workspace_id, path)

    def __repr__(self) -> str:
        return "SyntheticWorkspace(...)"

    __str__ = __repr__
