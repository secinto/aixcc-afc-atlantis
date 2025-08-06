from pathlib import Path
from typing import NotRequired, TypedDict


class SandboxContext(TypedDict):
    project_name: str
    version: str
    project_directory: Path
    source_directory: NotRequired[
        tuple[Path, Path]
    ]  # (host directory, container directory)
    sanitizer: str
    fuzzing_language: str
    initial_crash_log: NotRequired[bytes]
    proof: bytes
    harness: str
    logging_directory: NotRequired[Path]
