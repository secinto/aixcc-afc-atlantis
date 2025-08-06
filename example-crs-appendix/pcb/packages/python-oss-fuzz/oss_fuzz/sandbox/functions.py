from pathlib import Path
from typing import Unpack

from p4_core.scope.protocols import Scope

from .contexts import SandboxContext


def build_environment(**context: Unpack[SandboxContext]):
    return {
        "FUZZING_ENGINE": "libfuzzer",  # FIXME: hardcoded for now
        "SANITIZER": context["sanitizer"],
        "ARCHITECTURE": "x86_64",  # FIXME: hardcoded for now
        "PROJECT_NAME": context["project_name"],
        "HELPER": "True",
        "FUZZING_LANGUAGE": context["fuzzing_language"],
    }


def scope_from_root_directory(
    root_directory: Path,
) -> Scope:
    return Scope(
        source_directory=root_directory / "src",
        initial_crash_log=(root_directory / "crash.log").read_text(
            encoding="utf-8", errors="ignore"
        ),
        global_executable=Path("global"),  # FIXME: hardcoded for now
    )
