from pathlib import Path

OSS_FUZZ_PROJECTS_DIRECTORY = (
    Path(__file__).parent.parent.parent.parent.parent / "projects"
)

if not OSS_FUZZ_PROJECTS_DIRECTORY.exists():
    raise FileNotFoundError(
        f"OSS-Fuzz projects directory not found at {OSS_FUZZ_PROJECTS_DIRECTORY}"
    )
