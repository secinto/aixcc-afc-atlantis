import shutil
import tarfile
from io import BytesIO
from pathlib import Path

from docker.models.containers import Container


def load_directory_from_container(
    container: Container,
    root_directory: Path,
    container_absolute_path: Path,
):
    assert container_absolute_path.is_absolute()
    container_absolute_path = container_absolute_path.relative_to("/")
    shutil.rmtree(root_directory / container_absolute_path, ignore_errors=True)

    bits, _ = container.get_archive(str(container_absolute_path))  # pyright: ignore[reportUnknownMemberType]

    f = BytesIO()
    for chunk in bits:
        f.write(chunk)
    f.seek(0)

    with tarfile.open(fileobj=f, mode="r") as tar:
        tar.extractall(path=root_directory / container_absolute_path.parent)

    return (
        root_directory / container_absolute_path.parent / container_absolute_path.name
    )


def overwrite_directory_in_container(
    container: Container,
    source_directory: Path,
    container_path: Path,
):
    container.exec_run(["rm", "-rf", str(container_path)])  # pyright: ignore[reportUnknownMemberType]
    container.exec_run(["mkdir", "-p", str(container_path)])  # pyright: ignore[reportUnknownMemberType]

    f = BytesIO()

    with tarfile.open(fileobj=f, mode="w") as tar:
        tar.add(source_directory, arcname=container_path.name)

    f.seek(0)

    success = container.put_archive(str(container_path.parent), f.getvalue())  # pyright: ignore[reportUnknownMemberType]

    if not success:
        raise RuntimeError(
            f"Failed to overwrite {container_path} in container {container.name}"
        )


def candidate_file_or_none_in_container(
    path: Path, container_source_directory: Path, container: Container
):
    for candidate in candidates_files_in_container(
        path, container_source_directory, container
    ):
        return candidate


def candidates_files_in_container(
    path: Path, container_source_directory: Path, container: Container
):
    parts = path.parts[1:] if path.is_absolute() else path.parts

    for candidate in [
        container_source_directory / path,
        *[container_source_directory / Path(*parts[i:]) for i in range(len(parts))],
    ]:
        result = container.exec_run(cmd=["ls", str(candidate)])  # pyright: ignore[reportUnknownMemberType]

        if result.exit_code != 0:
            continue

        yield candidate
