import logging
import tarfile
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

import docker
import docker.errors
from docker.models.containers import Container
from docker.models.images import Image


@contextmanager
def file_injected_container(
    container: Container,
    content: bytes,
    container_path: Path,
):
    with file_from_container(
        container=container,
        container_path=container_path,
    ) as file_or_none:
        original_content_or_none = file_or_none.read_bytes() if file_or_none else None

    original_tar_bytes_or_none = (
        _tar_bytes(content=original_content_or_none, path=Path(container_path.name))
        if original_content_or_none
        else None
    )

    modified_tar_bytes = _tar_bytes(
        content=content,
        path=Path(container_path.name),
    )

    try:
        container.put_archive(  # pyright: ignore[reportUnknownMemberType]
            str(container_path.parent),
            modified_tar_bytes,
        )
        with file_from_container(
            container=container,
            container_path=container_path,
        ) as file_or_none:
            assert file_or_none is not None
            yield file_or_none
    finally:
        if original_tar_bytes_or_none:
            container.put_archive(  # pyright: ignore[reportUnknownMemberType]
                str(container_path.parent),
                original_tar_bytes_or_none,
            )
        else:
            container.exec_run(  # pyright: ignore[reportUnknownMemberType]
                f"rm -f {container_path}",
            )


def _tar_bytes(
    content: bytes,
    path: Path,
):
    f = BytesIO()
    with tarfile.open(fileobj=f, mode="w") as tar:
        tar_info = tarfile.TarInfo(name=path.name)
        tar_info.size = len(content)

        tar.addfile(
            tarinfo=tar_info,
            fileobj=BytesIO(content),
        )

    f.seek(0)
    return f.getvalue()


@contextmanager
def file_from_container(
    container: Container,
    container_path: Path,
):
    try:
        bits, _ = container.get_archive(
            str(container_path),
        )
    except docker.errors.APIError:
        yield None
    else:
        f = BytesIO()
        for chunk in bits:
            f.write(chunk)
        f.seek(0)

        with TemporaryDirectory() as _temporary_directory_path_string:
            with tarfile.open(fileobj=f) as tar:
                tar.extractall(_temporary_directory_path_string)
                yield Path(_temporary_directory_path_string) / container_path.name


@contextmanager
def directory_from_container(
    container: Container,
    container_path: Path,
):
    bits, _ = container.get_archive(
        str(container_path),
    )

    f = BytesIO()
    for chunk in bits:
        f.write(chunk)
    f.seek(0)

    with TemporaryDirectory() as _temporary_directory_path_string:
        with tarfile.open(fileobj=f) as tar:
            tar.extractall(_temporary_directory_path_string)
            yield Path(_temporary_directory_path_string) / container_path.name


@contextmanager
def temporary_container(image: Image):
    client = docker.from_env(timeout=600)
    container = client.containers.run(  # pyright: ignore[reportUnknownMemberType]
        command=["tail", "-f", "/dev/null"],
        image=image,
        detach=True,
        shm_size="2g",  # FIXME: this is a workaround for the OOM issue
    )

    try:
        yield container
    finally:
        try:
            container.remove(force=True)
        except docker.errors.APIError as error:
            logging.exception(error)
