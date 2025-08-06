import logging
from contextlib import contextmanager
from pathlib import Path

import docker
from docker.models.images import Image

from ..container.context_managers import directory_from_container


@contextmanager
def directory_from_image(
    image: Image,
    image_path: Path,
):
    client = docker.from_env()
    container = client.containers.run(  # pyright: ignore[reportUnknownMemberType]
        image=image,
        command=["tail", "-f", "/dev/null"],
        detach=True,
    )

    try:
        with directory_from_container(container, image_path) as directory:
            yield directory
    finally:
        try:
            container.remove(force=True)
        except Exception as error:
            logging.exception(error)
