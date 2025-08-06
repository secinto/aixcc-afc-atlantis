from pathlib import Path
from typing import Unpack, cast

import docker
from docker.models.images import Image
from docker_extension.container.context_managers import (
    file_injected_container,
    temporary_container,
)
from docker_extension.container.functions import (
    load_directory_from_container,
    overwrite_directory_in_container,
)
from p4_core.scope.protocols import BaseSandbox, Scope

from .contexts import SandboxContext
from .functions import build_environment, scope_from_root_directory


class Sandbox(BaseSandbox):
    def __init__(
        self,
        root_directory: Path,
        builder_image: Image,
        **context: Unpack[SandboxContext],
    ):
        self.root_directory = root_directory
        self._builder_image = builder_image
        self._context = context

    @property
    def scope(self) -> Scope:
        return scope_from_root_directory(root_directory=self.root_directory)

    @property
    def _out_directory(self) -> Path:
        return self.root_directory / "out"

    @property
    def _ccache_cache_directory(self) -> Path:
        return self.root_directory / "ccache" / "cache"

    def build(self):
        with temporary_container(self._builder_image) as builder:
            overwrite_directory_in_container(
                builder,
                source_directory=self.scope["source_directory"],
                container_path=Path("/src"),
            )
            overwrite_directory_in_container(
                builder,
                source_directory=self._ccache_cache_directory,
                container_path=Path("/ccache/cache"),
            )
            overwrite_directory_in_container(
                builder,
                source_directory=self._out_directory,
                container_path=Path("/out"),
            )

            exit_code, (stdout, stderr) = builder.exec_run(  # pyright: ignore[reportUnknownMemberType]
                [
                    "/bin/bash",
                    "-c",
                    'PATH=/ccache/bin:$PATH CFLAGS="$CFLAGS -O0" CXXFLAGS="$CXXFLAGS -O0" compile',
                ],
                environment=build_environment(**self._context),
                privileged=True,
                stdout=True,
                stderr=True,
                demux=True,
            )

            stdout = cast(
                bytes,
                stdout,
            ).decode("utf-8", errors="ignore")
            stderr = cast(
                bytes,
                stderr,
            ).decode("utf-8", errors="ignore")

            if exit_code == 0:
                load_directory_from_container(
                    container=builder,
                    root_directory=self.root_directory,
                    container_absolute_path=Path("/out"),
                )

            return exit_code, stdout, stderr

    def reproduce(self):
        client = docker.from_env()
        runner_image = client.images.get("ghcr.io/aixcc-finals/base-runner:v1.1.0")

        with temporary_container(runner_image) as runner:
            with file_injected_container(
                runner,
                content=self._context["proof"],
                container_path=Path("/testcase"),
            ):
                overwrite_directory_in_container(
                    runner,
                    source_directory=self._out_directory,
                    container_path=Path("/out"),
                )

                exit_code, output = runner.exec_run(  # pyright: ignore[reportUnknownMemberType]
                    ["reproduce", self._context["harness"], "-runs=100"],
                    stdout=True,
                    stderr=True,
                    environment={
                        "HELPER": "True",
                        "ARCHITECTURE": "x86_64",  # FIXME: hardcoded for now
                    },
                )

            output = cast(
                bytes,
                output,
            ).decode("utf-8", errors="ignore")

            return exit_code, output
