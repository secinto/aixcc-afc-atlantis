import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Unpack

import docker
from docker_extension.container.context_managers import (
    file_injected_container,
    temporary_container,
)
from docker_extension.container.functions import (
    load_directory_from_container,
    overwrite_directory_in_container,
)

from ..project.models import Project
from .contexts import SandboxContext
from .functions import build_environment, scope_from_root_directory
from .models import Sandbox


class SandboxManager:
    def __init__(self, cache_directory: Path):
        self._cache_directory = cache_directory

    def scope(self, **context: Unpack[SandboxContext]):
        root_directory = (
            self._cache_directory / context["project_name"] / context["version"]
        )

        if not root_directory.exists():
            raise RuntimeError(
                f"Root directory {root_directory} not found. Please register the project first."
            )

        return scope_from_root_directory(root_directory=root_directory)

    @contextmanager
    def use(self, **context: Unpack[SandboxContext]):
        project = Project(directory=context["project_directory"])
        builder_image = project.builder_image_or_none()

        if builder_image is None:
            raise RuntimeError(
                f"Builder image for project {context['project_name']} not found. "
                "Please register the project first."
            )

        root_directory = (
            self._cache_directory / context["project_name"] / context["version"]
        )

        if not root_directory.exists():
            raise RuntimeError(
                f"Root directory {root_directory} not found. Please register the project first."
            )

        with TemporaryDirectory() as temporary_directory_path_string:
            temporary_directory = Path(temporary_directory_path_string)
            shutil.copytree(
                root_directory,
                temporary_directory,
                dirs_exist_ok=True,
                symlinks=True,
            )

            yield Sandbox(
                root_directory=temporary_directory,
                builder_image=builder_image,
                **context,
            )

    def register(self, **context: Unpack[SandboxContext]):
        root_directory = (
            self._cache_directory / context["project_name"] / context["version"]
        )
        project = Project(directory=context["project_directory"])
        builder_image = project.build_builder_image()

        with temporary_container(builder_image) as builder:
            if "source_directory" in context:
                host_directory, container_directory = context["source_directory"]
                overwrite_directory_in_container(
                    builder,
                    source_directory=host_directory,
                    container_path=container_directory,
                )

            exit_code, output = builder.exec_run(  # pyright: ignore[reportUnknownMemberType]
                [
                    "/bin/bash",
                    "-c",
                    'PATH=/ccache/bin:$PATH CFLAGS="$CFLAGS -O0" CXXFLAGS="$CXXFLAGS -O0" compile',
                ],
                environment=build_environment(**context),
                privileged=True,
                stdout=True,
                stderr=True,
            )

            if exit_code != 0:
                raise RuntimeError(
                    f"Failed to compile project {context['project_name']} "
                    f"with exit code {exit_code}.\n"
                    f"Output:\n{output.decode('utf-8', errors='ignore')}"
                )

            load_directory_from_container(
                container=builder,
                root_directory=root_directory,
                container_absolute_path=Path("/out"),
            )
            load_directory_from_container(
                container=builder,
                root_directory=root_directory,
                container_absolute_path=Path("/ccache/cache"),
            )
            load_directory_from_container(
                container=builder,
                root_directory=root_directory,
                container_absolute_path=Path("/src"),
            )

        subprocess.check_call(["gtags"], cwd=root_directory / "src")

        if "initial_crash_log" in context:
            crash_log = context["initial_crash_log"]
        else:
            client = docker.from_env()

            runner_image = client.images.get("ghcr.io/aixcc-finals/base-runner:v1.3.0")

            with temporary_container(runner_image) as runner:
                with file_injected_container(
                    runner,
                    content=context["proof"],
                    container_path=Path("/testcase"),
                ):
                    overwrite_directory_in_container(
                        runner,
                        source_directory=root_directory / "out",
                        container_path=Path("/out"),
                    )

                    _, crash_log = runner.exec_run(  # pyright: ignore[reportUnknownMemberType]
                        ["reproduce", context["harness"], "-runs=100"],
                        stdout=True,
                        stderr=True,
                        environment={
                            "HELPER": "True",
                            "ARCHITECTURE": "x86_64",  # FIXME: hardcoded for now
                        },
                    )

        (root_directory / "crash.log").write_bytes(crash_log)
