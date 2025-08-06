from __future__ import annotations

from pathlib import Path

import docker
import docker.errors
import yaml
from docker.models.images import Image
from pydantic import BaseModel

from .types import SupportedLanguage


class _ProjectMetadata(BaseModel):
    language: SupportedLanguage
    sanitizers: list[str]
    fuzzing_engines: list[str]

    @staticmethod
    def from_yaml_string(yaml_string: str) -> _ProjectMetadata:
        data = yaml.safe_load(yaml_string)
        return _ProjectMetadata(**data)


class Project(BaseModel):
    directory: Path

    @property
    def name(self) -> str:
        return self.directory.name

    @property
    def metadata(self) -> _ProjectMetadata:
        metadata_file = self.directory / "project.yaml"
        if not metadata_file.exists():
            raise FileNotFoundError(f"Metadata file not found: {metadata_file}")

        yaml_string = metadata_file.read_text(encoding="utf-8")
        return _ProjectMetadata.from_yaml_string(yaml_string)

    def builder_image_or_none(self) -> Image | None:
        client = docker.from_env()

        try:
            return client.images.get(self.builder_image_name())
        except docker.errors.ImageNotFound:
            return None

    def build_builder_image(self) -> Image:
        client = docker.from_env()

        try:
            return client.images.get(self.builder_image_name())
        except docker.errors.ImageNotFound:
            image, _ = client.images.build(
                path=str(self.directory),
                dockerfile=str(self.directory / "Dockerfile"),
                tag=f"{self.builder_image_name()}:latest",
            )
            return image

    def builder_image_name(self) -> str:
        return f"pcb/{self.name}"


class ProjectCollection(list[Project]):
    @staticmethod
    def from_projects_directory(directory: Path) -> ProjectCollection:
        if not directory.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: {directory}")

        return ProjectCollection(
            [
                Project(directory=project_dir)
                for project_dir in directory.iterdir()
                if project_dir.is_dir() and (project_dir / "project.yaml").exists()
            ]
        )
