import logging
from pathlib import Path

import click
from joblib import Parallel, delayed
from oss_fuzz.project.globals import OSS_FUZZ_PROJECTS_DIRECTORY
from oss_fuzz.project.models import ProjectCollection
from oss_fuzz.sandbox.actors import SandboxManager
from oss_fuzz.sandbox.contexts import SandboxContext
from oss_fuzz_vulnerability.vulnerability.models import VulnerabilityCollection


@click.command()
@click.option(
    "--cache-directory",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path(__file__).parent.parent / ".cache",
)
def main(cache_directory: Path):
    projects = ProjectCollection.from_projects_directory(OSS_FUZZ_PROJECTS_DIRECTORY)
    vulnerabilities = [
        vulnerability
        for project in projects
        for vulnerability in VulnerabilityCollection.from_project(project)
    ]
    sandbox_contexts = [
        vulnerability.as_sandbox_context for vulnerability in vulnerabilities
    ]
    sandbox_manager = SandboxManager(cache_directory=cache_directory)

    def register(context: SandboxContext):
        try:
            sandbox_manager.register(**context)
        except Exception as e:
            logging.exception(e)

    Parallel(
        n_jobs=-1,
        backend="threading",
    )(delayed(register)(context) for context in sandbox_contexts)


if __name__ == "__main__":
    main()
