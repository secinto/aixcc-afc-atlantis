import argparse
import functools
import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

import coloredlogs
import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
coloredlogs.install(fmt="%(asctime)s %(levelname)s %(message)s")


def log(message: str):
    logger.info(f"[CRS-TEST-SETUP] {message}")


def warn(message: str):
    logger.warning(f"[CRS-TEST-SETUP] {message}")


def error(message: str):
    logger.error(f"[CRS-TEST-SETUP] {message}")


def log_func(func):
    """Decorator to log function entry and exit."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        log(f"Running {func.__name__}")
        try:
            result = func(*args, **kwargs)
            log(f"Exiting {func.__name__}")
            return result
        except Exception as e:
            error(f"Error in {func.__name__}: {str(e)}")
            raise

    return wrapper


def run(cmd: list, env: dict[str, str] | None = None, cwd: str | None = None):
    cmd = list(map(str, cmd))

    logger.info(f'[RUN] {" ".join(cmd)}')
    if cwd:
        logger.info(f"Running in directory: {cwd}")

    if env is not None:
        logger.info(json.dumps(env, indent=2))
    try:
        combined_env = None
        if env is not None:
            combined_env = os.environ.copy()
            combined_env.update(env)

        ret = subprocess.run(
            " ".join(cmd),
            check=False,
            shell=True,
            # capture_output=True,
            # text=True,
            env=combined_env,
            cwd=cwd,
        )

        logger.info(f"Return code: {ret.returncode}")

        if ret.stdout:
            logger.info(f"STDOUT: {ret.stdout}")
        if ret.stderr:
            logger.error(f"STDERR: {ret.stderr}")
        if ret.returncode != 0:
            raise Exception(f"Command failed with return code {ret.returncode}")
        return ret
    except Exception as e:
        error(f"Failed to run command: {e}")
        raise


class SharedDir:
    def __init__(self, root_dir: Path, project_name: str):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir = root_dir / "build"
        self.out_dir = root_dir / "out"
        self.coverage_dir = root_dir / "coverage"
        self.reachability_dir = root_dir / "reachability"
        self.corpus_dir = root_dir / "corpus"
        self.call_trace_dir = root_dir / "call_trace"
        self.coverage_request_dir = root_dir / "coverage_request"
        self.original_sarif_dir = root_dir / "original_sarif"
        self.pocgen_dir = root_dir / "poc_gen"
        self.java_dir = root_dir / "java"

        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.coverage_dir.mkdir(parents=True, exist_ok=True)
        self.reachability_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.call_trace_dir.mkdir(parents=True, exist_ok=True)
        self.coverage_request_dir.mkdir(parents=True, exist_ok=True)
        self.original_sarif_dir.mkdir(parents=True, exist_ok=True)
        self.pocgen_dir.mkdir(parents=True, exist_ok=True)
        self.java_dir.mkdir(parents=True, exist_ok=True)

        shared_cpmeta_path = Path("./cpmetas") / f"{project_name}.json"
        if shared_cpmeta_path.exists():
            self.cpmeta_path = (
                self.java_dir
                / f"cpmeta-{hashlib.sha256(str(shared_cpmeta_path).encode()).hexdigest()}.json"
            )
            shutil.copy(shared_cpmeta_path, self.cpmeta_path)
        else:
            warn(f"CPMeta file {shared_cpmeta_path} does not exist")
            warn("Do not use Sootup for this project")


class MultilangDir:
    def __init__(
        self,
        root_dir: Path,
        original_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
        not_benchmark: bool,
    ):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.done_path = self.root_dir / "DONE"
        self.done_path.touch(exist_ok=True)
        if not not_benchmark:
            original_config_yaml = (
                original_oss_fuzz_dir
                / "projects"
                / "aixcc"
                / project_language
                / project_name
                / ".aixcc"
                / "config.yaml"
            )
            aixcc_config_yaml = self.root_dir / "aixcc_conf.yaml"
            shutil.copy(original_config_yaml, aixcc_config_yaml)
        else:
            warn("Not benchmark mode is enabled. Do not copy aixcc config.yaml")


class SarifDir:
    def __init__(
        self,
        root_dir: Path,
        original_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
        not_benchmark: bool,
    ):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir = self.root_dir / "build"
        self.out_dir = self.root_dir / "out"
        self.src_dir = self.root_dir / "src"
        self.work_dir = self.root_dir / "work"
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.src_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.full_project_name = (
            f"aixcc/{project_language}/{project_name}"
            if not not_benchmark
            else project_name
        )

        if not not_benchmark:
            original_config_yaml = (
                original_oss_fuzz_dir
                / "projects"
                / self.full_project_name
                / ".aixcc"
                / "config.yaml"
            )
            if not Path(self.work_dir / ".aixcc").exists():
                Path(self.work_dir / ".aixcc").mkdir(parents=True, exist_ok=True)

            aixcc_config_yaml = self.work_dir / ".aixcc" / "config.yaml"
            shutil.copy(original_config_yaml, aixcc_config_yaml)
        else:
            warn("Not benchmark mode is enabled. Do not copy aixcc config.yaml")

        original_project_yaml = (
            original_oss_fuzz_dir / "projects" / self.full_project_name / "project.yaml"
        )
        project_yaml = self.work_dir / "project.yaml"
        shutil.copy(original_project_yaml, project_yaml)


class CPManagerDir:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir = self.root_dir / "out"
        self.src_dir = self.root_dir / "src"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.src_dir.mkdir(parents=True, exist_ok=True)


class JavaDir:
    def __init__(self, root_dir: Path, project_name: str):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)


class TarballDir:
    def __init__(
        self,
        root_dir: Path,
        tarball_dir: Path,
        project_name: str,
        project_language: str,
        oss_fuzz_language: str,
        original_oss_fuzz_dir: Path,
        config_yaml: dict,
        project_yaml: dict,
        diff_mode: bool,
        not_benchmark: bool,
    ):
        self.project_name = project_name
        self.project_language = project_language
        self.oss_fuzz_language = oss_fuzz_language
        self.full_project_name = (
            f"aixcc/{self.oss_fuzz_language}/{self.project_name}"
            if not not_benchmark
            else self.project_name
        )
        self.original_oss_fuzz_dir = original_oss_fuzz_dir
        self.config_yaml = config_yaml
        self.project_yaml = project_yaml

        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)

        if (
            not (tarball_dir / project_name / "repo.tar.gz").exists()
            or not (tarball_dir / project_name / "oss-fuzz.tar.gz").exists()
        ):
            self.make_tarball(tarball_dir / project_name, diff_mode)
        else:
            log(f"Tarballs already exist for {project_name}")
            if diff_mode:
                warn(
                    f"Diff mode is enabled, but tarballs already exist for {project_name}. Using existing tarball."
                )

        original_repo_path = tarball_dir / project_name / "repo.tar.gz"
        self.repo_path = self.root_dir / "repo.tar.gz"
        shutil.copy(original_repo_path, self.repo_path)

        original_oss_fuzz_path = tarball_dir / project_name / "oss-fuzz.tar.gz"
        self.oss_fuzz_path = self.root_dir / "oss-fuzz.tar.gz"
        shutil.copy(original_oss_fuzz_path, self.oss_fuzz_path)

        original_diff_path = tarball_dir / project_name / "diff.tar.gz"
        if original_diff_path.exists():
            self.diff_path = self.root_dir / "diff.tar.gz"
            shutil.copy(original_diff_path, self.diff_path)

    def make_tarball(self, project_tarball_dir: Path, diff_mode: bool):
        log(f"Making tarball at {project_tarball_dir}")

        project_tarball_dir.mkdir(parents=True, exist_ok=True)

        main_repo = self.project_yaml["main_repo"]
        if self.config_yaml == {}:
            commit_hash = None
        else:
            if diff_mode:
                commit_hash = self.config_yaml["delta_mode"][0]["base_commit"]
            else:
                commit_hash = self.config_yaml["full_mode"]["base_commit"]

        # repo.tar.gz
        if not (project_tarball_dir / self.project_name).exists():
            run(
                ["git", "clone", main_repo, self.project_name],
                cwd=project_tarball_dir.resolve(),
            )
        if commit_hash is not None:
            run(
                ["git", "checkout", commit_hash],
                cwd=(project_tarball_dir / self.project_name).resolve(),
            )
        run(
            ["rm", "-rf", f"{self.project_name}/.git"],
            cwd=project_tarball_dir.resolve(),
        )
        run(
            ["tar", "-czvf", "repo.tar.gz", self.project_name],
            cwd=project_tarball_dir.resolve(),
        )
        log(f"Tarball created at {project_tarball_dir / 'repo.tar.gz'}")
        run(["rm", "-rf", self.project_name], cwd=project_tarball_dir.resolve())

        # oss-fuzz.tar.gz
        mock_c_ossfuzz_tarball = (
            project_tarball_dir / ".." / "mock-c" / "oss-fuzz.tar.gz"
        )
        run(
            ["cp", mock_c_ossfuzz_tarball.resolve(), "oss-fuzz.tar.gz"],
            cwd=project_tarball_dir.resolve(),
        )
        run(["tar", "-xvf", "oss-fuzz.tar.gz"], cwd=project_tarball_dir.resolve())
        run(["rm", "-rf", "oss-fuzz.tar.gz"], cwd=project_tarball_dir.resolve())
        run(
            ["rm", "-rf", "./fuzz-tooling/projects/*"],
            cwd=project_tarball_dir.resolve(),
        )
        run(
            [
                "rsync",
                "-a",
                self.original_oss_fuzz_dir.resolve()
                / "projects"
                / self.full_project_name,
                "./fuzz-tooling/projects/",
            ],
            cwd=project_tarball_dir.resolve(),
        )
        run(
            ["rm", "-rf", f"./fuzz-tooling/projects/{self.full_project_name}/.aixcc"],
            cwd=project_tarball_dir.resolve(),
        )
        run(
            ["tar", "-czvf", "oss-fuzz.tar.gz", "fuzz-tooling"],
            cwd=project_tarball_dir.resolve(),
        )
        log(f"Oss-fuzz tarball created at {project_tarball_dir / 'oss-fuzz.tar.gz'}")
        run(["rm", "-rf", "fuzz-tooling"], cwd=project_tarball_dir.resolve())

        # diff.tar.gz
        if diff_mode:
            Path(project_tarball_dir / "diff").mkdir(parents=True, exist_ok=True)
            run(
                [
                    "rsync",
                    "-a",
                    self.original_oss_fuzz_dir.resolve()
                    / "projects"
                    / self.full_project_name
                    / ".aixcc"
                    / "ref.diff",
                    "./diff",
                ],
                cwd=project_tarball_dir.resolve(),
            )
            run(
                ["tar", "-czvf", "diff.tar.gz", "diff"],
                cwd=project_tarball_dir.resolve(),
            )
            run(["rm", "-rf", "diff"], cwd=project_tarball_dir.resolve())


class PocGenDir:
    def __init__(
        self,
        root_dir: Path,
        joern_dir: Path,
        work_dir: Path,
        project_name: str,
        repo_src_path: Path,
        debug_src_dir: Path,
        debug_bin_dir: Path,
        shared_dir: Path,
    ):
        self.root_dir = root_dir
        self.joern_dir = joern_dir
        self.output_dir = self.root_dir / "output"
        self.work_dir = work_dir
        self.cp_name = project_name
        self.repo_src_path = repo_src_path
        self.debug_src_dir = debug_src_dir
        self.debug_bin_dir = debug_bin_dir
        self.shared_dir = shared_dir


class TestSetup:
    def __init__(
        self,
        crs_test_dir: Path,
        original_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
        tarball_dir: Path,
        diff_mode: bool,
        not_benchmark: bool,
        docker_work_dir: Path | None = None,
    ):
        self.crs_test_dir = crs_test_dir
        self.original_oss_fuzz_dir = original_oss_fuzz_dir
        self.project_name = project_name
        if project_language == "cpp":
            self.project_language = "c"
            self.oss_fuzz_language = "cpp"
        else:
            self.project_language = project_language
            self.oss_fuzz_language = project_language

        self.full_project_name = (
            f"aixcc/{self.oss_fuzz_language}/{self.project_name}"
            if not not_benchmark
            else self.project_name
        )
        with open(
            original_oss_fuzz_dir
            / "projects"
            / self.full_project_name
            / "project.yaml",
            "r",
        ) as f:
            project_yaml_data = yaml.safe_load(f)

        if not not_benchmark:
            with open(
                original_oss_fuzz_dir
                / "projects"
                / self.full_project_name
                / ".aixcc"
                / "config.yaml",
                "r",
            ) as f:
                config_yaml_data = yaml.safe_load(f)
            self.harness_names = [
                harness["name"] for harness in config_yaml_data["harness_files"]
            ]
        else:
            config_yaml_data = {}
            self.harness_names = []

        if docker_work_dir is None:
            docker_work_dir = Path("/workspace")
        self.docker_work_dir = docker_work_dir

        self.root_dir = self.crs_test_dir / self.project_name

        self.tarball_dir = TarballDir(
            self.root_dir / "tarball_dir",
            tarball_dir,
            project_name,
            project_language,
            self.oss_fuzz_language,
            original_oss_fuzz_dir,
            config_yaml_data,
            project_yaml_data,
            diff_mode,
            not_benchmark,
        )

        self.multilang_dir = MultilangDir(
            self.root_dir / "multilang_dir",
            self.original_oss_fuzz_dir,
            self.project_name,
            self.oss_fuzz_language,
            not_benchmark,
        )
        self.sarif_dir = SarifDir(
            self.root_dir / "sarif_dir",
            self.original_oss_fuzz_dir,
            self.project_name,
            self.oss_fuzz_language,
            not_benchmark,
        )
        self.java_dir = JavaDir(self.root_dir / "java_dir", self.project_name)
        self.shared_dir = SharedDir(self.root_dir / "shared_dir", self.project_name)
        self.cp_manager_dir = CPManagerDir(self.root_dir / "cp-manager_dir")
        self.pocgen_dir = PocGenDir(
            Path(os.environ.get("POC_GEN_DIR", "/app/llm-poc-gen")),
            Path(os.environ.get("JOERN_DIR", "/opt/joern")),
            self.sarif_dir.work_dir,
            self.project_name,
            self.cp_manager_dir.src_dir,
            self.sarif_dir.build_dir / "cpg_src",
            self.sarif_dir.build_dir / "debug",
            self.shared_dir.pocgen_dir,
        )


class TestEnv:
    def __init__(self, test_setup: TestSetup, crs_port: int = 4321):
        self.test_setup = test_setup
        self.crs_port = crs_port

    def build_env(self) -> dict[str, str]:
        return {
            "TARBALL_DIR": str(self.test_setup.tarball_dir.root_dir),
            "REGISTRY": "ghcr.io/team-atlanta",
            "PROJECT_NAME": self.test_setup.project_name,
            "PROJECT_LANGUAGE": self.test_setup.project_language,
            "HARNESS_NAMES": ":".join(self.test_setup.harness_names),
            "SOURCE_DIR": str(self.test_setup.cp_manager_dir.src_dir),
            "BUILDER_OUT_DIR": str(self.test_setup.cp_manager_dir.out_dir),
            "BUILD_SHARED_DIR": str(self.test_setup.shared_dir.build_dir),
            "SVF_MODE": "ander",
            # "SVF_PARALLEL": "True",
            # "SVF_MAX_WORKERS": "2",
            "SVF_PARALLEL": "False",
            "SVF_MAX_WORKERS": "1",
            "IMAGE_VERSION": "latest",
            "CODEQL_THREADS": "16",
        }

    def tracer_env(self) -> dict[str, str]:
        return {
            "CRS_SARIF_TRACER_CORPUS_DIRECTORY": "/corpus",
            "CRS_SARIF_TRACER_TRACE_OUTPUTDIR": "/output",
            "MULTILANG_BUILD_DIR": "/resources",
        }

    def _to_docker_path(self, path: Path) -> str:
        return str(path).replace(
            str(self.test_setup.root_dir), str(self.test_setup.docker_work_dir)
        )

    def crs_env(self) -> dict[str, str]:
        return {
            "VAPI_HOST": "http://localhost:4321",
            "CRS_TARGET": self.test_setup.project_name,
            "CRS_SARIF_REDIS_URL": "redis://redis:6379",
            "CRS_MODE": "debug",
            "BUILD_DIR": self._to_docker_path(self.test_setup.sarif_dir.build_dir),
            "OUT_DIR": self._to_docker_path(self.test_setup.sarif_dir.out_dir),
            "SRC_DIR": self._to_docker_path(self.test_setup.sarif_dir.src_dir),
            "PROJECT_NAME": self.test_setup.project_name,
            "PROJECT_LANGUAGE": self.test_setup.project_language,
            "TARBALL_DIR": self._to_docker_path(self.test_setup.tarball_dir.root_dir),
            "MULTILANG_BUILD_DIR": self._to_docker_path(
                self.test_setup.multilang_dir.root_dir
            ),
            "BUILD_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.build_dir
            ),
            "COVERAGE_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.coverage_dir
            ),
            "CORPUS_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.corpus_dir
            ),
            "REACHABILITY_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.reachability_dir
            ),
            "CALL_TRACE_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.call_trace_dir
            ),
            "COVERAGE_REQUEST_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.coverage_request_dir
            ),
            "ORIGINAL_SARIF_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.original_sarif_dir
            ),
            "JAVA_CP_METADATA_PATH": self._to_docker_path(
                self.test_setup.shared_dir.java_dir
            ),
            "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
            "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL"),
            "LITELLM_KEY": os.getenv("LITELLM_KEY"),
            "SANITIZER": "address",
            "FUZZING_ENGINE": "libfuzzer",
            "HELPER": "True",
            "FUZZING_LANGUAGE": self.test_setup.project_language,
            "POCGEN_ROOT_DIR": str(self.test_setup.pocgen_dir.root_dir),
            "POCGEN_JOERN_DIR": str(self.test_setup.pocgen_dir.joern_dir),
            "POCGEN_OUTPUT_DIR": f"{self.test_setup.pocgen_dir.output_dir}_{self.test_setup.project_name}",
            "POCGEN_WORK_DIR": self._to_docker_path(self.test_setup.sarif_dir.work_dir),
            "POCGEN_CP_NAME": self.test_setup.pocgen_dir.cp_name,
            "POCGEN_REPO_SRC_PATH": self._to_docker_path(
                self.test_setup.pocgen_dir.repo_src_path
            ),
            "POCGEN_DEBUG_SRC_DIR": self._to_docker_path(
                self.test_setup.pocgen_dir.debug_src_dir
            ),
            "POCGEN_DEBUG_BIN_DIR": self._to_docker_path(
                self.test_setup.pocgen_dir.debug_bin_dir
            ),
            "POCGEN_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.pocgen_dir
            ),
            "CRS_SARIF_PORT": str(self.crs_port),
            "BUILDER_OUT_DIR": "/out",
        }

    def crs_volumes(self) -> dict[str, str]:
        return {
            "CRS_SARIF_HOST_VOLUME": str(self.test_setup.root_dir.absolute()),
            "CRS_SARIF_DOCKER_VOLUME": str(self.test_setup.docker_work_dir),
        }


def main(args: argparse.Namespace):
    # load env for LLM keys
    load_dotenv(override=True)

    # Check if project name contains delta/diff but diff mode is not enabled
    if (
        "delta" in args.project_name.lower() or "diff" in args.project_name.lower()
    ) and not args.diff_mode:
        error(
            f"Project name '{args.project_name}' contains 'delta' or 'diff' but --diff-mode is not enabled. Consider using --diff-mode flag."
        )
        return

    test_setup = TestSetup(
        Path(args.crs_test_dir),
        Path(args.original_oss_fuzz_dir),
        args.project_name,
        args.project_language,
        Path(args.tarball_dir),
        args.diff_mode,
        args.not_benchmark,
    )
    test_env = TestEnv(test_setup, getattr(args, "crs_port", 4321))

    if args.run_docker_build:
        log("Running docker build...")

        run(
            [
                "bash",
                "./docker-build.sh",
            ]
        )
        log("Docker build completed")

    if args.run_sarif_build:
        log("Running sarif build...")

        run(
            [
                "python3",
                "./build.py",
            ],
            env=test_env.build_env(),
        )

        log("Sarif build completed")
        (test_setup.shared_dir.build_dir / "DONE").touch(exist_ok=True)

    if args.run_function_tracer:
        if args.not_benchmark:
            error(
                "Running function tracer with not-benchmark mode is not supported yet"
            )
            return

        log("Running function tracer...")
        if args.multilang_dir is None:
            raise ValueError("multilang-dir is required for function tracer")

        tracer_corpus_dir = test_setup.shared_dir.corpus_dir.resolve()
        tracer_output_dir = test_setup.shared_dir.call_trace_dir.resolve()
        tracer_fuzzer_dir = (
            Path(args.multilang_dir)
            / "libs"
            / "oss-fuzz"
            / "build"
            / "artifacts"
            / "aixcc"
            / test_setup.oss_fuzz_language
            / test_setup.project_name
            / "tarballs"
        )

        # Copy fuzzers.tar.gz from multilang-dir to crs-test-dir
        if not (tracer_fuzzer_dir / "fuzzers.tar.gz").exists():
            logger.warning(
                "fuzzers.tar.gz not found in multilang-dir. Building fuzzers..."
            )
            cmd = [
                ".venv/bin/python",
                "run.py",
                "run",
                "--target",
                f"aixcc/{test_setup.oss_fuzz_language}/{test_setup.project_name}",
                "--build-only",
            ]
            run(cmd, cwd=args.multilang_dir)

            logger.info("Fuzzers built successfully. Recheck fuzzers.tar.gz")

            if not (tracer_fuzzer_dir / "fuzzers.tar.gz").exists():
                raise ValueError(
                    "Building fuzzers failed. Please run multilang build first manually"
                )

        if test_setup.project_language in ["c", "cpp", "c++"]:
            tracer_dockername = "sarif-tracer-c"
        else:
            tracer_dockername = "sarif-tracer-java"

        # Copy seeds to test_dir
        seed_dir = Path("./seeds") / test_setup.project_name
        if not seed_dir.exists():
            warn(
                f"Seeds not found for {test_setup.project_name}. Turn on function-tracer without default corpus."
            )
        else:
            multilang_corpus_dir = tracer_corpus_dir / "crs-multilang"
            multilang_corpus_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(seed_dir, multilang_corpus_dir, dirs_exist_ok=True)

        run(
            [
                "docker",
                "run",
                "--name",
                f"sarif-tracer-{test_setup.project_name}",
                "-d" if not args.run_crs else "",
                "-v",
                f"{tracer_corpus_dir}:/corpus",
                "-v",
                f"{tracer_output_dir}:/output",
                "-v",
                f"{tracer_fuzzer_dir}:/resources",
                "-it",
                "-e",
                "CRS_SARIF_TRACER_CORPUS_DIRECTORY=/corpus",
                "-e",
                "CRS_SARIF_TRACER_TRACE_OUTPUTDIR=/output",
                "-e",
                "MULTILANG_BUILD_DIR=/resources",
                tracer_dockername,
            ],
            env=test_env.build_env(),
        )

        log("Running function tracer completed")
        log("Check the logs using docker logs -f sarif-tracer-<project-name>")

    if args.run_crs:
        if args.not_benchmark:
            error("Running CRS with not-benchmark mode is not supported yet")
        else:
            crs_env = test_env.crs_env()
            volumes_env = test_env.crs_volumes()
            crs_env.update(volumes_env)

            logger.info(json.dumps(crs_env, indent=2))

            run(
                [
                    "docker",
                    "compose",
                    "--project-name",
                    f"crs-sarif-{test_setup.project_name}",
                    "up",
                    "--build",
                    "--force-recreate",
                ],
                env=crs_env,
            )


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("--project-name", type=str, required=True)
    args.add_argument("--project-language", type=str, required=True)
    args.add_argument("--original-oss-fuzz-dir", type=str, required=True)
    args.add_argument("--crs-test-dir", type=str, required=True)
    args.add_argument("--tarball-dir", type=str, required=True)
    args.add_argument("--multilang-dir", type=str)
    args.add_argument(
        "--crs-port", type=int, default=4321, help="Port for CRS-SARIF service"
    )
    args.add_argument("--not-benchmark", action="store_true")
    args.add_argument("--diff-mode", action="store_true")
    args.add_argument("--run-docker-build", action="store_true")
    args.add_argument("--run-sarif-build", action="store_true")
    args.add_argument("--run-function-tracer", action="store_true")
    args.add_argument("--run-crs", action="store_true")
    args = args.parse_args()
    main(args)
