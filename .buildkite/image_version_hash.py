#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Pattern:
    pattern: str
    negated: bool
    anchored: bool
    has_slash: bool
    dir_only: bool


class DockerIgnore:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> list[Pattern]:
        dockerignore_path = self.repo_root / ".dockerignore"
        if not dockerignore_path.exists():
            return []

        patterns: list[Pattern] = []
        for raw_line in dockerignore_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            negated = line.startswith("!")
            if negated:
                line = line[1:]

            dir_only = line.endswith("/")
            if dir_only:
                line = line.rstrip("/")

            anchored = line.startswith("/")
            if anchored:
                line = line.lstrip("/")

            if not line:
                continue

            patterns.append(
                Pattern(
                    pattern=line,
                    negated=negated,
                    anchored=anchored,
                    has_slash="/" in line,
                    dir_only=dir_only,
                )
            )
        return patterns

    def is_ignored(self, relative_path: str, is_dir: bool) -> bool:
        path = relative_path.strip("/")
        if not path:
            return False

        ignored = False
        candidates = self._candidates(path, is_dir)
        for pattern in self.patterns:
            if any(
                self._matches(pattern, candidate, candidate_is_dir)
                for candidate, candidate_is_dir in candidates
            ):
                ignored = not pattern.negated
        return ignored

    @staticmethod
    def _candidates(path: str, is_dir: bool) -> list[tuple[str, bool]]:
        parts = path.split("/")
        candidates = [(path, is_dir)]
        for index in range(1, len(parts)):
            candidates.append(("/".join(parts[:index]), True))
        return candidates

    @staticmethod
    def _matches(pattern: Pattern, candidate: str, candidate_is_dir: bool) -> bool:
        if pattern.dir_only and not candidate_is_dir:
            return False

        if pattern.anchored or pattern.has_slash:
            return fnmatch.fnmatchcase(candidate, pattern.pattern)

        return any(
            fnmatch.fnmatchcase(segment, pattern.pattern)
            for segment in candidate.split("/")
        )


def run_git(*args: str, cwd: Path, stdin: str | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        input=stdin,
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def git_file_hash(repo_root: Path, relative_path: str) -> str:
    return run_git("hash-object", "--", relative_path, cwd=repo_root)


def git_text_hash(repo_root: Path, text: str) -> str:
    return run_git("hash-object", "--stdin", cwd=repo_root, stdin=text)


def collect_files(repo_root: Path, dockerignore: DockerIgnore) -> list[str]:
    files: list[str] = []

    def walk(current_dir: Path) -> None:
        for child in sorted(current_dir.iterdir(), key=lambda path: path.name):
            relative_path = child.relative_to(repo_root).as_posix()
            if dockerignore.is_ignored(relative_path, child.is_dir()):
                continue
            if child.is_dir():
                walk(child)
            elif child.is_file():
                files.append(relative_path)

    walk(repo_root)
    return files


def build_directory_hashes(repo_root: Path, files: list[str]) -> dict[str, str]:
    file_hashes = {path: git_file_hash(repo_root, path) for path in files}
    directory_entries: dict[str, list[tuple[str, str, str]]] = {".": []}

    for path, file_hash in file_hashes.items():
        parts = path.split("/")
        parent = "."
        for index, part in enumerate(parts):
            current = "/".join(parts[: index + 1])
            is_last = index == len(parts) - 1
            if is_last:
                directory_entries.setdefault(parent, []).append(
                    ("blob", part, file_hash)
                )
            else:
                directory_entries.setdefault(current, [])
                directory_entries.setdefault(parent, [])
                parent = current

    for directory in sorted(
        directory_entries.keys(),
        key=lambda item: (item.count("/"), item),
        reverse=True,
    ):
        if directory == ".":
            continue
        parent, _name = directory.rsplit("/", 1) if "/" in directory else (".", directory)
        directory_entries.setdefault(parent, [])

    directory_hashes: dict[str, str] = {}
    for directory in sorted(
        directory_entries.keys(),
        key=lambda item: (item.count("/"), item),
        reverse=True,
    ):
        resolved_entries: list[tuple[str, str, str]] = []
        for entry_type, name, entry_hash in directory_entries[directory]:
            resolved_entries.append((entry_type, name, entry_hash))

        child_directories = []
        prefix = "" if directory == "." else f"{directory}/"
        expected_depth = 0 if directory == "." else directory.count("/") + 1
        for child_directory, child_hash in directory_hashes.items():
            if child_directory == ".":
                continue
            if not child_directory.startswith(prefix):
                continue
            if child_directory.count("/") != expected_depth:
                continue
            child_name = child_directory[len(prefix) :]
            child_directories.append(("tree", child_name, child_hash))

        resolved_entries.extend(child_directories)
        resolved_entries.sort(key=lambda item: (item[0], item[1]))
        content = "".join(
            f"{entry_type} {name}\0{entry_hash}\n"
            for entry_type, name, entry_hash in resolved_entries
        )
        directory_hashes[directory] = git_text_hash(repo_root, content)

    return {**file_hashes, **directory_hashes}


def cargo_package_metadata(repo_root: Path) -> tuple[str, str]:
    in_package = False
    name = None
    version = None

    for raw_line in (repo_root / "Cargo.toml").read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_package = line == "[package]"
            continue
        if not in_package:
            continue

        match = re.match(r'^(name|version)\s*=\s*"([^"]+)"\s*$', line)
        if not match:
            continue

        key, value = match.groups()
        if key == "name":
            name = value
        elif key == "version":
            version = value

    if name is None or version is None:
        raise SystemExit("Cargo.toml [package] table must contain string name and version")
    return name, version


def docker_context_hash(repo_root: Path) -> str:
    dockerignore = DockerIgnore(repo_root)
    files = collect_files(repo_root, dockerignore)
    hashes = build_directory_hashes(repo_root, files)
    return hashes["."][:8]


def docker_image_tag(repo_root: Path) -> str:
    package_name, package_version = cargo_package_metadata(repo_root)
    return f"{package_name}:{package_version}-{docker_context_hash(repo_root)}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hash the Docker build context using git hash-object and .dockerignore filtering."
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Print hashes for the root context and included files/directories.",
    )
    parser.add_argument(
        "--tag",
        action="store_true",
        help="Print a Docker tag in the form <package-name>:<package-version>-<hash> using Cargo.toml.",
    )
    args = parser.parse_args()

    repo_root = Path(run_git("rev-parse", "--show-toplevel", cwd=Path.cwd()))
    root_hash = docker_context_hash(repo_root)

    if args.tag:
        print(docker_image_tag(repo_root))
        return 0

    if not args.details:
        print(root_hash)
        return 0

    for path in sorted(hashes.keys(), key=lambda item: (item != ".", item)):
        print(f"{hashes[path][:8]}  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
