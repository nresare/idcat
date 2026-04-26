#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
from pathlib import Path

from image_version_hash import docker_image_tag


def pipeline_yaml(tag: str, should_publish: bool = False) -> str:
    lines = [
        "steps:",
        "  - label: ':rust: rust build and test'",
        "    env:",
        "      RUSTFLAGS: -Dwarnings",
        "    commands:",
        "      - cargo fmt --check",
        "      - cargo clippy --workspace --locked --all-targets",
        "      - cargo test --workspace --locked",
        "    key: test",
    ]

    if should_publish:
        image_name, image_tag = tag.split(":", 1)
        lines.extend(
            [
                "  - label: ':whale: build docker image'",
                "    depends_on: test",
                "    agents:",
                "      arch: arm64",
                f"    command: docker buildx build -t {tag} .",
                "    plugins:",
                "      - docker-image-push#v1.1.0:",
                "          buildkite:",
                "            auth-method: oidc",
                f"          image: {image_name}",
                "          provider: buildkite",
                f"          tag: {image_tag}",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    tag = docker_image_tag(repo_root)
    should_publish = os.getenv("BUILDKITE_BRANCH") == "main"
    sys.stdout.write(pipeline_yaml(tag, should_publish))


if __name__ == "__main__":
    main()
