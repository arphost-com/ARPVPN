from pathlib import Path
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_pipeline():
    return yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))


def test_pipeline_has_required_gates_and_manual_final_jobs():
    pipeline = load_pipeline()

    assert pipeline["default"]["tags"] == ["docker02-shell"]
    assert pipeline["deploy:production"]["tags"] == ["docker03"]
    assert pipeline["deploy:production"]["extends"] == ".manual_protected_main_job"
    assert pipeline["publish:github"]["extends"] == ".manual_protected_main_job"
    assert pipeline["publish:github"]["needs"] == ["deploy:production"]

    production_needs = pipeline["deploy:production"]["needs"]
    assert "smoke:docker02" in production_needs
    assert "publish:validated-image" in production_needs

    security_jobs = {
        "security:semgrep",
        "security:trivy-repository",
        "security:gitleaks",
        "security:trufflehog",
        "security:dependency-check",
        "security:bandit",
        "security:image",
    }
    assert security_jobs.issubset(pipeline)


def test_pipeline_does_not_embed_private_deploy_paths_or_ssh_workflow():
    source = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")

    assert "/home/debian/" not in source
    assert "10.10.10." not in source
    assert "ssh-keyscan" not in source
    assert "STAGING_SSH_PRIVATE_KEY" not in source
    assert "PROD_SSH_PRIVATE_KEY" not in source
    assert "git push --force" not in source


def test_release_metadata_validator_passes_for_repository_state():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/ci/validate_release_metadata.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "3.0.2" in completed.stdout


def test_runtime_image_removes_build_only_pip_tooling():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")

    assert "/site-packages/pip-*.dist-info" in dockerfile
    assert "/ensurepip/_bundled/pip-*.whl" in dockerfile


def test_update_env_preserves_comments_and_replaces_duplicate_keys(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("# retained\nARPVPN_IMAGE=old\nARPVPN_IMAGE=duplicate\nOTHER=kept\n")

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ci/update_env.py"),
            str(env_path),
            "ARPVPN_IMAGE=registry/project@sha256:abc",
            "DATA_FOLDER=/srv/arpvpn/data",
        ],
        cwd=ROOT,
        check=True,
    )

    assert env_path.read_text() == (
        "# retained\n"
        "ARPVPN_IMAGE=registry/project@sha256:abc\n"
        "OTHER=kept\n"
        "DATA_FOLDER=/srv/arpvpn/data\n"
    )
