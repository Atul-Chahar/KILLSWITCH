"""The secret scanner is the last line of defence, so it gets tested like one.

The synthetic key ids below are assembled from split literals on purpose: if they
appeared whole in this file, the scanner would correctly flag its own test suite.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER = REPO_ROOT / "scripts" / "check_secrets.sh"

AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
SYNTHETIC_REAL_KEY = "AKIA" + "TESTFAKEKEY00001"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo with the scanner copied in at its expected path."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(SCANNER, scripts / "check_secrets.sh")
    return tmp_path


def scan(repo: Path) -> subprocess.CompletedProcess[str]:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    return subprocess.run(
        ["./scripts/check_secrets.sh"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def test_clean_repo_passes(repo: Path):
    (repo / "app.py").write_text("print('no secrets here')\n")
    result = scan(repo)
    assert result.returncode == 0, result.stdout


def test_aws_documented_example_key_is_allowed(repo: Path):
    (repo / "test_detect.py").write_text(f'EXAMPLE = "{AWS_EXAMPLE_KEY}"\n')
    result = scan(repo)
    assert result.returncode == 0, result.stdout


def test_real_key_alongside_the_example_key_is_still_caught(repo: Path):
    """The old scanner treated the example key as a whole-file pass."""
    (repo / "test_detect.py").write_text(
        f'IGNORED = "{AWS_EXAMPLE_KEY}"\nLEAKED = "{SYNTHETIC_REAL_KEY}"\n'
    )
    result = scan(repo)
    assert result.returncode == 1
    assert "test_detect.py" in result.stdout


def test_key_pasted_into_markdown_is_caught(repo: Path):
    """Write-ups and evidence notes were previously exempt from scanning."""
    (repo / "evidence.md").write_text(f"The leaked key was {SYNTHETIC_REAL_KEY}.\n")
    result = scan(repo)
    assert result.returncode == 1
    assert "evidence.md" in result.stdout


def test_prose_naming_the_secret_variable_does_not_fail_the_build(repo: Path):
    (repo / "README.md").write_text("Set aws_secret_access_key in your environment.\n")
    result = scan(repo)
    assert result.returncode == 0, result.stdout


def test_assigned_secret_access_key_is_caught(repo: Path):
    (repo / "config.ini").write_text("aws_secret_access_key = " + "x" * 40 + "\n")
    result = scan(repo)
    assert result.returncode == 1
    assert "config.ini" in result.stdout


def test_github_token_is_caught(repo: Path):
    (repo / "deploy.sh").write_text("TOKEN=" + "ghp_" + "a" * 36 + "\n")
    result = scan(repo)
    assert result.returncode == 1


def test_tracked_dotenv_is_caught(repo: Path):
    (repo / ".env").write_text("AWS_REGION=ap-south-1\n")
    result = scan(repo)
    assert result.returncode == 1
    assert ".env is tracked" in result.stdout
