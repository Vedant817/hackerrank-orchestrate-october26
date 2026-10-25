"""T03 acceptance tests for the deterministic archive builder (``code/package.py``).

These pin the packaging contract:

* the archive excludes the dataset, the ignored ``ghostwatch/`` orchestration tree, caches,
  environments, secrets, raw data and nested archives;
* the archive includes the runnable code, ``README.md``, ``requirements.txt`` and the
  Markdown evaluation reports;
* two builds of the same tree are byte-identical (deterministic metadata and ordering);
* a denied path aborts the build rather than being silently dropped.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

import package as packaging  # noqa: E402

REQUIRED_MEMBERS = (
    "README.md",
    "requirements.txt",
    "code/main.py",
    "code/package.py",
    "code/ghostwatch/planner.py",
    "code/evaluation/main.py",
    "code/evaluation/custom_cases.py",
    "code/evaluation/evaluation_report.md",
    "code/evaluation/usage_report.md",
    # The contract (AGENTS.md §6.8) also requires the reports at the archive root; the
    # packager declares those two mirror files individually in TREE_SPEC.
    "evaluation/evaluation_report.md",
    "evaluation/usage_report.md",
)

#: The two contract report names, checked at both required locations.
REPORT_NAMES = ("evaluation_report.md", "usage_report.md")


def test_package_excludes_dataset_secrets_caches_archives_and_ghostwatch(tmp_path) -> None:
    """No excluded path appears in the archive."""

    out = tmp_path / "code.zip"
    result = packaging.build_archive(out)
    members = set(result.files)

    assert "dataset" not in members
    for member in members:
        assert not member.startswith("dataset/")
        assert not member.startswith("ghostwatch/")
        assert not member.startswith(".git/")
        assert "__pycache__" not in member
        assert ".pytest_cache" not in member
        assert ".venv" not in member
        assert not member.endswith((".zip", ".tar", ".gz", ".7z", ".rar"))
        assert ".env" not in Path(member).name
        assert not member.endswith((".csv", ".sql", ".jsonl", ".db"))
        assert "diagnostic_" not in Path(member).name

    assert out.is_file()
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
    assert names == members


def test_package_includes_runnable_code_and_reports(tmp_path) -> None:
    """The archive contains the runnable solution, README, requirements and reports."""

    out = tmp_path / "code.zip"
    result = packaging.build_archive(out)
    members = set(result.files)
    for required in REQUIRED_MEMBERS:
        assert required in members, f"missing required member {required}"


def test_package_is_byte_deterministic(tmp_path) -> None:
    """Two builds of the same tree produce identical bytes."""

    first = packaging.build_archive(tmp_path / "a.zip")
    second = packaging.build_archive(tmp_path / "b.zip")
    assert first.sha256 == second.sha256
    assert first.files == second.files


def _minimal_root(root: Path) -> None:
    """Create the minimum on-disk tree the default TREE_SPEC requires (incl. both reports)."""

    (root / "code" / "evaluation").mkdir(parents=True, exist_ok=True)
    (root / "evaluation").mkdir(parents=True, exist_ok=True)
    (root / "code" / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "README.md").write_text("# r\n", encoding="utf-8")
    (root / "requirements.txt").write_text("\n", encoding="utf-8")
    for name in REPORT_NAMES:
        (root / "code" / "evaluation" / name).write_text(f"# {name}\n", encoding="utf-8")
        (root / "evaluation" / name).write_text(f"# {name}\n", encoding="utf-8")


def test_denied_path_aborts_the_build(tmp_path) -> None:
    """A denied name aborts rather than being dropped silently."""

    root = tmp_path / "root"
    _minimal_root(root)
    (root / "code" / ".env").write_text("SECRET=1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="denied"):
        packaging.build_archive(tmp_path / "out.zip", root=root)


def test_missing_target_raises(tmp_path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(FileNotFoundError):
        packaging.build_archive(tmp_path / "out.zip", root=root)


def test_archive_carries_both_required_report_locations(tmp_path) -> None:
    """Both contract report paths are inside the archive: ``code/evaluation`` and root ``evaluation``."""

    out = tmp_path / "code.zip"
    result = packaging.build_archive(out)
    members = set(result.files)
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())

    for name in REPORT_NAMES:
        for location in (f"code/evaluation/{name}", f"evaluation/{name}"):
            assert location in members, f"{location} missing from the archive file list"
            assert location in names, f"{location} missing from the zip directory"

    # Everything under the archive-root ``evaluation/`` must be a required report — the narrow
    # per-file allowlist means no unrelated evaluation artifact (drafts, data) can ride along.
    root_eval = {member for member in members if member.startswith("evaluation/")}
    assert root_eval == {f"evaluation/{name}" for name in REPORT_NAMES}


def test_archive_report_bytes_match_the_live_tree(tmp_path) -> None:
    """The archived report bytes are exactly the live reviewed bytes at both locations and agree."""

    out = tmp_path / "code.zip"
    packaging.build_archive(out)
    with zipfile.ZipFile(out) as archive:
        for name in REPORT_NAMES:
            primary = (REPO_ROOT / "code" / "evaluation" / name).read_bytes()
            mirror = (REPO_ROOT / "evaluation" / name).read_bytes()
            archived_primary = archive.read(f"code/evaluation/{name}")
            archived_mirror = archive.read(f"evaluation/{name}")
            assert archived_primary == primary, f"archived {name} (code/) differs from the live file"
            assert archived_mirror == mirror, f"archived {name} (root) differs from the live file"
            assert archived_primary == archived_mirror, f"{name} archive locations disagree"


def test_missing_report_member_raises_clearly(tmp_path) -> None:
    """A missing required report aborts the build with a named error, never silently."""

    root = tmp_path / "root"
    _minimal_root(root)
    # Remove one required mirror: the build must abort naming the missing report.
    (root / "evaluation" / "usage_report.md").unlink()

    with pytest.raises(FileNotFoundError, match="usage_report.md"):
        packaging.build_archive(tmp_path / "out.zip", root=root)


def test_pruned_root_report_aborts_the_build(tmp_path) -> None:
    """A required report absent from the active spec still aborts, not silently drops.

    A spec override that keeps only ``code/`` must fail the required-member gate rather than
    producing an archive missing the contract-required root ``evaluation/`` report paths.
    """

    root = tmp_path / "root"
    _minimal_root(root)
    narrow_spec = {"README.md": "file", "requirements.txt": "file", "code": "dir"}
    with pytest.raises(FileNotFoundError, match="required report member"):
        packaging.build_archive(tmp_path / "out.zip", root=root, spec=narrow_spec)


def test_denied_pattern_guard_is_intact(tmp_path) -> None:
    """The denied-name guard still aborts for a path the allowlist walks (not weakened)."""

    root = tmp_path / "root"
    _minimal_root(root)
    (root / "code" / "secrets.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="denied"):
        packaging.build_archive(tmp_path / "out.zip", root=root)


def test_root_evaluation_allowlist_is_narrow(tmp_path) -> None:
    """Only the two contract reports are collected under the archive-root ``evaluation/``."""

    root = tmp_path / "root"
    _minimal_root(root)
    # An unrelated artifact in the root ``evaluation/`` directory is *not* collected (allowlist).
    (root / "evaluation" / "diagnostic_predictions.csv").write_text("x\n", encoding="utf-8")
    (root / "evaluation" / "notes.md").write_text("x\n", encoding="utf-8")

    result = packaging.build_archive(tmp_path / "out.zip", root=root)
    root_eval = {member for member in result.files if member.startswith("evaluation/")}
    assert root_eval == {f"evaluation/{name}" for name in REPORT_NAMES}


def test_package_excludes_root_output_csv(tmp_path) -> None:
    """``code.zip`` never contains ``output.csv``: it is a separate submission artifact (T04).

    The competition contract lists ``code.zip`` and ``output.csv`` as **two distinct**
    deliverables, so the answer file must travel outside the archive. The packager's allowlist
    and its ``.csv`` prune rule both keep it out, and this test pins that on the live tree.
    """

    out = tmp_path / "code.zip"
    result = packaging.build_archive(out)
    members = set(result.files)

    assert "output.csv" not in members
    assert not any(member.endswith("output.csv") for member in members)
    assert not any(member.endswith(".csv") for member in members), "raw data must never be packaged"

    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
    assert not any(name.endswith("output.csv") for name in names)

    # The live repository root genuinely carries the T04 answer file, so the exclusion is
    # meaningful rather than vacuous.
    assert (REPO_ROOT / "output.csv").is_file()
