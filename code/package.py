"""Deterministic ``code.zip`` builder for Ghost Data Still Exists.

The archive contains exactly the runnable solution, the ``README.md``, ``requirements.txt``
and the Markdown evaluation reports. It never contains the dataset, the ignored
``ghostwatch/`` orchestration tree, the transcript (``log.txt``), caches, virtual
environments, secrets, raw data, nested archives or symlinks.

Design choices:

* **Allowlist, not denylist for the tree.** Only the declared submission paths are walked.
* **Denied-name guard.** A deny pattern that matches any allowlisted file aborts the build
  instead of silently dropping it, so credentials or run artifacts cannot slide in.
* **Deterministic metadata.** Entries are sorted by path and written with a fixed
  ``date_time`` and fixed permissions, so two builds of the same tree are byte-identical.

Usage::

    python code/package.py                 # writes repo-root code.zip
    python code/package.py --output PATH   # explicit output path
    python code/package.py --list          # print the file list without writing
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent

#: The submission tree spec: repo-root-relative path -> "file" | "dir".
#:
#: The challenge contract (``AGENTS.md`` §6.8) requires ``code.zip`` to carry the two
#: Markdown reports at **both** the archive root (``evaluation/<name>.md``) and the
#: ``code/evaluation/<name>.md`` location. The ``code`` directory supplies the latter; the
#: two root mirror files are declared individually rather than by adding the whole
#: ``evaluation/`` directory, so no unrelated artifact can ever be bundled by accident.
TREE_SPEC: dict[str, str] = {
    "README.md": "file",
    "requirements.txt": "file",
    "code": "dir",
    "evaluation/evaluation_report.md": "file",
    "evaluation/usage_report.md": "file",
}

#: The exact, contract-required report members, relative to the repository root. Both the
#: ``code/evaluation`` primary and the root mirror must be present in every archive; a missing
#: one aborts the build (see :func:`collect_files`) and is asserted by the tests.
REQUIRED_REPORT_MEMBERS: tuple[str, ...] = (
    "code/evaluation/evaluation_report.md",
    "code/evaluation/usage_report.md",
    "evaluation/evaluation_report.md",
    "evaluation/usage_report.md",
)

#: Directories that are pruned silently (build/test caches, virtual environments). These
#: are excluded because they are not part of the reviewable source, not because they are
#: dangerous; pruning them keeps the build working on a freshly tested tree.
PRUNE_DIRS: frozenset[str] = frozenset(
    {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".venv", "venv", "env", "node_modules"}
)

#: Repo-root-relative path prefixes that must never be packaged. The allowlist already
#: excludes them, but the guard makes the intent explicit and would abort if the spec ever
#: widened to include them.
DENY_PREFIXES: tuple[str, ...] = ("ghostwatch/", "dataset/", ".git/")

#: Paths that must never appear in the archive. A match aborts the build rather than being
#: dropped silently, so credentials or a nested archive cannot slide into the submission
#: unnoticed.
DENY_PATTERNS: tuple[str, ...] = (
    "*.pyc",
    "*.pyo",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "credentials*",
    "secrets*",
    ".netrc",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.gz",
    "*.7z",
    "*.rar",
)

#: File extensions that are raw data rather than report/code. Excluded from the archive so
#: diagnostic drafts or exported data can never be bundled as if they were deliverables.
PRUNE_SUFFIXES: tuple[str, ...] = (
    ".csv",
    ".tsv",
    ".jsonl",
    ".sql",
    ".db",
    ".sqlite",
    ".parquet",
)

#: Fixed timestamp for reproducible archives (ZIP epoch floor for 1980-01-01).
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_EXTERNAL_ATTR = 0o644 << 16


@dataclass(frozen=True, slots=True)
class PackageResult:
    output: Path
    files: tuple[str, ...]
    sha256: str


#: Specific repo-relative files that are diagnostic artifacts, never deliverables.
PRUNE_FILES: frozenset[str] = frozenset(
    {
        "code/evaluation/diagnostic_predictions.csv",
        "code/evaluation/diagnostic_gaps.md",
    }
)


def _is_pruned(relative: Path) -> bool:
    if relative.as_posix() in PRUNE_FILES:
        return True
    if any(part in PRUNE_DIRS for part in relative.parts):
        return True
    return relative.suffix.lower() in PRUNE_SUFFIXES


def _is_denied(relative: Path) -> bool:
    posix = relative.as_posix()
    if any(posix.startswith(prefix) for prefix in DENY_PREFIXES):
        return True
    for part in relative.parts:
        for pattern in DENY_PATTERNS:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


def collect_files(root: Path = REPO_ROOT, spec: dict[str, str] | None = None) -> list[Path]:
    """Return the sorted list of files to package, or raise on a missing target / symlink."""

    spec = spec or TREE_SPEC
    missing = [
        name
        for name, kind in spec.items()
        if not ((root / name).is_file() if kind == "file" else (root / name).is_dir())
    ]
    if missing:
        raise FileNotFoundError(f"missing package target(s): {', '.join(sorted(missing))}")

    files: list[Path] = []
    for name, kind in sorted(spec.items()):
        target = root / name
        candidates = [target] if kind == "file" else list(target.rglob("*"))
        for path in candidates:
            if path.is_symlink():
                raise ValueError(f"refusing to package a symlink: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if _is_pruned(relative):
                continue
            if _is_denied(relative):
                raise ValueError(f"refusing to package a denied path: {relative.as_posix()}")
            files.append(relative)
    files.sort(key=lambda item: item.as_posix())

    # The contract-required report members are decidable only after pruning, so assert them
    # here: a report that is pruned, denied or absent aborts the build with a named error
    # instead of producing a silently incomplete submission archive.
    present = {relative.as_posix() for relative in files}
    missing_reports = [member for member in REQUIRED_REPORT_MEMBERS if member not in present]
    if missing_reports:
        raise FileNotFoundError(
            "required report member(s) missing from the archive: " + ", ".join(missing_reports)
        )
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def build_archive(
    output: Path | None = None,
    *,
    root: Path = REPO_ROOT,
    spec: dict[str, str] | None = None,
) -> PackageResult:
    """Build the archive deterministically and return its path, file list and hash."""

    files = collect_files(root, spec)
    destination = output or (root / "code.zip")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            info = zipfile.ZipInfo(filename=relative.as_posix(), date_time=FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FIXED_EXTERNAL_ATTR
            info.create_system = 0
            archive.writestr(info, (root / relative).read_bytes())

    return PackageResult(
        output=destination,
        files=tuple(relative.as_posix() for relative in files),
        sha256=_sha256(destination),
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the deterministic code.zip submission archive")
    parser.add_argument("--output", type=Path, default=None, help="archive output path (default: repo-root code.zip)")
    parser.add_argument("--list", action="store_true", help="print the file list and exit without writing")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    if args.list:
        for relative in collect_files():
            print(relative)
        return 0
    result = build_archive(args.output)
    print(f"wrote {result.output} with {len(result.files)} files")
    print(f"sha256 {result.sha256}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
