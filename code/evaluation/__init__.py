"""Evaluation package for Ghost Data Still Exists.

Modules:

* :mod:`evaluation.main` - metrics harness (case/step/field/sequence) over the public
  sample labels and the audit core.
* :mod:`evaluation.custom_cases` - authored evaluation fixtures (historical identifier,
  temporal recreation, tombstone/retention, late-evidence cutoff).

The package reads ``dataset/sample_output.csv`` **only** as reference labels inside the
metrics harness, after predictions have been produced. The prediction path never imports a
label.
"""

from __future__ import annotations

__all__ = ["main", "custom_cases"]
