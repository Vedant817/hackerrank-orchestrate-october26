"""Ghost Data Still Exists - deletion audit agent.

The package is deliberately split into small layers so each one can be reviewed and
tested on its own:

``ingest``
    Load and validate the participant CSVs under ``dataset/``.
``identity``
    Resolve a request (current or historical email) to one subject and reconstruct the
    identifiers that were in force at a given instant.
``evidence``
    Read the participant evidence files (SQL snapshots, JSON, logs, text, PDF,
    screenshots), keep provenance, and retrieve the records that are grounded to a
    subject without attributing anyone else's data.

Nothing in this package reads organizer-only material, and ``sample_output.csv`` is
never opened: the sample answers are evaluation data, not prediction input.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
