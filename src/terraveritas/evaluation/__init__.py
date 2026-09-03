"""Evaluation protocol for validating oracle verdicts against human ground truth.

Deliberately dataset-agnostic: as of this writing, no accessible,
independently-verified, human-adjudicated ground-truth dataset for this
exact task (AI-repaired Terraform security findings) was found — see
project notes from the verification pass. This module is the reusable
harness for whenever labeled data becomes available (from Prompt 9's own
generation, an independent replication, or a future verified external
source) — it does not assume any particular dataset's shape.
"""
