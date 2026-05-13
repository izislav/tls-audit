"""Shared TLS Audit domain package."""

from .report import Finding, Recommendation, Report
from .scoring import score_report
from .validation import Target, validate_target

__all__ = [
    "Finding",
    "Recommendation",
    "Report",
    "Target",
    "score_report",
    "validate_target",
]

