"""Deterministic analyzers: source diff, binary features, binary diff stub, log correlation."""

from oss_sensor.analyzers.source_diff import extract_source_diff, extract_source_features
from oss_sensor.analyzers.binary_features import extract_binary_features
from oss_sensor.analyzers.binary_diff import compute_binary_diff_stub
from oss_sensor.analyzers.log_correlation import extract_log_templates, correlate_log_to_binary

__all__ = [
    "extract_source_diff",
    "extract_source_features",
    "extract_binary_features",
    "compute_binary_diff_stub",
    "extract_log_templates",
    "correlate_log_to_binary",
]
