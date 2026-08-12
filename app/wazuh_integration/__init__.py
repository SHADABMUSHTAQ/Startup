"""Feature-gated Wazuh detection integration.

WarSOC remains the system of record. Modules in this package only exchange
minimized generic-SIEM inputs and untrusted detection candidates.
"""

from .contracts import (
    DETECTION_CANDIDATE_SCHEMA,
    DETECTION_INPUT_SCHEMA,
    DetectionCandidate,
    DetectionCandidateBatch,
    DetectionInput,
    DetectionInputBatch,
)

__all__ = [
    "DETECTION_CANDIDATE_SCHEMA",
    "DETECTION_INPUT_SCHEMA",
    "DetectionCandidate",
    "DetectionCandidateBatch",
    "DetectionInput",
    "DetectionInputBatch",
]
