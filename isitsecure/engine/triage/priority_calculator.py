"""Priority calculator using Impact x Likelihood matrix.

SRP: This module has one responsibility — computing priority from
     impact and likelihood.  It does not access LLMs, findings, or
     any other domain logic.
"""

from __future__ import annotations

from isitsecure.engine.constants import TriageConfig
from isitsecure.engine.enums import ImpactCategory, LikelihoodLevel


def calculate_priority(
    impact: ImpactCategory,
    likelihood: LikelihoodLevel,
) -> int:
    """Calculate priority (1-4) from impact and likelihood.

    Uses the priority matrix defined in ``TriageConfig``.
    Returns ``TriageConfig.DEFAULT_PRIORITY`` if the combination
    is not in the matrix.
    """
    key = (impact.value, likelihood.value)
    return TriageConfig.PRIORITY_MATRIX.get(key, TriageConfig.DEFAULT_PRIORITY)
