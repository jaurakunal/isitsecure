"""Tests for the priority calculator module.

Validates that the Impact x Likelihood priority matrix returns correct
priority values (1-4) for all defined combinations and falls back to
the default priority for any hypothetical gaps.
"""

import pytest

from isitsecure.engine.constants import TriageConfig
from isitsecure.engine.enums import ImpactCategory, LikelihoodLevel
from isitsecure.engine.triage.priority_calculator import (
    calculate_priority,
)


class TestPriorityMatrix:
    """Tests for calculate_priority against the full matrix."""

    def test_financial_exploitable_is_priority_1(self) -> None:
        """Financial impact + actively exploitable must be P1."""
        result = calculate_priority(
            ImpactCategory.FINANCIAL, LikelihoodLevel.ACTIVELY_EXPLOITABLE
        )
        assert result == 1

    def test_data_breach_exploitable_is_priority_1(self) -> None:
        """Data breach + actively exploitable must be P1."""
        result = calculate_priority(
            ImpactCategory.DATA_BREACH, LikelihoodLevel.ACTIVELY_EXPLOITABLE
        )
        assert result == 1

    def test_legal_exploitable_is_priority_1(self) -> None:
        """Legal impact + actively exploitable must be P1."""
        result = calculate_priority(
            ImpactCategory.LEGAL, LikelihoodLevel.ACTIVELY_EXPLOITABLE
        )
        assert result == 1

    def test_operational_exploitable_is_priority_2(self) -> None:
        """Operational impact + actively exploitable must be P2."""
        result = calculate_priority(
            ImpactCategory.OPERATIONAL, LikelihoodLevel.ACTIVELY_EXPLOITABLE
        )
        assert result == 2

    def test_reputational_theoretical_is_priority_4(self) -> None:
        """Reputational impact + theoretical likelihood must be P4."""
        result = calculate_priority(
            ImpactCategory.REPUTATIONAL, LikelihoodLevel.THEORETICAL
        )
        assert result == 4

    def test_financial_requires_admin_is_priority_3(self) -> None:
        """Financial impact + requires admin must be P3."""
        result = calculate_priority(
            ImpactCategory.FINANCIAL, LikelihoodLevel.REQUIRES_ADMIN
        )
        assert result == 3

    def test_reputational_exploitable_is_priority_2(self) -> None:
        """Reputational impact + actively exploitable must be P2."""
        result = calculate_priority(
            ImpactCategory.REPUTATIONAL, LikelihoodLevel.ACTIVELY_EXPLOITABLE
        )
        assert result == 2

    def test_data_breach_requires_auth_is_priority_2(self) -> None:
        """Data breach + requires auth must be P2."""
        result = calculate_priority(
            ImpactCategory.DATA_BREACH, LikelihoodLevel.REQUIRES_AUTH
        )
        assert result == 2

    def test_operational_theoretical_is_priority_4(self) -> None:
        """Operational impact + theoretical likelihood must be P4."""
        result = calculate_priority(
            ImpactCategory.OPERATIONAL, LikelihoodLevel.THEORETICAL
        )
        assert result == 4

    def test_legal_requires_admin_is_priority_3(self) -> None:
        """Legal impact + requires admin must be P3."""
        result = calculate_priority(
            ImpactCategory.LEGAL, LikelihoodLevel.REQUIRES_ADMIN
        )
        assert result == 3

    def test_all_matrix_entries_return_1_to_4(self) -> None:
        """Every combination in the matrix must return a priority in [1, 4]."""
        for impact in ImpactCategory:
            for likelihood in LikelihoodLevel:
                priority = calculate_priority(impact, likelihood)
                assert 1 <= priority <= 4, (
                    f"Priority {priority} out of range for "
                    f"({impact.value}, {likelihood.value})"
                )

    def test_all_impact_likelihood_combinations_have_entry(self) -> None:
        """Verify the matrix has no gaps -- every (impact, likelihood) pair
        should be present in PRIORITY_MATRIX so we never silently fall back
        to the default."""
        for impact in ImpactCategory:
            for likelihood in LikelihoodLevel:
                key = (impact.value, likelihood.value)
                assert key in TriageConfig.PRIORITY_MATRIX, (
                    f"Missing matrix entry for ({impact.value}, {likelihood.value})"
                )

    def test_default_priority_is_used_for_unknown_key(self) -> None:
        """If the matrix lookup misses (hypothetical), DEFAULT_PRIORITY is returned."""
        # Directly test the .get fallback by calling with string values
        # that are not in the matrix.  We cannot pass non-enum values to
        # calculate_priority, so test the dict directly.
        missing_key = ("nonexistent_impact", "nonexistent_likelihood")
        result = TriageConfig.PRIORITY_MATRIX.get(
            missing_key, TriageConfig.DEFAULT_PRIORITY
        )
        assert result == TriageConfig.DEFAULT_PRIORITY
