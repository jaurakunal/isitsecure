"""Tests for the rule-based, LLM-free plain-English framing layer.

Covers Wave 1 issues #41-#44 and #57:
* per-category plain-English explanations (#41)
* inline glossary / acronym expansion (#42)
* granular grade ladder incl. the +/- boundaries (#43)
* business-impact-first framing (#44)
* launch-readiness verdict (#57)
"""

import pytest

from isitsecure.engine.enums import FindingCategory
from isitsecure.engine.reporting import plain_english


# ---------------------------------------------------------------------------
# #41 — plain-English explanation per category
# ---------------------------------------------------------------------------

class TestPlainExplanation:
    def test_every_category_has_full_three_part_explanation(self) -> None:
        """Every FindingCategory must yield a non-empty three-part block."""
        for category in FindingCategory:
            exp = plain_english.explain_finding_category(category)
            assert exp.what_it_is.strip(), category
            assert exp.attacker_could.strip(), category
            assert exp.what_to_do.strip(), category

    def test_explanation_is_jargon_light_for_idor(self) -> None:
        """IDOR explanation should read plainly (mentions changing an ID)."""
        exp = plain_english.explain_finding_category(FindingCategory.IDOR)
        assert "id" in exp.attacker_could.lower()
        # No raw acronym-only sentence — it explains in words.
        assert "belongs to them" in exp.what_it_is.lower()

    def test_unknown_category_falls_back_gracefully(self) -> None:
        exp = plain_english.explain_finding_category("not_a_real_category")
        assert exp is plain_english._GENERIC_EXPLANATION
        assert exp.what_it_is.strip()

    def test_explain_finding_duck_types_on_category(self) -> None:
        class _F:
            category = FindingCategory.RLS_MISCONFIGURATION

        exp = plain_english.explain_finding(_F())
        assert "row-level security" in exp.what_it_is.lower()

    def test_as_dict_and_as_text(self) -> None:
        exp = plain_english.explain_finding_category(FindingCategory.EXPOSED_SECRETS)
        d = exp.as_dict()
        assert set(d) == {"what_it_is", "attacker_could", "what_to_do"}
        text = exp.as_text()
        assert "What it is:" in text
        assert "What an attacker could do:" in text
        assert "What to do:" in text


# ---------------------------------------------------------------------------
# #42 — glossary
# ---------------------------------------------------------------------------

class TestGlossary:
    @pytest.mark.parametrize(
        "term",
        ["xss", "idor", "bola", "rls", "csrf", "ssrf", "xxe",
         "ssti", "cors", "jwt", "sast", "dast"],
    )
    def test_required_terms_present(self, term: str) -> None:
        assert plain_english.expand_glossary(term)

    def test_expand_is_case_insensitive(self) -> None:
        assert plain_english.expand_glossary("XSS") == plain_english.expand_glossary("xss")

    def test_expand_unknown_returns_none(self) -> None:
        assert plain_english.expand_glossary("zzz_nope") is None

    def test_annotate_first_use_adds_one_parenthetical(self) -> None:
        text = "Confirmed reflected XSS via a query param"
        out = plain_english.annotate_first_use(text)
        assert "XSS (" in out
        # Only annotated once — the definition appears a single time.
        assert out.count("Cross-Site Scripting") == 1

    def test_annotate_first_use_no_term_is_noop(self) -> None:
        text = "Some finding with no acronym here"
        assert plain_english.annotate_first_use(text) == text

    def test_annotate_picks_earliest_term(self) -> None:
        # "SAST" appears before "IDOR" in the sentence.
        text = "SAST flagged a possible IDOR"
        out = plain_english.annotate_first_use(text)
        assert out.startswith("SAST (")


# ---------------------------------------------------------------------------
# #43 — granular grade ladder incl. boundaries
# ---------------------------------------------------------------------------

class TestGradeLadder:
    def test_any_critical_is_f(self) -> None:
        assert plain_english.calculate_grade(1, 0, 0, 0).grade == "F"
        # Critical dominates everything else.
        assert plain_english.calculate_grade(1, 9, 9, 9).grade == "F"

    def test_any_high_is_d(self) -> None:
        assert plain_english.calculate_grade(0, 1, 0, 0).grade == "D"
        assert plain_english.calculate_grade(0, 5, 9, 9).grade == "D"

    def test_medium_boundaries(self) -> None:
        # 1-2 medium -> C+ ; 3+ medium -> C
        assert plain_english.calculate_grade(0, 0, 1, 0).grade == "C+"
        assert plain_english.calculate_grade(0, 0, 2, 0).grade == "C+"
        assert plain_english.calculate_grade(0, 0, 3, 0).grade == "C"
        assert plain_english.calculate_grade(0, 0, 10, 0).grade == "C"

    def test_low_boundaries(self) -> None:
        # 1-2 low -> A- ; 3-5 low -> B+ ; 6+ low -> B
        assert plain_english.calculate_grade(0, 0, 0, 1).grade == "A-"
        assert plain_english.calculate_grade(0, 0, 0, 2).grade == "A-"
        assert plain_english.calculate_grade(0, 0, 0, 3).grade == "B+"
        assert plain_english.calculate_grade(0, 0, 0, 5).grade == "B+"
        assert plain_english.calculate_grade(0, 0, 0, 6).grade == "B"
        assert plain_english.calculate_grade(0, 0, 0, 99).grade == "B"

    def test_clean_is_a_and_hardened_is_a_plus(self) -> None:
        assert plain_english.calculate_grade(0, 0, 0, 0).grade == "A"
        assert plain_english.calculate_grade(0, 0, 0, 0, hardened=True).grade == "A+"

    def test_medium_takes_precedence_over_low(self) -> None:
        # A medium present outranks any number of lows.
        assert plain_english.calculate_grade(0, 0, 1, 9).grade == "C+"

    def test_every_grade_has_label(self) -> None:
        for grade in plain_english.GRADE_LADDER_LABELS:
            assert plain_english.GRADE_LADDER_LABELS[grade].strip()

    def test_result_carries_label_and_legend(self) -> None:
        r = plain_english.calculate_grade(0, 0, 0, 0)
        assert r.label == plain_english.GRADE_LADDER_LABELS["A"]
        assert r.legend == plain_english.GRADE_LEGEND

    def test_grade_base_letter(self) -> None:
        assert plain_english.grade_base_letter("A+") == "A"
        assert plain_english.grade_base_letter("A-") == "A"
        assert plain_english.grade_base_letter("C+") == "C"
        assert plain_english.grade_base_letter("F") == "F"
        assert plain_english.grade_base_letter("") == "?"


# ---------------------------------------------------------------------------
# #44 — business-impact framing
# ---------------------------------------------------------------------------

class TestBusinessImpact:
    def test_every_category_has_impact_line(self) -> None:
        for category in FindingCategory:
            line = plain_english.business_impact(category)
            assert line.strip()
            # Consequence-first: should not just echo the technical label.
            assert category.value not in line

    def test_idor_impact_is_consequence_first(self) -> None:
        line = plain_english.business_impact(FindingCategory.IDOR)
        assert "customer" in line.lower() or "other" in line.lower()

    def test_unknown_category_uses_generic(self) -> None:
        assert plain_english.business_impact("nope") == plain_english._GENERIC_BUSINESS_IMPACT


# ---------------------------------------------------------------------------
# #57 — launch verdict
# ---------------------------------------------------------------------------

class TestLaunchVerdict:
    def test_critical_blocks_launch(self) -> None:
        v = plain_english.launch_verdict(critical=2, high=0)
        assert v.ready is False
        assert v.headline.startswith("⛔")
        assert "2 critical issues" in v.headline
        assert "customer data" in v.headline

    def test_single_critical_is_singular(self) -> None:
        v = plain_english.launch_verdict(critical=1, high=3)
        assert "1 critical issue" in v.headline
        assert "1 critical issues" not in v.headline

    def test_high_holds_launch(self) -> None:
        v = plain_english.launch_verdict(critical=0, high=2)
        assert v.ready is False
        assert v.headline.startswith("⚠")
        assert "2 high-risk issues" in v.headline

    def test_medium_only_is_launchable(self) -> None:
        v = plain_english.launch_verdict(critical=0, high=0, medium=4)
        assert v.ready is True
        assert v.headline.startswith("✅")
        assert "4 medium-risk issues" in v.detail

    def test_clean_is_launchable(self) -> None:
        v = plain_english.launch_verdict(critical=0, high=0, medium=0)
        assert v.ready is True
        assert v.headline.startswith("✅")
        assert "No critical issues" in v.headline

    def test_as_line_joins_headline_and_detail(self) -> None:
        v = plain_english.launch_verdict(critical=1, high=0)
        assert v.as_line() == f"{v.headline} {v.detail}"
        clean = plain_english.launch_verdict(0, 0, 0)
        assert clean.as_line() == clean.headline


# ---------------------------------------------------------------------------
# #47 — specific remediation for ALL 18 categories (no generic fallback)
# ---------------------------------------------------------------------------

class TestCategoryRemediation:
    def test_every_category_has_specific_remediation(self) -> None:
        """No FindingCategory may fall through to the generic fallback (#47)."""
        for category in FindingCategory:
            text = plain_english.remediation_for(category)
            assert text.strip(), category
            assert text != plain_english._GENERIC_REMEDIATION, category

    def test_all_eighteen_categories_are_covered(self) -> None:
        """Sanity-check that all 18 known categories have an explicit entry."""
        keys = set(plain_english._CATEGORY_REMEDIATION)
        assert keys == {c.value for c in FindingCategory}
        assert len(keys) == 18

    def test_remediation_is_concrete_not_boilerplate(self) -> None:
        """Guidance names the actual control, not a vague 'review this'."""
        rls = plain_english.remediation_for(FindingCategory.RLS_MISCONFIGURATION)
        assert "row level security" in rls.lower()
        dep = plain_english.remediation_for(FindingCategory.DEPENDENCY_VULNERABILITY)
        assert "audit" in dep.lower()

    def test_unknown_category_uses_generic_fallback(self) -> None:
        assert (
            plain_english.remediation_for("not_a_real_category")
            == plain_english._GENERIC_REMEDIATION
        )

    def test_accepts_enum_or_string(self) -> None:
        assert (
            plain_english.remediation_for(FindingCategory.IDOR)
            == plain_english.remediation_for("idor")
        )


# ---------------------------------------------------------------------------
# #48 — framework-aware remediation for DAST/config findings
# ---------------------------------------------------------------------------

class TestFrameworkRemediation:
    def test_tailors_headers_snippet_per_framework(self) -> None:
        express = plain_english.framework_remediation(
            FindingCategory.MISSING_HEADERS, framework="express"
        )
        nextjs = plain_english.framework_remediation(
            FindingCategory.MISSING_HEADERS, framework="nextjs"
        )
        fastapi = plain_english.framework_remediation(
            FindingCategory.MISSING_HEADERS, framework="fastapi"
        )
        assert express and "helmet" in express.lower()
        assert nextjs and "next.config" in nextjs.lower()
        assert fastapi and "middleware" in fastapi.lower()
        # The snippets are genuinely different per stack.
        assert express != nextjs != fastapi

    def test_cors_snippet_differs_by_stack(self) -> None:
        express = plain_english.framework_remediation(
            FindingCategory.CORS_MISCONFIGURATION, framework="express"
        )
        django = plain_english.framework_remediation(
            FindingCategory.CORS_MISCONFIGURATION, framework="django"
        )
        assert express and "cors(" in express.lower()
        assert django and "cors_allowed_origins" in django.lower()

    def test_backend_takes_precedence_for_idor(self) -> None:
        """Supabase backend yields an RLS snippet even with a JS framework."""
        snippet = plain_english.framework_remediation(
            FindingCategory.IDOR, framework="nextjs", backend="supabase"
        )
        assert snippet and "row level security" in snippet.lower()

    def test_unknown_stack_returns_none(self) -> None:
        assert (
            plain_english.framework_remediation(
                FindingCategory.MISSING_HEADERS, framework="unknown", backend="unknown"
            )
            is None
        )
        # A category with no stack table at all also returns None.
        assert (
            plain_english.framework_remediation(
                FindingCategory.EXPOSED_SECRETS, framework="express"
            )
            is None
        )

    def test_remediation_detail_appends_snippet_when_known(self) -> None:
        detail = plain_english.remediation_detail(
            FindingCategory.CORS_MISCONFIGURATION, framework="express"
        )
        assert plain_english.remediation_for(
            FindingCategory.CORS_MISCONFIGURATION
        ) in detail
        assert "For your stack:" in detail
        assert "cors(" in detail.lower()

    def test_remediation_detail_generic_when_stack_unknown(self) -> None:
        detail = plain_english.remediation_detail(
            FindingCategory.MISSING_HEADERS, framework="unknown"
        )
        assert "For your stack:" not in detail
        assert detail == plain_english.remediation_for(
            FindingCategory.MISSING_HEADERS
        )


# ---------------------------------------------------------------------------
# #49 — step-by-step walkthroughs for the top-4 fixes
# ---------------------------------------------------------------------------

class TestWalkthroughs:
    TOP_FOUR = [
        FindingCategory.RLS_MISCONFIGURATION,
        FindingCategory.CORS_MISCONFIGURATION,
        FindingCategory.IDOR,
        FindingCategory.EXPOSED_SECRETS,
    ]

    def test_top_four_have_walkthroughs(self) -> None:
        for category in self.TOP_FOUR:
            w = plain_english.walkthrough_for(category)
            assert w is not None, category
            assert w.title.strip(), category
            assert len(w.steps) >= 3, category
            assert all(step.strip() for step in w.steps), category

    def test_walkthrough_as_dict_is_serializable(self) -> None:
        w = plain_english.walkthrough_for(FindingCategory.IDOR)
        d = w.as_dict()
        assert set(d) == {"title", "steps"}
        assert isinstance(d["steps"], list)

    def test_other_categories_have_no_walkthrough(self) -> None:
        assert plain_english.walkthrough_for(FindingCategory.MIXED_CONTENT) is None
        assert plain_english.walkthrough_for("not_a_real_category") is None
