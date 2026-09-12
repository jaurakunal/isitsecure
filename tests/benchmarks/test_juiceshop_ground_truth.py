"""Guard against IDOR ground-truth over-crediting.

`GroundTruthItem.detected_by` credits a challenge when a class-matching finding's
URL *contains* the challenge's `endpoint_contains` token. That substring
behaviour is load-bearing — `changeProduct`'s singular "Product" must match the
plural "Products" segment — but it means a token that is a substring of an
*unrelated* endpoint silently double-credits. `forgedReview` ("products") used to
be credited by a finding on `/api/Products/1` (the changeProduct endpoint),
inflating `--probe-writes` idor recall by one. This pins the fix.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "benchmarks"))

from ground_truth import juiceshop  # noqa: E402


def _idor_items():
    return [g for g in juiceshop.build_ground_truth() if g.vuln_class == "idor"]


def _credits(item, url: str) -> bool:
    """Mirror detected_by's endpoint gate for a single idor finding."""
    finding = {
        "category": "idor",
        "scanner_name": "idor_scanner",
        "endpoint_url": url,
        "title": "IDOR",
    }
    return item.detected_by([finding]) is not None


def test_product_edit_finding_credits_only_change_product() -> None:
    url = "http://localhost:3000/api/Products/1"
    crediting = [g.id for g in _idor_items() if _credits(g, url)]
    assert crediting == ["changeProductChallenge"], crediting


def test_forged_review_needs_the_reviews_endpoint() -> None:
    review = next(g for g in _idor_items() if g.id == "forgedReviewChallenge")
    assert "reviews" in (review.endpoint_contains or "")
    assert not _credits(review, "http://localhost:3000/api/Products/1")
    assert _credits(review, "http://localhost:3000/rest/products/reviews")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000/api/Products/1",
        "http://localhost:3000/api/BasketItems/1",
        "http://localhost:3000/api/Feedbacks/1",
        "http://localhost:3000/rest/basket/1",
        "http://localhost:3000/rest/products/reviews",
        "http://localhost:3000/api/Users/1",
    ],
)
def test_no_single_endpoint_credits_two_idor_challenges(url: str) -> None:
    """Each idor challenge is a distinct vuln on a distinct route, so one
    discovered endpoint must not satisfy more than one of them."""
    crediting = [g.id for g in _idor_items() if _credits(g, url)]
    assert len(crediting) <= 1, f"{url} credits {crediting}"
