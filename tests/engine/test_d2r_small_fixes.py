"""Small D2 review fixes: camelCase linking, RLS parsing, vendor sibling domains."""

from __future__ import annotations

from isitsecure.engine.cross_referencer import FindingCrossReferencer, findings_related
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def _f(src, *, file=None, url=None, title="t", cat=FindingCategory.IDOR) -> DeepFinding:
    return DeepFinding(
        source=src, category=cat, severity=SeverityLevel.HIGH, title=title,
        description="d", confidence=0.9, scanner_name="x", endpoint_url=url,
        code_location=CodeLocation(file_path=file, line_number=3) if file else None,
    )


def test_pascal_case_controller_links_to_plural_endpoint() -> None:
    dast = _f(FindingSource.DAST_URL, url="http://t/api/v1/accounts/7")
    sast = _f(FindingSource.SAST_CODE, file="src/main/java/AccountController.java")
    assert findings_related(dast, sast)
    assert len(FindingCrossReferencer().cross_reference([dast], [sast])) == 1


def test_camel_case_file_links() -> None:
    dast = _f(FindingSource.DAST_URL, url="http://t/api/order-items")
    sast = _f(FindingSource.SAST_CODE, file="routes/orderItems.ts")
    assert findings_related(dast, sast)


def test_camel_split_does_not_link_unrelated_files() -> None:
    dast = _f(FindingSource.DAST_URL, url="http://t/api/v1/accounts/7")
    sast = _f(FindingSource.SAST_CODE, file="src/main/java/InvoiceController.java")
    assert not findings_related(dast, sast)


def test_vendor_sibling_requires_label_equality_or_hyphen_suffix() -> None:
    from isitsecure.engine.ingestion.vendor_filter import VendorAssetFilter

    def third_party(site: str, asset: str) -> bool:
        return VendorAssetFilter(site).is_vendor_asset(asset, "const a=1;")

    assert third_party("https://shop.com/", "https://cdn.shopify.com/a.js") is True
    assert third_party("https://cloud.com/", "https://x.cloudflare.com/a.js") is True
    # positive controls: genuine first-party siblings stay first-party
    assert third_party("https://example.com/", "https://cdn.example-static.com/a.js") is False
    assert third_party("https://example-static.com/", "https://www.example.com/a.js") is False
    assert third_party("https://example.com/", "https://cdn.example.org/a.js") is False
