"""Scan configuration model for customer-customizable scan settings."""

from pydantic import BaseModel, Field

from isitsecure.engine.constants import ScanConfigDefaults
from isitsecure.engine.enums import ScanMode


class ScanConfiguration(BaseModel):
    """Customer-configurable scan settings.

    Controls which scanners run, what paths to exclude,
    resource limits, and scan mode.
    """

    # Scope control
    scan_mode: ScanMode = ScanMode.URL_ONLY
    exclude_paths: list[str] = Field(default_factory=list)
    exclude_tables: list[str] = Field(default_factory=list)
    include_only_paths: list[str] = Field(default_factory=list)
    max_crawl_depth: int = ScanConfigDefaults.MAX_CRAWL_DEPTH

    # Scanner toggles
    enable_active_xss: bool = True
    enable_active_injection: bool = True
    enable_csrf: bool = True
    enable_rate_limit_test: bool = True
    enable_git_history_scan: bool = True
    enable_llm_review: bool = True
    enable_dependency_scan: bool = True

    # Resource limits
    max_endpoints_to_test: int = ScanConfigDefaults.MAX_ENDPOINTS_TO_TEST
    max_files_for_llm_review: int = ScanConfigDefaults.MAX_FILES_FOR_LLM_REVIEW
    llm_token_budget: int = ScanConfigDefaults.LLM_TOKEN_BUDGET

    def should_scan_path(self, path: str) -> bool:
        """Check if a path should be scanned based on includes/excludes."""
        if self.include_only_paths:
            return any(path.startswith(p) for p in self.include_only_paths)
        return not any(path.startswith(p) for p in self.exclude_paths)

    def should_scan_table(self, table: str) -> bool:
        """Check if a Supabase table should be scanned."""
        return table not in self.exclude_tables
