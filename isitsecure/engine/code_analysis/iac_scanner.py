"""Infrastructure-as-Code (Terraform) security scanner.

Currently supports **AWS-specific** Terraform resources (security groups,
IAM, ECS, ALB, Secrets Manager, CloudWatch).  GCP and Azure support
can be added as additional scanner classes following OCP.

SRP: This scanner is responsible ONLY for analyzing Terraform HCL files
     for security misconfigurations.  It does not analyze application code,
     Docker files, or runtime behavior.

OCP: Implements ``CodeScannerProtocol`` — added to the sast_scanners
     list without modifying the agent or factory.  New cloud providers
     can be added as separate scanner classes.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import IaCScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class IaCScanner:
    """Scans Terraform files for security misconfigurations.

    Currently covers AWS-specific resources.  GCP/Azure scanners can be
    added as separate classes following OCP (new class, add to factory).

    AWS checks performed:
    1. Security groups with overly permissive ingress rules
    2. IAM policies with wildcard actions/resources
    3. Hardcoded secrets in variable defaults or tfvars
    4. Public S3 buckets
    5. Secrets Manager with zero recovery window
    6. ALB HTTP listeners without HTTPS redirect
    7. ECS tasks with direct public IP assignment
    8. Short CloudWatch log retention periods

    Provider-agnostic checks:
    3. Hardcoded secrets (works for any cloud provider)

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return IaCScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Terraform files for security issues."""
        findings: list[CodeFinding] = []

        tf_files = self._find_tf_files(repo)

        if not tf_files:
            return findings

        for file_path, content in tf_files.items():
            try:
                findings.extend(self._check_security_groups(content, file_path))
                findings.extend(self._check_iam_policies(content, file_path))
                findings.extend(self._check_hardcoded_secrets(content, file_path))
                findings.extend(self._check_s3_buckets(content, file_path))
                findings.extend(self._check_secrets_manager(content, file_path))
                findings.extend(self._check_alb_http(content, file_path))
                findings.extend(self._check_ecs_public_ip(content, file_path))
                findings.extend(self._check_log_retention(content, file_path))
            except Exception as e:
                logger.warning(
                    IaCScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        logger.info(
            "IaCScanner: %d .tf files scanned, %d findings",
            len(tf_files),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _find_tf_files(repo: RepoSnapshot) -> dict[str, str]:
        """Find Terraform files in the file index."""
        return {
            path: content
            for path, content in repo.file_index.items()
            if any(path.endswith(ext) for ext in IaCScannerConfig.IAC_EXTENSIONS)
        }

    # ------------------------------------------------------------------
    # 1. Security group checks
    # ------------------------------------------------------------------

    def _check_security_groups(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find security groups with 0.0.0.0/0 or ::/0 ingress on non-standard ports."""
        findings: list[CodeFinding] = []

        # Check both IPv4 and IPv6 open ingress patterns
        for pattern in IaCScannerConfig.OPEN_INGRESS_PATTERNS:
            for match in re.finditer(pattern, content, re.DOTALL):
                block = match.group(0)

                # Extract the port
                port_match = re.search(
                    IaCScannerConfig.INGRESS_PORT_PATTERN, block
                )
                if not port_match:
                    continue

                port = int(port_match.group(1))

                # Skip acceptable public ports (80, 443)
                if port in IaCScannerConfig.ACCEPTABLE_PUBLIC_PORTS:
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_API_ENDPOINT,
                        title=IaCScannerConfig.TITLE_OPEN_SG.format(port=port),
                        description=IaCScannerConfig.DESC_OPEN_SG.format(
                            file=file_path, port=port
                        ),
                        file_path=file_path,
                        confidence=IaCScannerConfig.CONFIDENCE_OPEN_SG,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 2. IAM policy checks
    # ------------------------------------------------------------------

    def _check_iam_policies(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find IAM policies with wildcard actions or resources."""
        findings: list[CodeFinding] = []

        if any(
            re.search(p, content)
            for p in IaCScannerConfig.WILDCARD_ACTION_PATTERNS
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=IaCScannerConfig.TITLE_WILDCARD_IAM_ACTION,
                    description=IaCScannerConfig.DESC_WILDCARD_IAM_ACTION.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=IaCScannerConfig.CONFIDENCE_WILDCARD_IAM,
                )
            )

        if any(
            re.search(p, content)
            for p in IaCScannerConfig.WILDCARD_RESOURCE_PATTERNS
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=IaCScannerConfig.TITLE_WILDCARD_IAM_RESOURCE,
                    description=IaCScannerConfig.DESC_WILDCARD_IAM_RESOURCE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=IaCScannerConfig.CONFIDENCE_WILDCARD_IAM,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 3. Hardcoded secrets checks
    # ------------------------------------------------------------------

    def _check_hardcoded_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find hardcoded secrets in variable defaults or tfvars."""
        findings: list[CodeFinding] = []

        for pattern, secret_type in IaCScannerConfig.SECRET_IN_DEFAULT_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.CRITICAL,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=IaCScannerConfig.TITLE_HARDCODED_SECRET.format(
                            secret_type=secret_type
                        ),
                        description=IaCScannerConfig.DESC_HARDCODED_SECRET.format(
                            secret_type=secret_type, file=file_path
                        ),
                        file_path=file_path,
                        confidence=IaCScannerConfig.CONFIDENCE_HARDCODED_SECRET,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 4. S3 bucket checks
    # ------------------------------------------------------------------

    def _check_s3_buckets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find S3 buckets with public ACLs."""
        findings: list[CodeFinding] = []

        if any(
            re.search(p, content) for p in IaCScannerConfig.PUBLIC_ACL_PATTERNS
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.EXPOSED_API_ENDPOINT,
                    title=IaCScannerConfig.TITLE_PUBLIC_S3,
                    description=IaCScannerConfig.DESC_PUBLIC_S3.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=IaCScannerConfig.CONFIDENCE_PUBLIC_S3,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 5. Secrets Manager checks
    # ------------------------------------------------------------------

    def _check_secrets_manager(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for Secrets Manager with zero recovery window."""
        findings: list[CodeFinding] = []

        if re.search(IaCScannerConfig.RECOVERY_WINDOW_ZERO_PATTERN, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=IaCScannerConfig.TITLE_RECOVERY_ZERO,
                    description=IaCScannerConfig.DESC_RECOVERY_ZERO.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=IaCScannerConfig.CONFIDENCE_RECOVERY_ZERO,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 6. ALB HTTP check
    # ------------------------------------------------------------------

    def _check_alb_http(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for ALB listeners forwarding HTTP without HTTPS redirect."""
        findings: list[CodeFinding] = []

        if re.search(
            IaCScannerConfig.HTTP_FORWARD_PATTERN, content, re.DOTALL
        ):
            # Check if there's also an HTTPS listener or redirect in the
            # same file — if so, the HTTP forward may be conditional
            has_https = "protocol" in content and '"HTTPS"' in content
            has_redirect = '"redirect"' in content

            if not has_https and not has_redirect:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.MISSING_HEADERS,
                        title=IaCScannerConfig.TITLE_HTTP_FORWARD,
                        description=IaCScannerConfig.DESC_HTTP_FORWARD.format(
                            file=file_path
                        ),
                        file_path=file_path,
                        confidence=IaCScannerConfig.CONFIDENCE_HTTP_FORWARD,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 7. ECS public IP check
    # ------------------------------------------------------------------

    def _check_ecs_public_ip(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for ECS tasks with direct public IP assignment."""
        findings: list[CodeFinding] = []

        if re.search(IaCScannerConfig.ECS_PUBLIC_IP_PATTERN, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=IaCScannerConfig.TITLE_ECS_PUBLIC_IP,
                    description=IaCScannerConfig.DESC_ECS_PUBLIC_IP.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=IaCScannerConfig.CONFIDENCE_ECS_PUBLIC_IP,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 8. Log retention check
    # ------------------------------------------------------------------

    def _check_log_retention(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for short CloudWatch log retention periods."""
        findings: list[CodeFinding] = []

        for match in re.finditer(
            IaCScannerConfig.LOG_RETENTION_PATTERN, content
        ):
            days = int(match.group(1))

            if days <= IaCScannerConfig.SHORT_LOG_RETENTION_THRESHOLD:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.LOW,
                        category=FindingCategory.INFO_DISCLOSURE,
                        title=IaCScannerConfig.TITLE_SHORT_LOG_RETENTION.format(
                            days=days
                        ),
                        description=IaCScannerConfig.DESC_SHORT_LOG_RETENTION.format(
                            file=file_path, days=days
                        ),
                        file_path=file_path,
                        confidence=IaCScannerConfig.CONFIDENCE_SHORT_LOG_RETENTION,
                    )
                )

        return findings
