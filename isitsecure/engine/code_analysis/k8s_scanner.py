"""Kubernetes and Helm manifest security scanner.

Scans Kubernetes manifests and Helm charts for security
misconfigurations such as privileged containers, running as root,
host namespace sharing, hardcoded secrets, and missing image tags.

SRP: This scanner is responsible ONLY for analyzing Kubernetes and Helm
     files for security misconfigurations.  It does not analyze
     application code, Docker files, or runtime behavior.

OCP: Implements ``CodeScannerProtocol`` -- added to the sast_scanners
     list without modifying the agent or factory.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import K8sScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class K8sScanner:
    """Scans Kubernetes manifests and Helm charts for security issues.

    Discovers K8s manifests via two strategies:
    1. Files already in ``repo.file_index`` that contain ``apiVersion:``
    2. .yaml/.yml files found by scanning K8s-specific directories
       under ``repo.clone_path`` using ``Path.rglob()``

    Checks performed:
    1. Privileged containers (``privileged: true``)
    2. Running as root (``runAsUser: 0`` or ``runAsNonRoot: false``)
    3. Host namespace sharing (``hostNetwork``, ``hostPID``)
    4. Secrets in env values (hardcoded API keys, passwords)
    5. Latest/missing image tag
    6. ALL capabilities (``capabilities.add: ["ALL"]``)
    7. LoadBalancer without internal annotation
    8. Helm values.yaml with plaintext secrets

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return K8sScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Kubernetes manifests and Helm charts for security issues."""
        findings: list[CodeFinding] = []

        k8s_files = self._find_k8s_files(repo)

        if not k8s_files:
            return findings

        for file_path, content in k8s_files.items():
            try:
                is_values_yaml = file_path.endswith(
                    K8sScannerConfig.VALUES_YAML_NAME
                )

                if is_values_yaml:
                    findings.extend(
                        self._check_helm_plaintext_secrets(content, file_path)
                    )
                else:
                    findings.extend(self._check_privileged(content, file_path))
                    findings.extend(self._check_run_as_root(content, file_path))
                    findings.extend(self._check_host_namespace(content, file_path))
                    findings.extend(self._check_env_secrets(content, file_path))
                    findings.extend(self._check_image_tag(content, file_path))
                    findings.extend(self._check_all_capabilities(content, file_path))
                    findings.extend(self._check_loadbalancer(content, file_path))
            except Exception as e:
                logger.warning(
                    K8sScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        logger.info(
            "K8sScanner: %d manifest files scanned, %d findings",
            len(k8s_files),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_k8s_files(self, repo: RepoSnapshot) -> dict[str, str]:
        """Find Kubernetes manifests in file_index and K8s directories.

        Two strategies:
        1. Files in ``file_index`` containing ``apiVersion:``
        2. .yaml/.yml files in K8s-specific directories via Path.rglob()
        """
        k8s_files: dict[str, str] = {}

        # Strategy 1: Check file_index for files with apiVersion:
        for path, content in repo.file_index.items():
            if not any(
                path.endswith(ext) for ext in K8sScannerConfig.K8S_EXTENSIONS
            ):
                continue
            if re.search(K8sScannerConfig.API_VERSION_MARKER, content):
                k8s_files[path] = content

        # Strategy 2: Scan K8s directories from clone_path
        if repo.clone_path:
            clone_root = Path(repo.clone_path)
            for k8s_dir_name in K8sScannerConfig.K8S_DIRECTORIES:
                k8s_dir = clone_root / k8s_dir_name
                if not k8s_dir.is_dir():
                    continue
                for ext in K8sScannerConfig.K8S_EXTENSIONS:
                    for yaml_file in k8s_dir.rglob(f"*{ext}"):
                        rel_path = str(yaml_file.relative_to(clone_root))
                        if rel_path in k8s_files:
                            continue
                        try:
                            content = yaml_file.read_text(
                                encoding="utf-8", errors="ignore"
                            )
                            k8s_files[rel_path] = content
                        except OSError:
                            continue

        return k8s_files

    # ------------------------------------------------------------------
    # 1. Privileged containers
    # ------------------------------------------------------------------

    def _check_privileged(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for containers running in privileged mode."""
        findings: list[CodeFinding] = []

        if re.search(K8sScannerConfig.PRIVILEGED_PATTERN, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=K8sScannerConfig.TITLE_PRIVILEGED,
                    description=K8sScannerConfig.DESC_PRIVILEGED.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=K8sScannerConfig.CONFIDENCE_PRIVILEGED,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 2. Running as root
    # ------------------------------------------------------------------

    def _check_run_as_root(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for containers configured to run as root."""
        findings: list[CodeFinding] = []

        if any(
            re.search(p, content)
            for p in K8sScannerConfig.RUN_AS_ROOT_PATTERNS
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=K8sScannerConfig.TITLE_RUN_AS_ROOT,
                    description=K8sScannerConfig.DESC_RUN_AS_ROOT.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=K8sScannerConfig.CONFIDENCE_RUN_AS_ROOT,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 3. Host namespace sharing
    # ------------------------------------------------------------------

    def _check_host_namespace(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for host namespace sharing (hostNetwork, hostPID)."""
        findings: list[CodeFinding] = []

        for pattern, ns_type in K8sScannerConfig.HOST_NAMESPACE_PATTERNS:
            if re.search(pattern, content):
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.PRIVILEGE_ESCALATION,
                        title=K8sScannerConfig.TITLE_HOST_NAMESPACE.format(
                            namespace_type=ns_type
                        ),
                        description=K8sScannerConfig.DESC_HOST_NAMESPACE.format(
                            file=file_path, namespace_type=ns_type
                        ),
                        file_path=file_path,
                        confidence=K8sScannerConfig.CONFIDENCE_HOST_NAMESPACE,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 4. Secrets in env values
    # ------------------------------------------------------------------

    def _check_env_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for hardcoded secrets in container env values."""
        findings: list[CodeFinding] = []

        for pattern, secret_type in K8sScannerConfig.ENV_SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(1)

                # Skip Helm template expressions
                if re.search(K8sScannerConfig.HELM_TEMPLATE_PATTERN, value):
                    continue

                # Skip variable references and placeholders
                if any(
                    re.search(skip, value)
                    for skip in K8sScannerConfig.SECRET_SKIP_PATTERNS
                ):
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.CRITICAL,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=K8sScannerConfig.TITLE_ENV_SECRET.format(
                            secret_type=secret_type
                        ),
                        description=K8sScannerConfig.DESC_ENV_SECRET.format(
                            secret_type=secret_type, file=file_path
                        ),
                        file_path=file_path,
                        confidence=K8sScannerConfig.CONFIDENCE_ENV_SECRET,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 5. Latest/missing image tag
    # ------------------------------------------------------------------

    def _check_image_tag(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for container images using :latest or no tag."""
        findings: list[CodeFinding] = []

        for pattern in K8sScannerConfig.IMAGE_TAG_PATTERNS:
            for match in re.finditer(pattern, content):
                image = match.group(1) if match.lastindex else match.group(0)

                # Skip Helm template expressions
                if re.search(K8sScannerConfig.HELM_TEMPLATE_PATTERN, image):
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.LOW,
                        category=FindingCategory.INFO_DISCLOSURE,
                        title=K8sScannerConfig.TITLE_IMAGE_TAG,
                        description=K8sScannerConfig.DESC_IMAGE_TAG.format(
                            file=file_path, image=image
                        ),
                        file_path=file_path,
                        confidence=K8sScannerConfig.CONFIDENCE_IMAGE_TAG,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 6. ALL capabilities
    # ------------------------------------------------------------------

    def _check_all_capabilities(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for containers adding ALL capabilities."""
        findings: list[CodeFinding] = []

        if re.search(
            K8sScannerConfig.ALL_CAPABILITIES_PATTERN, content, re.DOTALL
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=K8sScannerConfig.TITLE_ALL_CAPABILITIES,
                    description=K8sScannerConfig.DESC_ALL_CAPABILITIES.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=K8sScannerConfig.CONFIDENCE_ALL_CAPABILITIES,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 7. LoadBalancer without internal annotation
    # ------------------------------------------------------------------

    def _check_loadbalancer(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for LoadBalancer services without internal annotation."""
        findings: list[CodeFinding] = []

        if re.search(K8sScannerConfig.LOADBALANCER_PATTERN, content):
            has_internal = any(
                re.search(p, content)
                for p in K8sScannerConfig.INTERNAL_LB_ANNOTATION_PATTERNS
            )

            if not has_internal:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.EXPOSED_API_ENDPOINT,
                        title=K8sScannerConfig.TITLE_LOADBALANCER_EXTERNAL,
                        description=K8sScannerConfig.DESC_LOADBALANCER_EXTERNAL.format(
                            file=file_path
                        ),
                        file_path=file_path,
                        confidence=K8sScannerConfig.CONFIDENCE_LOADBALANCER,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 8. Helm values.yaml with plaintext secrets
    # ------------------------------------------------------------------

    def _check_helm_plaintext_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check Helm values.yaml for plaintext secrets."""
        findings: list[CodeFinding] = []

        for pattern, secret_type in K8sScannerConfig.HELM_SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(1)

                # Skip Helm template expressions
                if re.search(K8sScannerConfig.HELM_TEMPLATE_PATTERN, value):
                    continue

                # Skip placeholders and empty values
                if any(
                    re.search(skip, value)
                    for skip in K8sScannerConfig.SECRET_SKIP_PATTERNS
                ):
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=K8sScannerConfig.TITLE_HELM_SECRET.format(
                            secret_type=secret_type
                        ),
                        description=K8sScannerConfig.DESC_HELM_SECRET.format(
                            secret_type=secret_type, file=file_path
                        ),
                        file_path=file_path,
                        confidence=K8sScannerConfig.CONFIDENCE_HELM_SECRET,
                    )
                )

        return findings
