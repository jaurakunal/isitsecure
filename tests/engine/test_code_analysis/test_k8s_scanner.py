"""Tests for K8sScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.k8s_scanner import K8sScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import K8sScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

K8S_PRIVILEGED_CONTAINER = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.0.0
          securityContext:
            privileged: true
"""

K8S_RUN_AS_ROOT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.0.0
          securityContext:
            runAsUser: 0
"""

K8S_LATEST_IMAGE_TAG = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: nginx:latest
"""

K8S_ALL_CAPABILITIES = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.0.0
          securityContext:
            capabilities:
              add:
                - ALL
"""

K8S_HARDCODED_SECRET = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.0.0
          env:
            - name: DB_PASSWORD
              value: supersecretpassword123
"""

K8S_HELM_TEMPLATE_ENV = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.0.0
          env:
            - name: DB_PASSWORD
              value: {{.Values.database.password}}
"""

K8S_LOADBALANCER_NO_INTERNAL = """\
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
"""

K8S_LOADBALANCER_WITH_INTERNAL = """\
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
"""

K8S_SECURE_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:1.2.3
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL
          env:
            - name: DB_HOST
              valueFrom:
                secretKeyRef:
                  name: db-secret
                  key: host
"""

NO_K8S_CODE = """\
const express = require('express');
const app = express();
app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=[],
        package_json={},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerName:
    def test_scanner_name(self) -> None:
        scanner = K8sScanner()
        assert scanner.scanner_name == K8sScannerConfig.SCANNER_NAME


class TestNoK8sFiles:
    @pytest.mark.asyncio
    async def test_empty_when_no_k8s_files(self) -> None:
        """No K8s manifests -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_K8S_CODE})
        scanner = K8sScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0


class TestPrivilegedContainer:
    @pytest.mark.asyncio
    async def test_flags_privileged_true(self) -> None:
        """privileged: true -> CRITICAL finding."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_PRIVILEGED_CONTAINER}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        priv_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_PRIVILEGED
        ]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == SeverityLevel.CRITICAL
        assert priv_findings[0].category == FindingCategory.PRIVILEGE_ESCALATION
        assert priv_findings[0].confidence == K8sScannerConfig.CONFIDENCE_PRIVILEGED


class TestRunAsRoot:
    @pytest.mark.asyncio
    async def test_flags_run_as_user_zero(self) -> None:
        """runAsUser: 0 -> HIGH finding."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_RUN_AS_ROOT}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        root_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_RUN_AS_ROOT
        ]
        assert len(root_findings) == 1
        assert root_findings[0].severity == SeverityLevel.HIGH
        assert root_findings[0].category == FindingCategory.PRIVILEGE_ESCALATION
        assert root_findings[0].confidence == K8sScannerConfig.CONFIDENCE_RUN_AS_ROOT


class TestLatestImageTag:
    @pytest.mark.asyncio
    async def test_flags_latest_tag(self) -> None:
        """image: nginx:latest -> LOW finding."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_LATEST_IMAGE_TAG}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        tag_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_IMAGE_TAG
        ]
        assert len(tag_findings) == 1
        assert tag_findings[0].severity == SeverityLevel.LOW
        assert tag_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert tag_findings[0].confidence == K8sScannerConfig.CONFIDENCE_IMAGE_TAG


class TestAllCapabilities:
    @pytest.mark.asyncio
    async def test_flags_all_capabilities(self) -> None:
        """capabilities.add: [ALL] -> CRITICAL finding."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_ALL_CAPABILITIES}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        cap_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_ALL_CAPABILITIES
        ]
        assert len(cap_findings) == 1
        assert cap_findings[0].severity == SeverityLevel.CRITICAL
        assert cap_findings[0].category == FindingCategory.PRIVILEGE_ESCALATION
        assert cap_findings[0].confidence == K8sScannerConfig.CONFIDENCE_ALL_CAPABILITIES


class TestHardcodedSecretInEnv:
    @pytest.mark.asyncio
    async def test_flags_hardcoded_password(self) -> None:
        """Hardcoded password in env value -> CRITICAL finding."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_HARDCODED_SECRET}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
        ]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == SeverityLevel.CRITICAL
        assert secret_findings[0].confidence == K8sScannerConfig.CONFIDENCE_ENV_SECRET


class TestHelmTemplateNotFlagged:
    @pytest.mark.asyncio
    async def test_skips_helm_template_values(self) -> None:
        """{{ .Values.x }} expressions should NOT be flagged as hardcoded secrets."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_HELM_TEMPLATE_ENV}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
        ]
        assert len(secret_findings) == 0


class TestLoadBalancerNoInternal:
    @pytest.mark.asyncio
    async def test_flags_loadbalancer_without_internal(self) -> None:
        """type: LoadBalancer without internal annotation -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"k8s/service.yaml": K8S_LOADBALANCER_NO_INTERNAL}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        lb_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_LOADBALANCER_EXTERNAL
        ]
        assert len(lb_findings) == 1
        assert lb_findings[0].severity == SeverityLevel.MEDIUM
        assert lb_findings[0].category == FindingCategory.EXPOSED_API_ENDPOINT
        assert lb_findings[0].confidence == K8sScannerConfig.CONFIDENCE_LOADBALANCER

    @pytest.mark.asyncio
    async def test_no_finding_with_internal_annotation(self) -> None:
        """LoadBalancer with internal annotation -> no finding."""
        repo = _make_repo(
            file_index={"k8s/service.yaml": K8S_LOADBALANCER_WITH_INTERNAL}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        lb_findings = [
            f for f in findings
            if f.title == K8sScannerConfig.TITLE_LOADBALANCER_EXTERNAL
        ]
        assert len(lb_findings) == 0


class TestSecureDeployment:
    @pytest.mark.asyncio
    async def test_no_critical_findings_for_secure_deployment(self) -> None:
        """Well-configured deployment -> no CRITICAL/HIGH findings."""
        repo = _make_repo(
            file_index={"k8s/deployment.yaml": K8S_SECURE_DEPLOYMENT}
        )
        scanner = K8sScanner()
        findings = await scanner.scan(repo)

        critical_findings = [
            f for f in findings
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        ]
        assert len(critical_findings) == 0
