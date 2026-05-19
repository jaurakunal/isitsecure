"""Out-of-Band (OOB) callback service for blind vulnerability detection.

Uses interactsh v1 protocol (by ProjectDiscovery) with encrypted sessions.
Supports self-hosted servers (primary) and public fallbacks.

Protocol:
    1. ``register()``  — RSA key exchange with the interactsh server
    2. ``generate_url(tag)`` — create ``<corr_id><nonce>.<domain>`` callback
    3. Scanners inject these URLs into payloads
    4. ``poll()`` — fetch + AES-decrypt callback interactions
    5. ``get_findings()`` — convert hits into DeepFindings

Each callback URL encodes the scanner name + payload ID so hits can
be correlated back to the exact payload that triggered them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import string
from dataclasses import dataclass, field

import httpx

from isitsecure.engine.constants import OOBConfig
from isitsecure.engine.models import DeepFinding, FindingSource
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)

# Lazy-import cryptography (only when OOB is actually used)
_crypto_available: bool | None = None


def _ensure_crypto() -> bool:
    """Import cryptography primitives on first use."""
    global _crypto_available  # noqa: PLW0603
    if _crypto_available is not None:
        return _crypto_available
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
        _crypto_available = True
    except ImportError:
        logger.warning("cryptography package not installed — OOB disabled")
        _crypto_available = False
    return _crypto_available


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class OOBInteraction:
    """A single callback interaction received by the OOB server."""

    tag: str  # scanner-name + payload-id encoded in subdomain
    interaction_type: str  # "dns", "http", "smtp"
    remote_address: str = ""
    raw_request: str = ""
    timestamp: str = ""


@dataclass
class OOBSession:
    """Active OOB callback session with crypto state."""

    correlation_id: str = ""
    domain: str = ""  # e.g. "oob.isitsecure.ai"
    server_url: str = ""
    secret_key: str = ""
    registered: bool = False
    # RSA keypair for interactsh v1 encrypted protocol
    private_key: object | None = None  # RSA private key
    public_key_b64: str = ""  # base64(PEM) for registration


class OOBCallbackService:
    """Manages OOB callback URLs and polls for interactions.

    Implements the interactsh v1 encrypted protocol:
    - Registration via RSA public key exchange
    - Callback URLs: ``<correlation_id><nonce>.<domain>``
    - Poll responses decrypted with AES-CFB (key from RSA-OAEP)

    Usage::

        oob = OOBCallbackService()
        await oob.register()

        # In SSRF scanner:
        url = oob.generate_url("ssrf", "param-url-endpoint1")
        # inject url into SSRF payload...

        # After all scanners finish:
        await oob.poll()
        findings = oob.get_findings()
    """

    def __init__(self) -> None:
        self._session = OOBSession()
        self._pending_tags: dict[str, _TagMetadata] = {}
        self._interactions: list[OOBInteraction] = []

    @property
    def is_registered(self) -> bool:
        return self._session.registered

    @property
    def interaction_count(self) -> int:
        return len(self._interactions)

    # ------------------------------------------------------------------
    # Phase 1: Register with interactsh (v1 encrypted protocol)
    # ------------------------------------------------------------------

    async def register(self) -> bool:
        """Register a new session with the OOB callback server.

        Generates an RSA keypair, sends the public key to the server,
        and stores the private key for decrypting poll responses.
        Tries each server in ``OOBConfig.SERVERS`` until one responds.

        Returns:
            True if registration succeeded, False otherwise.
        """
        if not _ensure_crypto():
            return False

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # Generate RSA keypair for this session
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=OOBConfig.RSA_KEY_SIZE,
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        pub_b64 = base64.b64encode(pub_pem.encode()).decode()

        # Generate correlation ID (lowercase alphanumeric)
        charset = string.ascii_lowercase + string.digits
        corr_id = "".join(
            random.choice(charset)  # noqa: S311
            for _ in range(OOBConfig.CORRELATION_ID_LENGTH)
        )

        # Secret key for poll authentication
        secret_key = base64.b64encode(os.urandom(32)).decode()

        for server_url in OOBConfig.SERVERS:
            try:
                async with httpx.AsyncClient(
                    timeout=OOBConfig.HTTP_TIMEOUT_SECONDS,
                ) as client:
                    resp = await client.post(
                        f"{server_url}{OOBConfig.REGISTER_PATH}",
                        json={
                            "public-key": pub_b64,
                            "secret-key": secret_key,
                            "correlation-id": corr_id,
                        },
                    )
                    if resp.status_code != 200:
                        continue

                    # Determine the domain for callback URLs
                    domain = self._resolve_domain(server_url)

                    self._session = OOBSession(
                        correlation_id=corr_id,
                        domain=domain,
                        server_url=server_url,
                        secret_key=secret_key,
                        registered=True,
                        private_key=private_key,
                        public_key_b64=pub_b64,
                    )

                    logger.info(
                        OOBConfig.LOG_REGISTERED,
                        domain,
                        server_url,
                    )
                    return True

            except Exception as exc:
                logger.debug(
                    "OOB register failed for %s: %s", server_url, exc,
                )

        logger.warning(OOBConfig.ERROR_REGISTER_FAILED)
        return False

    @staticmethod
    def _resolve_domain(server_url: str) -> str:
        """Extract the domain from a server URL for callback generation.

        Self-hosted servers use ``OOBConfig.SELF_HOSTED_DOMAIN``.
        Public servers derive the domain from the URL hostname.
        """
        if OOBConfig.SELF_HOSTED_DOMAIN in server_url:
            return OOBConfig.SELF_HOSTED_DOMAIN
        # Public servers: https://oast.pro → oast.pro
        from urllib.parse import urlparse
        return urlparse(server_url).hostname or server_url

    # ------------------------------------------------------------------
    # Phase 2: Generate callback URLs
    # ------------------------------------------------------------------

    def generate_url(
        self,
        scanner_name: str,
        payload_id: str,
        endpoint_url: str = "",
        param_name: str = "",
        description: str = "",
    ) -> str:
        """Generate a unique OOB callback URL for a specific payload.

        interactsh v1 subdomain format:
            ``<correlation_id><nonce>.<domain>``

        The correlation_id (first 20 chars) lets the server match the
        interaction to our session.  The nonce (13 chars) is unique
        per callback URL so we can correlate hits to specific payloads.

        We store a mapping from nonce → tag metadata so that when we
        decrypt interactions, we can look up which scanner/payload
        triggered each hit.

        Returns:
            Full callback URL like ``http://<corr_id><nonce>.oob.isitsecure.ai``
        """
        if not self._session.registered:
            return ""

        charset = string.ascii_lowercase + string.digits
        nonce = "".join(
            random.choice(charset)  # noqa: S311
            for _ in range(OOBConfig.NONCE_LENGTH)
        )

        # Tag for internal tracking (maps scanner+payload to this nonce)
        tag = f"{scanner_name}-{nonce}"

        self._pending_tags[tag] = _TagMetadata(
            scanner_name=scanner_name,
            payload_id=payload_id,
            endpoint_url=endpoint_url,
            param_name=param_name,
            description=description,
            nonce=nonce,
        )

        # interactsh v1 format: <corr_id><nonce>.<domain>
        subdomain = f"{self._session.correlation_id}{nonce}"
        return f"http://{subdomain}.{self._session.domain}"

    # ------------------------------------------------------------------
    # Phase 3: Poll for interactions (encrypted)
    # ------------------------------------------------------------------

    async def poll(self) -> list[OOBInteraction]:
        """Poll the OOB server for callback interactions and decrypt them.

        Waits ``OOBConfig.POLL_DELAY_SECONDS`` first to give time for
        delayed callbacks (DNS propagation, async server processing).

        Returns:
            List of decrypted interactions received.
        """
        if not self._session.registered:
            return []

        await asyncio.sleep(OOBConfig.POLL_DELAY_SECONDS)

        for attempt in range(OOBConfig.POLL_ATTEMPTS):
            try:
                async with httpx.AsyncClient(
                    timeout=OOBConfig.HTTP_TIMEOUT_SECONDS,
                ) as client:
                    resp = await client.get(
                        f"{self._session.server_url}{OOBConfig.POLL_PATH}",
                        params={
                            "id": self._session.correlation_id,
                            "secret": self._session.secret_key,
                        },
                    )

                    if resp.status_code != 200:
                        continue

                    data = resp.json()
                    aes_key_enc = data.get("aes_key", "")
                    raw_encrypted = data.get("data") or []

                    if aes_key_enc and raw_encrypted:
                        decrypted = self._decrypt_interactions(
                            aes_key_enc, raw_encrypted,
                        )
                        for interaction_data in decrypted:
                            self._process_interaction(interaction_data)

                    if self._interactions:
                        break

            except Exception as exc:
                logger.debug("OOB poll attempt %d failed: %s", attempt, exc)

            if attempt < OOBConfig.POLL_ATTEMPTS - 1:
                await asyncio.sleep(OOBConfig.POLL_INTERVAL_SECONDS)

        logger.info(
            OOBConfig.LOG_POLL_COMPLETE,
            len(self._interactions),
            len(self._pending_tags),
        )
        return self._interactions

    def _decrypt_interactions(
        self,
        aes_key_encrypted: str,
        encrypted_interactions: list[str],
    ) -> list[dict]:
        """Decrypt AES key with RSA, then decrypt each interaction.

        interactsh v1 encryption:
            - AES key: RSA-OAEP encrypted, base64-encoded
            - Interactions: AES-CFB encrypted (IV = first 16 bytes)
        """
        if not _ensure_crypto():
            return []

        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        try:
            # Decrypt AES key with our RSA private key
            aes_key = self._session.private_key.decrypt(
                base64.b64decode(aes_key_encrypted),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            logger.warning("Failed to decrypt AES key: %s", exc)
            return []

        decrypted: list[dict] = []
        for enc_b64 in encrypted_interactions:
            try:
                enc_bytes = base64.b64decode(enc_b64)
                iv = enc_bytes[:16]
                ciphertext = enc_bytes[16:]
                decryptor = Cipher(
                    algorithms.AES(aes_key), modes.CFB(iv),
                ).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                decrypted.append(json.loads(plaintext.decode()))
            except Exception as exc:
                logger.debug("Failed to decrypt interaction: %s", exc)

        return decrypted

    def _process_interaction(self, interaction_data: dict) -> None:
        """Extract tag from a decrypted interaction and store it."""
        tag = self._extract_tag(interaction_data)
        if tag and tag in self._pending_tags:
            self._interactions.append(OOBInteraction(
                tag=tag,
                interaction_type=(
                    interaction_data.get("protocol", "")
                    or interaction_data.get("type", "")
                ),
                remote_address=(
                    interaction_data.get("remote-address", "")
                    or interaction_data.get("remoteAddress", "")
                ),
                raw_request=(
                    interaction_data.get("raw-request", "")
                    or interaction_data.get("rawRequest", "")
                ),
                timestamp=interaction_data.get("timestamp", ""),
            ))

    # ------------------------------------------------------------------
    # Phase 4: Convert interactions to findings
    # ------------------------------------------------------------------

    def get_findings(self) -> list[DeepFinding]:
        """Convert confirmed OOB interactions into DeepFindings.

        Each interaction proves a blind vulnerability — the target
        server made an outbound request to our callback URL.
        """
        findings: list[DeepFinding] = []
        seen_tags: set[str] = set()

        for interaction in self._interactions:
            if interaction.tag in seen_tags:
                continue
            seen_tags.add(interaction.tag)

            metadata = self._pending_tags.get(interaction.tag)
            if not metadata:
                continue

            severity = OOBConfig.SCANNER_SEVERITY.get(
                metadata.scanner_name, SeverityLevel.HIGH,
            )
            category = OOBConfig.SCANNER_CATEGORY.get(
                metadata.scanner_name, FindingCategory.INJECTION_RISK,
            )

            findings.append(DeepFinding(
                source=FindingSource.DAST_URL,
                category=category,
                severity=severity,
                title=OOBConfig.TITLE_OOB_CONFIRMED.format(
                    scanner=metadata.scanner_name,
                    desc=metadata.description or metadata.payload_id,
                ),
                description=OOBConfig.DESC_OOB_CONFIRMED.format(
                    scanner=metadata.scanner_name,
                    desc=metadata.description or metadata.payload_id,
                    endpoint=metadata.endpoint_url,
                    param=metadata.param_name,
                    interaction_type=interaction.interaction_type,
                ),
                technical_detail=(
                    f"**Blind vulnerability confirmed via OOB callback**\n\n"
                    f"**Scanner:** {metadata.scanner_name}\n"
                    f"**Endpoint:** {metadata.endpoint_url}\n"
                    f"**Parameter:** {metadata.param_name}\n"
                    f"**Callback type:** {interaction.interaction_type}\n"
                    f"**Remote address:** {interaction.remote_address}\n\n"
                    f"The target server made an outbound "
                    f"{interaction.interaction_type} request to the OOB "
                    f"callback URL, confirming the server processes "
                    f"attacker-controlled URLs/commands server-side."
                ),
                evidence=(
                    f"OOB {interaction.interaction_type} callback received "
                    f"from {interaction.remote_address} for payload "
                    f"'{metadata.payload_id}' on {metadata.endpoint_url}"
                ),
                confidence=OOBConfig.CONFIDENCE_OOB_CONFIRMED,
                scanner_name=f"oob_{metadata.scanner_name}",
                endpoint_url=metadata.endpoint_url,
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_tag(self, raw_interaction: dict) -> str | None:
        """Extract the tag from a decrypted interact.sh interaction.

        interactsh v1 ``unique-id`` / ``full-id`` contains:
            ``<correlation_id><nonce>``  (no domain suffix)

        We extract the nonce (last 13 chars) and look up the
        scanner tag via the nonce → _TagMetadata mapping.
        """
        unique_id = (
            raw_interaction.get("full-id", "")
            or raw_interaction.get("fullId", "")
            or raw_interaction.get("unique-id", "")
            or raw_interaction.get("uniqueId", "")
        )

        if unique_id and self._session.correlation_id:
            # Strip domain suffix if present
            domain_suffix = f".{self._session.domain}"
            if unique_id.endswith(domain_suffix):
                unique_id = unique_id[: -len(domain_suffix)]

            # Extract nonce: last NONCE_LENGTH characters
            nonce_len = OOBConfig.NONCE_LENGTH
            if len(unique_id) >= OOBConfig.CORRELATION_ID_LENGTH + nonce_len:
                nonce = unique_id[-nonce_len:]
                # Look up tag by nonce
                for tag, meta in self._pending_tags.items():
                    if meta.nonce == nonce:
                        return tag

        # Fallback: check raw request for any known nonce/tag
        raw = (
            raw_interaction.get("raw-request", "")
            or raw_interaction.get("rawRequest", "")
        )
        for tag, meta in self._pending_tags.items():
            if meta.nonce in raw or tag in raw:
                return tag

        return None


@dataclass
class _TagMetadata:
    """Metadata associated with a pending OOB callback tag."""

    scanner_name: str
    payload_id: str
    endpoint_url: str = ""
    param_name: str = ""
    description: str = ""
    nonce: str = ""  # The 13-char nonce used in the subdomain
