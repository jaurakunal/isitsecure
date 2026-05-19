"""Tests for FrameworkDetector."""

from isitsecure.engine.code_analysis.framework_detector import (
    FrameworkDetector,
)
from isitsecure.engine.enums import BackendType, FrameworkType


class TestFrameworkDetector:
    """Tests for framework, backend, and auth detection."""

    def setup_method(self) -> None:
        self.detector = FrameworkDetector()

    # --- Framework detection ---

    def test_detect_nextjs(self) -> None:
        """Should detect Next.js from package.json."""
        pkg = {"dependencies": {"next": "14.0.0", "react": "18.0.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.NEXTJS

    def test_detect_remix(self) -> None:
        """Should detect Remix from package.json."""
        pkg = {"dependencies": {"@remix-run/node": "2.0.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.REMIX

    def test_detect_sveltekit(self) -> None:
        """Should detect SvelteKit from package.json."""
        pkg = {"dependencies": {"@sveltejs/kit": "1.0.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.SVELTEKIT

    def test_detect_nuxt(self) -> None:
        """Should detect Nuxt from package.json."""
        pkg = {"dependencies": {"nuxt": "3.0.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.NUXT

    def test_detect_astro(self) -> None:
        """Should detect Astro from package.json."""
        pkg = {"dependencies": {"astro": "4.0.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.ASTRO

    def test_detect_express(self) -> None:
        """Should detect Express from package.json."""
        pkg = {"dependencies": {"express": "4.18.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.EXPRESS

    def test_detect_unknown_framework(self) -> None:
        """Should return UNKNOWN when no framework is detected."""
        pkg = {"dependencies": {"lodash": "4.17.0"}}
        assert self.detector.detect_framework(pkg) == FrameworkType.UNKNOWN

    def test_detect_unknown_framework_empty(self) -> None:
        """Should return UNKNOWN for empty package.json."""
        assert self.detector.detect_framework({}) == FrameworkType.UNKNOWN

    # --- Backend detection ---

    def test_detect_supabase_backend(self) -> None:
        """Should detect Supabase from package.json."""
        pkg = {"dependencies": {"@supabase/supabase-js": "2.0.0"}}
        assert self.detector.detect_backend(pkg) == BackendType.SUPABASE

    def test_detect_firebase_backend(self) -> None:
        """Should detect Firebase from package.json."""
        pkg = {"dependencies": {"firebase": "10.0.0"}}
        assert self.detector.detect_backend(pkg) == BackendType.FIREBASE

    def test_detect_prisma_backend(self) -> None:
        """Should detect Prisma from devDependencies."""
        pkg = {"devDependencies": {"prisma": "5.0.0"}}
        assert self.detector.detect_backend(pkg) == BackendType.PRISMA

    def test_detect_drizzle_backend(self) -> None:
        """Should detect Drizzle from package.json."""
        pkg = {"dependencies": {"drizzle-orm": "0.29.0"}}
        assert self.detector.detect_backend(pkg) == BackendType.DRIZZLE

    def test_detect_unknown_backend(self) -> None:
        """Should return UNKNOWN when no backend is detected."""
        pkg = {"dependencies": {"react": "18.0.0"}}
        assert self.detector.detect_backend(pkg) == BackendType.UNKNOWN

    # --- Auth detection ---

    def test_detect_supabase_auth(self) -> None:
        """Should detect Supabase auth helpers."""
        pkg = {"dependencies": {"@supabase/auth-helpers-nextjs": "0.8.0"}}
        assert self.detector.detect_auth_provider(pkg) == "supabase_auth"

    def test_detect_supabase_ssr_auth(self) -> None:
        """Should detect Supabase SSR auth."""
        pkg = {"dependencies": {"@supabase/ssr": "0.1.0"}}
        assert self.detector.detect_auth_provider(pkg) == "supabase_ssr"

    def test_detect_nextauth(self) -> None:
        """Should detect NextAuth.js."""
        pkg = {"dependencies": {"next-auth": "4.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == "nextauth"

    def test_detect_clerk_auth(self) -> None:
        """Should detect Clerk."""
        pkg = {"dependencies": {"@clerk/nextjs": "4.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == "clerk"

    def test_detect_auth0(self) -> None:
        """Should detect Auth0."""
        pkg = {"dependencies": {"@auth0/nextjs-auth0": "3.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == "auth0"

    def test_detect_lucia_auth(self) -> None:
        """Should detect Lucia."""
        pkg = {"dependencies": {"lucia": "3.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == "lucia"

    def test_detect_no_auth(self) -> None:
        """Should return empty string when no auth provider is detected."""
        pkg = {"dependencies": {"react": "18.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == ""

    def test_detect_auth_in_dev_dependencies(self) -> None:
        """Should also check devDependencies for auth providers."""
        pkg = {"devDependencies": {"next-auth": "4.0.0"}}
        assert self.detector.detect_auth_provider(pkg) == "nextauth"
