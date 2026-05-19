"""Authentication infrastructure for the Deep Security Scan Agent."""

from .browser_auth import BrowserAuthProvider
from .protocols import AuthCredentials, AuthProviderProtocol, AuthSession
from .supabase_auth import SupabaseAuthProvider
from .token_auth import TokenAuthProvider

__all__ = [
    "AuthCredentials",
    "AuthProviderProtocol",
    "AuthSession",
    "BrowserAuthProvider",
    "SupabaseAuthProvider",
    "TokenAuthProvider",
]
