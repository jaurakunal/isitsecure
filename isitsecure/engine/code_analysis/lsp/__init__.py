"""LSP integration for semantic code analysis.

Provides TypeScript Language Server Protocol support for:
- Cross-file auth flow tracing (go-to-definition)
- Symbol reference resolution (find-references)
- Type information extraction (hover)

Graceful degradation: when Node.js/tsserver is unavailable,
``NoOpLSPClient`` provides empty results and the scan falls
back to regex-only analysis.
"""
