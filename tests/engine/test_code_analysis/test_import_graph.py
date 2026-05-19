"""Tests for ImportParser and ImportGraphBuilder."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.import_graph import (
    ImportGraphBuilder,
    ImportParser,
)


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

ES6_IMPORTS = """\
import { db } from './db';
import express from 'express';
import { helper } from '@/lib/helpers';
export { default } from './utils';
"""

CJS_REQUIRES = """\
const express = require('express');
const db = require('./db');
const utils = require('../lib/utils');
"""

DYNAMIC_IMPORTS = """\
const mod = await import('./lazy-module');
const other = await import('@/features/dashboard');
"""

REEXPORTS = """\
export * from './models';
export { UserService } from './services/user';
"""

PYTHON_IMPORTS = """\
from app.services.user import UserService
from app.db import get_connection
import os
import app.utils.helpers
"""

JS_WITH_COMMENTS = """\
// import { bad } from './should-not-match';
/* import { alsobad } from './commented-out'; */
import { real } from './real-import';
/*
const x = require('./multiline-comment');
*/
const y = require('./real-require');
"""

PYTHON_WITH_COMMENTS = """\
# from app.old import OldThing
from app.new import NewThing
# import app.deprecated
import app.current
"""


# ---------------------------------------------------------------------------
# ImportParser tests
# ---------------------------------------------------------------------------


class TestImportParserES6:
    def test_extracts_es6_imports(self) -> None:
        """ES6 import/export from statements -> specifiers extracted."""
        specifiers = ImportParser.parse_imports(ES6_IMPORTS, "src/app.ts")

        assert "./db" in specifiers
        assert "express" in specifiers
        assert "@/lib/helpers" in specifiers
        assert "./utils" in specifiers

    def test_extracts_reexports(self) -> None:
        """export * from / export { X } from -> specifiers extracted."""
        specifiers = ImportParser.parse_imports(REEXPORTS, "src/index.ts")

        assert "./models" in specifiers
        assert "./services/user" in specifiers


class TestImportParserCJS:
    def test_extracts_cjs_require(self) -> None:
        """require() calls -> specifiers extracted."""
        specifiers = ImportParser.parse_imports(CJS_REQUIRES, "src/app.js")

        assert "express" in specifiers
        assert "./db" in specifiers
        assert "../lib/utils" in specifiers


class TestImportParserDynamic:
    def test_extracts_dynamic_imports(self) -> None:
        """Dynamic import() -> specifiers extracted."""
        specifiers = ImportParser.parse_imports(
            DYNAMIC_IMPORTS, "src/app.ts"
        )

        assert "./lazy-module" in specifiers
        assert "@/features/dashboard" in specifiers


class TestImportParserPython:
    def test_extracts_python_imports(self) -> None:
        """from x import y and import x -> specifiers extracted."""
        specifiers = ImportParser.parse_imports(PYTHON_IMPORTS, "app/main.py")

        assert "app.services.user" in specifiers
        assert "app.db" in specifiers
        assert "os" in specifiers
        assert "app.utils.helpers" in specifiers


class TestImportParserComments:
    def test_js_comments_stripped(self) -> None:
        """Imports inside comments should not be matched."""
        specifiers = ImportParser.parse_imports(
            JS_WITH_COMMENTS, "src/app.ts"
        )

        assert "./real-import" in specifiers
        assert "./real-require" in specifiers
        assert "./should-not-match" not in specifiers
        assert "./commented-out" not in specifiers
        assert "./multiline-comment" not in specifiers

    def test_python_comments_stripped(self) -> None:
        """Python imports in comments should not be matched."""
        specifiers = ImportParser.parse_imports(
            PYTHON_WITH_COMMENTS, "app/main.py"
        )

        assert "app.new" in specifiers
        assert "app.current" in specifiers
        assert "app.old" not in specifiers
        assert "app.deprecated" not in specifiers


# ---------------------------------------------------------------------------
# ImportGraphBuilder tests
# ---------------------------------------------------------------------------


class TestImportGraphFanIn:
    def test_fan_in_computation(self) -> None:
        """Fan-in counts how many files import a given file."""
        file_index = {
            "src/db.ts": "export const db = {};",
            "src/routes/users.ts": "import { db } from '../db';",
            "src/routes/orders.ts": "import { db } from '../db';",
            "src/routes/admin.ts": "import { db } from '../db';",
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        assert "src/db.ts" in fan_in
        assert len(fan_in["src/db.ts"]) == 3
        assert "src/routes/users.ts" in fan_in["src/db.ts"]
        assert "src/routes/orders.ts" in fan_in["src/db.ts"]
        assert "src/routes/admin.ts" in fan_in["src/db.ts"]


class TestImportGraphRelativePaths:
    def test_relative_path_resolution(self) -> None:
        """./utils and ../lib/db should resolve to the correct file_index key."""
        file_index = {
            "src/lib/db.ts": "export const db = {};",
            "src/lib/utils.ts": "export const utils = {};",
            "src/routes/api.ts": (
                "import { db } from '../lib/db';\n"
                "import { utils } from '../lib/utils';\n"
            ),
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        assert "src/lib/db.ts" in fan_in
        assert "src/routes/api.ts" in fan_in["src/lib/db.ts"]

        assert "src/lib/utils.ts" in fan_in
        assert "src/routes/api.ts" in fan_in["src/lib/utils.ts"]


class TestImportGraphAliasResolution:
    def test_default_alias_resolution(self) -> None:
        """@/lib/helpers should resolve to src/lib/helpers.ts."""
        file_index = {
            "src/lib/helpers.ts": "export function helper() {}",
            "src/routes/api.ts": "import { helper } from '@/lib/helpers';",
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        assert "src/lib/helpers.ts" in fan_in
        assert "src/routes/api.ts" in fan_in["src/lib/helpers.ts"]


class TestImportGraphExtensionProbing:
    def test_extension_probing(self) -> None:
        """Bare import './utils' should resolve to './utils.ts'."""
        file_index = {
            "src/utils.ts": "export const x = 1;",
            "src/app.ts": "import { x } from './utils';",
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        assert "src/utils.ts" in fan_in
        assert "src/app.ts" in fan_in["src/utils.ts"]

    def test_index_file_probing(self) -> None:
        """Import './types' should resolve to './types/index.ts'."""
        file_index = {
            "src/types/index.ts": "export type User = {};",
            "src/app.ts": "import { User } from './types';",
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        assert "src/types/index.ts" in fan_in
        assert "src/app.ts" in fan_in["src/types/index.ts"]


class TestImportGraphExternalPackages:
    def test_external_packages_skipped(self) -> None:
        """External packages like 'express', 'react' should not appear in fan-in."""
        file_index = {
            "src/app.ts": (
                "import express from 'express';\n"
                "import React from 'react';\n"
                "import { db } from './db';\n"
            ),
            "src/db.ts": "export const db = {};",
        }

        builder = ImportGraphBuilder()
        fan_in = builder.build_fan_in_map(file_index)

        # External packages should not have entries
        for key in fan_in:
            assert "express" not in key
            assert "react" not in key

        # Local import should still work
        assert "src/db.ts" in fan_in
