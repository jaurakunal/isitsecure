"""Tests for GraphQLRouteMapper."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.graphql_route_mapper import (
    GraphQLRouteMapper,
)


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SDL_QUERY_AND_MUTATION = """\
type Query {
  users: [User!]!
  user(id: ID!): User
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  deleteUser(id: ID!): Boolean!
}
"""

SDL_WITH_INTROSPECTION = """\
type Query {
  users: [User!]!
  __typename: String
  __schema: __Schema
}
"""

TYPEGRAPHQL_RESOLVER = """\
import { Resolver, Query, Mutation, Authorized } from 'type-graphql';

@Resolver()
export class UserResolver {
  @Query()
  async users() {
    return await getUsers();
  }

  @Mutation()
  async createUser(input: CreateUserInput) {
    return await createUser(input);
  }
}
"""

POTHOS_RESOLVER = """\
import { builder } from '../builder';

builder.queryType({
  fields: (t) => ({
    hello: t.field('greeting', {
      type: 'String',
      resolve: () => 'Hello World',
    }),
  }),
});

builder.mutationType({
  fields: (t) => ({
    addItem: t.field('addItem', {
      type: 'Item',
      resolve: (_, args) => createItem(args),
    }),
  }),
});
"""

NEXUS_RESOLVER = """\
import { queryField, mutationField } from 'nexus';

export const usersQuery = queryField('listUsers', {
  type: list('User'),
  resolve: (_, args, ctx) => ctx.db.users(),
});

export const createUserMutation = mutationField('registerUser', {
  type: 'User',
  resolve: (_, args, ctx) => ctx.db.createUser(args),
});
"""

RESOLVER_WITH_AUTH = """\
import { Resolver, Query, Authorized } from 'type-graphql';

@Resolver()
export class ProtectedResolver {
  @Authorized()
  @Query()
  async protectedData() {
    const user = ctx.user;
    return await getData();
  }
}
"""

NO_GRAPHQL_CODE = """\
const express = require('express');
const app = express();
app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNoGraphQLFiles:
    def test_no_graphql_files(self, tmp_path) -> None:
        """No GraphQL files -> 0 routes."""
        # Create a src directory with a non-GraphQL file
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.ts").write_text(NO_GRAPHQL_CODE)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))
        assert len(routes) == 0


class TestSDLQueryFields:
    def test_query_fields_have_get_method(self, tmp_path) -> None:
        """SDL Query fields -> RouteEntry with GET method."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "schema.graphql").write_text(SDL_QUERY_AND_MUTATION)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        query_routes = [
            r for r in routes if "GET" in r.http_methods
        ]
        assert len(query_routes) >= 1

        # Check route patterns
        patterns = [r.route_pattern for r in query_routes]
        assert any("Query.users" in p for p in patterns)


class TestSDLMutationFields:
    def test_mutation_fields_have_post_method(self, tmp_path) -> None:
        """SDL Mutation fields -> RouteEntry with POST method."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "schema.graphql").write_text(SDL_QUERY_AND_MUTATION)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        mutation_routes = [
            r for r in routes if "POST" in r.http_methods
        ]
        assert len(mutation_routes) >= 1

        patterns = [r.route_pattern for r in mutation_routes]
        assert any("Mutation.createUser" in p for p in patterns)


class TestCodeFirstResolvers:
    def test_typegraphql_decorators(self, tmp_path) -> None:
        """@Query and @Mutation decorators -> RouteEntry objects."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "user.resolver.ts").write_text(TYPEGRAPHQL_RESOLVER)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        assert len(routes) >= 2
        patterns = [r.route_pattern for r in routes]
        assert any("Query.users" in p for p in patterns)
        assert any("Mutation.createUser" in p for p in patterns)

    def test_pothos_t_field_pattern(self, tmp_path) -> None:
        """t.field('fieldName', ...) -> RouteEntry objects."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "schema.ts").write_text(POTHOS_RESOLVER)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        assert len(routes) >= 2
        patterns = [r.route_pattern for r in routes]
        assert any("greeting" in p for p in patterns)
        assert any("addItem" in p for p in patterns)

    def test_nexus_top_level_fields(self, tmp_path) -> None:
        """queryField('name', ...) and mutationField('name', ...) -> RouteEntry."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "user.resolver.ts").write_text(NEXUS_RESOLVER)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        assert len(routes) >= 2
        patterns = [r.route_pattern for r in routes]
        assert any("Query.listUsers" in p for p in patterns)
        assert any("Mutation.registerUser" in p for p in patterns)


class TestIntrospectionFieldsSkipped:
    def test_skips_introspection_fields(self, tmp_path) -> None:
        """__typename, __schema should not produce routes."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "schema.graphql").write_text(SDL_WITH_INTROSPECTION)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        introspection_routes = [
            r for r in routes
            if "__typename" in r.route_pattern or "__schema" in r.route_pattern
        ]
        assert len(introspection_routes) == 0

        # But users should still be present
        user_routes = [r for r in routes if "users" in r.route_pattern]
        assert len(user_routes) == 1


class TestAuthDetection:
    def test_detects_auth_in_resolver(self, tmp_path) -> None:
        """Resolver with @Authorized and ctx.user -> has_auth_check = True."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "protected.resolver.ts").write_text(RESOLVER_WITH_AUTH)

        mapper = GraphQLRouteMapper()
        routes = mapper.map_routes(str(tmp_path))

        assert len(routes) >= 1
        # Routes from code-first resolvers with auth should have has_auth_check = True
        auth_routes = [r for r in routes if r.has_auth_check is True]
        assert len(auth_routes) >= 1
