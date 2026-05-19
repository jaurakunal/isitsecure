import { NextResponse } from "next/server"

// VULNERABILITY: GraphQL introspection enabled, no depth limit
// Scanner: graphql_scanner (#6)

const SCHEMA = `
  type Query {
    tasks(userId: ID): [Task]
    users: [User]
    task(id: ID!): Task
  }

  type Mutation {
    createTask(title: String!, userId: ID!): Task
    deleteTask(id: ID!): Boolean
  }

  type Task {
    id: ID!
    title: String
    description: String
    user: User
  }

  type User {
    id: ID!
    email: String
    tasks: [Task]
    role: String
  }
`

export async function POST(request: Request) {
  const { query: gqlQuery, variables } = await request.json()

  // VULNERABILITY: Introspection query fully allowed
  if (gqlQuery?.includes("__schema") || gqlQuery?.includes("__type")) {
    return NextResponse.json({
      data: {
        __schema: {
          types: [
            { name: "Query", fields: ["tasks", "users", "task"] },
            { name: "Mutation", fields: ["createTask", "deleteTask"] },
            { name: "Task", fields: ["id", "title", "description", "user"] },
            { name: "User", fields: ["id", "email", "tasks", "role"] },
          ],
        },
      },
    })
  }

  // VULNERABILITY: No query depth limit — deeply nested queries allowed
  // No query complexity analysis
  return NextResponse.json({
    data: { message: "GraphQL endpoint active" },
  })
}
