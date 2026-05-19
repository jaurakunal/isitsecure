import { NextResponse } from "next/server"
import { getById, updateRow, deleteRow } from "@/lib/db"

// VULNERABILITY: No auth, no ownership check — classic IDOR
// Scanner: idor_scanner (#16), route_auth_analyzer (#26)
// Guided DAST: auth_bypass (#44), idor_targeted (#45)
// Cross-reference: DAST IDOR + SAST missing auth = confirmed (#43)

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const task = await getById("tasks", params.id)

  if (!task || task.length === 0) {
    return NextResponse.json({ error: "Task not found" }, { status: 404 })
  }

  return NextResponse.json(task[0])
}

export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  const body = await request.json()

  // No ownership verification — any user can update any task
  const updated = await updateRow("tasks", params.id, body)
  return NextResponse.json(updated[0])
}

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  // No ownership verification — any user can delete any task
  await deleteRow("tasks", params.id)
  return NextResponse.json({ deleted: true })
}
