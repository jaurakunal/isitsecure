import { NextResponse } from "next/server"
import { writeFile, mkdir } from "fs/promises"
import path from "path"

// VULNERABILITY: No file extension validation, no content-type check
// Scanner: file_upload_scanner (#8)

export async function POST(request: Request) {
  const formData = await request.formData()
  const file = formData.get("file") as File

  if (!file) {
    return NextResponse.json({ error: "No file provided" }, { status: 400 })
  }

  // VULNERABILITY: Accepts any file extension (.html, .svg, .php, .exe)
  // No content-type validation
  // Uses original filename (path traversal risk)
  const filename = file.name
  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  const uploadDir = path.join(process.cwd(), "public", "uploads")
  await mkdir(uploadDir, { recursive: true })
  await writeFile(path.join(uploadDir, filename), buffer)

  return NextResponse.json({
    url: `/uploads/${filename}`,
    size: buffer.length,
  })
}
