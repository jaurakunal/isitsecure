# File Upload Scanner

**Type:** DAST | **Severity:** High | **Category:** Injection Risk

## What It Does

Tests file upload endpoints by attempting to upload files with dangerous extensions and path traversal filenames:

- **Dangerous extensions**: `.html`, `.svg`, `.php`, `.jsp`, `.exe`, `.sh`
- **Path traversal**: `../../../etc/passwd`, `..\\..\\windows\\system32`
- **Content-type mismatch**: sends executable content with image content-type

If the server accepts the upload and returns a URL, the file may be served directly — allowing XSS (via HTML/SVG), code execution (via PHP/JSP), or system file overwrites (via path traversal).

## Why It Matters

Unrestricted file uploads let attackers:

- **Execute code on your server** — uploading `.php`, `.jsp`, or `.sh` files that the server executes
- **Stored XSS** — uploading `.html` or `.svg` files with JavaScript that executes when viewed
- **Overwrite system files** — path traversal (`../../etc/cron.d/backdoor`) can write anywhere on the filesystem
- **Serve malware** — your domain becomes a malware distribution point

## Real-World Breaches

**ImageTragick (2016)** — CVE-2016-3714 in ImageMagick allowed remote code execution via crafted image files. Any service that accepted user-uploaded images and processed them with ImageMagick was vulnerable.

## How to Fix

```typescript
// GOOD: Whitelist allowed extensions and validate content
const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp"]
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"]

export async function POST(request: Request) {
  const file = formData.get("file") as File
  const ext = path.extname(file.name).toLowerCase()

  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return NextResponse.json({ error: "File type not allowed" }, { status: 400 })
  }

  if (!ALLOWED_TYPES.includes(file.type)) {
    return NextResponse.json({ error: "Invalid content type" }, { status: 400 })
  }

  // Generate a random filename (prevents path traversal)
  const safeFilename = `${crypto.randomUUID()}${ext}`
  // ... save with safeFilename
}
```
