# File Upload Scanner

**Type:** DAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Tests file upload endpoints (found by upload-like path indicators) by attempting to upload files with dangerous types and path traversal filenames, as a multipart `file` field:

- **Dangerous types**: only `.html` (`text/html`) and `.svg` (`image/svg+xml`), each with a small script payload. An accepted upload is reported High (confidence 0.85).
- **Path traversal**: filenames `../../../etc/passwd`, `..\\..\\..\\etc\\passwd` and `....//....//etc/passwd`, sent with `text/plain` content. The scanner stops at the first accepted name and reports Critical (confidence 0.90).

A bare 2xx is not acceptance. A probe counts as accepted only when the status is 2xx, the body is not a failure shape (JSON with `success`/`ok`/`uploaded` false, `status` of error/fail, a non-empty `error`/`errors`, or non-JSON text containing words such as invalid, forbidden or rejected), and there is evidence the file was stored: for the `.html`/`.svg` probes, a same-host URL from the response (a JSON value or the `Location` header) is fetched and serves the uploaded payload back, or that URL's path ends in the uploaded file's extension (storage evidence even if the GET does not return the payload verbatim, for example because the script executes), or the response references the stored file name; follow-up GETs skip URLs with a query string and paths containing logout, signout, delete, remove, destroy or reset; for the traversal probes, the response echoes the unsanitised traversal filename, so a server that stores only the basename is not reported. The finding evidence names which of these was observed. When a `.html`/`.svg` probe gets a 2xx, non-failure body but none of this storage evidence (for example the body is just `OK`), the same finding is still reported at a lower tier: Medium, confidence 0.4, with the evidence stating that evidence of storage was not found. Path traversal never uses this tier; it always needs the raw-name echo. The scanner does not delete the test files it uploads.

Not covered today: executable extensions such as `.php`, `.jsp`, `.exe` and `.sh`, and content-type mismatch tests (executable content sent with an image content-type).

If the server accepts an HTML or SVG upload and serves it back, the file may run script in the visitor's browser (stored XSS); an accepted traversal filename may allow writing outside the intended directory.

## Why It Matters

Unrestricted file uploads let attackers:

- **Execute code on your server** — uploading `.php`, `.jsp`, or `.sh` files that the server executes (a risk of unrestricted uploads in general; this scanner does not probe those extensions)
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
