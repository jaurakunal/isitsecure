# VHS tape for the README demo GIF.
#
# Renders the whole thing deterministically — no manual screen recording:
#   1. Install VHS:  brew install vhs          (https://github.com/charmbracelet/vhs)
#   2. `isitsecure` must be on your PATH (or uncomment the venv block below).
#   3. From the REPO ROOT:  vhs demo/scan.tape   ->  writes docs/demo.gif
#   4. git add docs/demo.gif && commit.
#
# It shows the animated welcome banner, the live narrated scan (each scanner
# reporting as it runs), and the graded findings — a fast code-only scan of the
# bundled test app.
#
# NOTE: the scan's tail (OSV dependency lookup over the network + git-history
# secret scan + LSP auth tracing) can run slow in some environments and blow the
# Wait timeout below. If that happens, either bump the timeout, or just render
# demo/banner.tape (the animated banner — no scan) and keep docs/demo.svg for
# the findings. First, sanity-check the scan is fast on your machine:
#   time isitsecure scan --repo ./test-app --mode code-only --depth quick --llm none

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1320
Set Height 960
Set Padding 22
Set Theme "Catppuccin Mocha"
Set Framerate 24
Set TypingSpeed 55ms

# If you installed via install.sh (venv), uncomment these to put isitsecure on PATH:
# Hide
# Type "source .venv/bin/activate"  Enter
# Sleep 500ms
# Show

Type "isitsecure scan --repo ./test-app --mode code-only --depth quick --llm none"
Sleep 700ms
Enter

# Wait for the scan to finish — the CLI prints "✓ Scan complete" at the end.
Wait+Screen@120s /Scan complete/
Sleep 3s
