# Demo assets

The README's demo GIF (`docs/demo.gif`) is generated from a script, so it's
reproducible and easy to re-render when the CLI changes — no manual screen
recording.

## Render it (recommended: VHS)

[VHS](https://github.com/charmbracelet/vhs) turns a `.tape` script into a GIF by
driving a real terminal headlessly (colors, the animated banner, and the live
narration all render).

```bash
brew install vhs          # macOS  (see the VHS repo for Linux)

# from the repository root, with `isitsecure` on your PATH:
vhs demo/scan.tape        # writes docs/demo.gif

git add docs/demo.gif && git commit -m "docs: add demo GIF"
```

Prerequisites: run from the repo root (so `./test-app` resolves) and have
`isitsecure` on your PATH. If you installed via `install.sh`, uncomment the venv
block at the top of `scan.tape`.

### Tuning

Everything is in `scan.tape`:

- `Set Theme` — try `Dracula`, `Tokyo Night`, `Nord` (see `vhs themes`).
- `Set Width` / `Set Height` — output dimensions.
- `Set TypingSpeed` / `Set PlaybackSpeed` — pacing.
- Want a short hero clip of just the animated banner? A one-liner tape:
  `Output docs/banner.gif` + `Type "isitsecure version"` + `Enter` + `Sleep 4s`.

## Manual alternative (asciinema)

If you'd rather record by hand:

```bash
brew install asciinema agg
asciinema rec demo.cast -c "isitsecure scan --repo ./test-app --mode code-only --depth quick --llm none"
agg demo.cast docs/demo.gif        # convert the recording to a GIF
```

Or just screen-record the terminal with Kap / QuickTime and export a GIF.
