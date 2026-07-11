# Renders docs/banner.gif — the animated welcome banner (the pink→purple wave +
# load shimmer). Fast and reliable: no scan, no network, no language servers.
# Great as the README hero on its own, or paired with docs/demo.svg (findings).
#
#   vhs demo/banner.tape        # -> docs/banner.gif

Output docs/banner.gif

Set Shell "bash"
Set FontSize 16
Set Width 1180
Set Height 640
Set Padding 26
Set Theme "Catppuccin Mocha"
Set Framerate 24
Set TypingSpeed 60ms

Type "isitsecure version"
Sleep 600ms
Enter
Sleep 4500ms
