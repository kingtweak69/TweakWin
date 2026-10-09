# Packaging

TweakWin will ship as a TweakPkg `.tweak` once that format exists. The
`.tweak` format belongs to TweakPkg / TweakOS core and is **not** defined
here. M2 does not invent a private TweakWin-only package format.

What this project provides for the packager:

- `make install DESTDIR=... PREFIX=/usr` installs `/usr/bin/tweakwin` only
- version string is `include/tweakwin/version.h` (`TWEAKWIN_VERSION_STRING`,
  currently `0.3.0-m3`)
- no runtime data files (API modules are linked into the binary)
- per-user state lives under `${XDG_DATA_HOME:-~/.local/share}/tweakwin/`;
  nothing is written there by M0, M1, or M2
- later milestones add `/usr/lib/tweakwin/{runtime,dlls,loader,helpers}/`
  and `/usr/share/tweakwin/`

Do not package:

- `build/`
- ASan / fuzz binaries
- generated fixtures
- Git metadata

`make installcheck` asserts the DESTDIR tree contains exactly one file:
`usr/bin/tweakwin`.

When TweakPkg's canonical `.tweak` format lands, add a recipe producing
`tweakwin-0.3.0-m3.tweak` (or whatever name TweakPkg requires). That file
is not produced by this tree.

Build inputs: a C11 compiler, make, and python3 (tests only). No Wine
packages, no extra APT sources.
