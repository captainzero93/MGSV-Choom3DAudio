# Validation performed for this port

- Passed: configuration parser compiled with g++ C++17, `-Wall -Wextra -Werror`.
- Passed: supplied settings retain emphasis 0.65 and all thirteen audio/guard
  values; comments, commas, false switches and numeric bounds parse correctly.
- Passed: malformed booleans, empty numbers, NaN, out-of-range values and trailing
  numeric junk retain the prior value and increment the invalid-setting count.
- Passed: exact text comparison of the complete audio implementation before the
  original DrawAudioStatus function, allowing only replacement of the ImGui
  include and insertion of the configurable log-path variable.
- Passed: both HRIR headers are byte-identical to the uploaded v0.73 source.
- Passed: both extracted guard namespace bodies match the uploaded IHHook.cpp.
- Passed: MSBuild project XML parses; all seven compilation-unit paths exist.
- Reviewed: the port's audio-source diff contains only status UI, logging,
  integration marker, and ownership-comment changes.

Not performed: Windows/MSVC compilation, DLL loading into IH, rendering the
Windows status panel, or game/audio runtime validation. This package contains
source, not a prebuilt or runtime-certified DLL.

The supplied test can be rerun from the package directory on Linux with:

```sh
g++ -std=c++17 -Wall -Wextra -Werror -Isrc tests/config_test.cpp -o /tmp/choom_config_test
/tmp/choom_config_test dist/plugins/choomaudio.lua
```

## Build-log follow-up: v145 fmt compatibility

The supplied Windows build reached compilation and failed in fmt's
`stdext::checked_array_iterator` declarations. Replaced only that helper branch
with the portable implementation already present in the same header.

Passed: `tests/fmt_compat_test.cpp` compiled and ran using g++ C++17 with
`_SECURE_SCL=1`, exercising string back-insertion, numeric formatting, and a
4096-character memory buffer. This macro previously selected the failing branch.
No audio or plugin implementation changes in this follow-up. Full Windows
compilation still requires rerunning BUILD.cmd on the user's machine.
