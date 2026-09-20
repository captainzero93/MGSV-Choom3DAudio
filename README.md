# Choom3DAudioMGSV

Binaural headphone audio for Metal Gear Solid V: The Phantom Pain.

**Version:** v0.74  
**Game:** `mgsvtpp.exe` 1.0.15.4, PE timestamp `0x6A4CB898`  
**Loading:** Infinite Heaven's Lua module system

I made this to give MGSV's sounds more direction over headphones, including front, back and height. It uses positions from the game's audio engine to render supported sounds through measured head-related impulse responses, or HRIRs. These are the time-domain filters used to produce HRTF audio.

The current plugin has no GUI or keybinds. Everything is configured in `plugins/choomaudio.lua`, with a restart after changes. This version has been tested in game by multiple people.

Use headphones. The output is intended to send a separate signal to each ear, so ordinary speakers will not reproduce the same effect. How convincing the positioning sounds will also depend on your headphones and how well the measured head matches your own hearing.

## Installation

You need Infinite Heaven. Its Lua module system loads this standalone audio plugin through `ChoomAudio_Core.lua`.

Close the game and copy both folders from `dist` into the folder containing `mgsvtpp.exe`:

| File | Location in the game folder |
| --- | --- |
| Audio plugin | `plugins/choomaudio.dll` |
| Settings | `plugins/choomaudio.lua` |
| IH loader module | `mod/modules/ChoomAudio_Core.lua` |

Include the Lua loader. Putting the DLL in `plugins` alone is not enough for this installation method. The module uses `package.loadlib` to load `choomaudio.dll` and call its `luaopen_choomaudio` entry. Native initialization then runs on a worker thread.

You can also install a completed build with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install.ps1 -GameDirectory "F:\SteamLibrary\steamapps\common\MGS_TPP"
```

The installer preserves an existing plugin config.


## Settings

Edit `plugins/choomaudio.lua` and restart the game. The file looks like Lua, but the native plugin reads literal settings from it rather than executing it. The separate loader module is executable Lua.

| Setting | Shipped value | What it does |
| --- | --- | --- |
| `enableAudioBridge` | `true` | Enables installation of the audio hooks. Set to `false` to compare with original audio after restarting. |
| `audioSpatialEmphasis` | `0.65` | Blends between the base and cue-emphasised HRIR tables. Accepts `0` to `1`. |
| `audioPeakGuard` | `true` | Reduces excessive peaks in the processed world-sound path. |
| `audioBedCentreDirect` | `false` | When enabled, sends a bed's centre channel through the game's downmix gains with a matching delay instead of an HRTF. Useful if centre dialogue sounds too coloured. |
| `audioDebugLog` | `false` | Enables extended audio diagnostics when set to `true`. Startup logs and warnings still exist when it is `false`. |
| `enableNullGuard` | `true` | Skips a known game call when its object argument is null. |
| `enableViewGuard` | `true` | Skips a known view update when its render context is missing. |

`audioNativeHooks`, `audioListenerHook`, `audioMixerHook` and `audioFoxHooks` are troubleshooting switches. Leave all four enabled for normal use. Disabling an individual group can remove coverage or prevent processing.

I treat `0.5` as the baseline emphasis setting, but I personally prefer `0.65`, so that is what the mod ships with. Both the packaged config and the built-in default use `0.65`. Set it to `0.5` if you prefer a subtler effect. This is a preference setting, not a calibration value: `0` selects the base filters without the extra cue emphasis.

If no plugin config is present, the code falls back to the root `ihhook_config.lua`, then built-in defaults. An explicit value in either config takes priority over the default.

There are no F-key controls or status panel in v0.74. Old `audioOverlay` and `audioHotkeys` settings are ignored.

## How I got here

This started with runtime probes and Ghidra exports to work out where the game's audio was actually going. Early tests worked backwards from the sink and buffer-submission paths. Being able to mute a generator while other sounds continued was useful evidence that we had isolated a real sound path, rather than just changing the master output.

The next problem was coverage. A generator working did not mean gunfire, vehicles and every other sound used the same path. Logging activity across firefights, helicopter rides and Mother Base helped separate the paths we could identify from the ones we were still missing.

The useful discovery was the common native position-update path. Instead of maintaining a list of sound IDs, the mod observes audio-object construction and position updates, then connects those objects to the playback contexts used by the mixer. The Fox sound-source event and transform hooks provide another route for matching sounds to positions.

There were a few important details along the way:

- The registered-source table address was a pointer slot, not the table itself. Reading it as the table gave the wrong layout.
- An event or playing ID alone was not enough to identify every source. Native object references and playback context also mattered.
- Audio objects can be reused. Position tracking needs identity and lifetime checks so a new sound does not inherit an old object's location.
- Sharing convolution history between unrelated voices caused resets and discontinuities. The renderer now hashes both the render node and destination and probes several history slots before replacing one.
- Large sounds could gain enough level through the HRTF to expose crackle further down the mix. That led to the peak guard rather than assuming the original gain chain would handle everything.

This avoids a per-sound mapping list. It does not mean every sound in the game has been individually verified, or that every possible playback path is supported.

## Audio processing

The main interception point is the Wwise source-to-destination mixer, before the supported sound has been collapsed into the final stereo output. The mod uses the captured source position and listener transform to calculate a camera-relative direction, renders left and right ear signals, then passes them back through the original mixing function with adjusted coefficients.

This retains the game's playback and mixing path rather than rebuilding its audio system. It also uses the game's mix gains and fades. I would not describe all occlusion, ducking or level processing as happening after the mod, because those can occur at different points in the engine.

Positioned mono, stereo and quad layouts have supported paths. Processing depends on valid identity, position, buffer layout and routing information. Unsupported or unresolved world sounds normally fall back to the original mixer.

The code does not identify sounds by categories such as music, radio or UI and then explicitly exempt them. Unmatched sounds generally stay on the original path, but supported multichannel beds have their own processing path. That means content inside a bed can be affected even without a separate world position.

### Filters and direction

The main dataset is the Neumann KU 100 compilation attributed to Benjamin Bernschütz and TH Köln in `src/MGSV_HRIR_KU100.h`. The shipped table is derived from the 16,020-direction full-sphere dataset:

- 820 directions across 18 elevation rings.
- Elevation from about -80.44 to +88.46 degrees.
- 90 directions around the horizon, or 4-degree spacing, with fewer points toward the poles.
- 128 samples per ear at 48 kHz, with a tapered tail.

The renderer interpolates between neighbouring azimuths in two neighbouring elevation rings. It also crossfades filters when direction changes. Interpolation smooths movement between measurements; it is not a guarantee of a particular localisation accuracy.

The filters contain relative timing, level and spectral cues between the ears. Keeping their relative timing matters. The 128-sample filter length is about 2.67 ms at 48 kHz, but that is the filter duration, not a measurement of the mod's total latency or preservation of the original recording's full propagation delay.

The header documents equalisation based on the horizontal ring, with a smoothed response and bounded correction. It is intended to reduce coloration. This is not a full-sphere, energy-weighted diffuse-field average, and I am not claiming a measured flat response for the finished game output.

### Emphasis and source width

`audioSpatialEmphasis` blends the base table with a precomputed cue-emphasised table. `0` selects the base processed KU 100 filters and `1` selects the emphasised version. It is not a volume control or a direct multiplier of interaural level difference.

The table's generation notes describe expanding deviation from the average by 1.5 between 300 Hz and 16 kHz, with timing retained. The exposed setting itself still runs from `0` to `1`.

Eligible stereo emitters can be rendered as two directions around the source instead of folding straight to a point. Their angular half-width is calculated as:

```text
min(40 degrees, atan2(1.5 metres, distance))
```

The implementation uses this wider treatment when the spread reaches 2 degrees. It is a width heuristic, not a measurement of an object's physical size.

### Multichannel beds and dialogue

Supported surround beds, including 5.1 and 7.1 layouts, use virtual speakers. Their directions come from the channel layout, not reconstructed positions for individual sounds inside the recording.

| Channel | Virtual direction |
| --- | --- |
| Front left and right | -30 and +30 degrees |
| Centre | 0 degrees |
| Rear pair with side channels present | -150 and +150 degrees |
| Side pair with rear channels present | -90 and +90 degrees |
| A surround pair without the other pair | -110 and +110 degrees |
| LFE | Original downmix gains, without an HRTF |

Beds use the base filters with cue emphasis disabled. `audioBedCentreDirect=true` provides the alternative centre-channel path described above. Bed rendering also includes level matching and peak control, so channel levels are not simply passed through without adjustment.

### Levels and processing cost

World sounds have a per-voice peak guard that compares the processed result with an estimate of the game's original stereo peak. It uses bounded attenuation and a gradual release. This helps control loud effects, but it is not a guarantee that the final combined mix can never clip. The bed path has separate peak control.

The renderer uses direct convolution. One mono source rendered to two ears with 128 taps at 48 kHz accounts for roughly 12.3 million multiply-accumulates per second before additional work. Stereo spread, multiple bed channels and filter transitions add cost. This is an operation count, not a CPU benchmark or a promise of negligible overhead on every machine.

## Engine integration

These are reverse-engineered roles for the supported executable, not names from an official engine SDK. Addresses below use image base `0x140000000`; the plugin resolves them relative to the loaded executable.

| Address | Observed role |
| --- | --- |
| `0x140388590` | Native audio-object construction and identity tracking |
| `0x140388E50` | Native object position consumed by the audio path |
| `0x14034D220` | Position dispatch |
| `0x141D728F0` | Fox sound-source event posting |
| `0x141D72C40` | Fox sound-source transform synchronisation |
| `0x140437B60` | Camera-to-audio listener bridge |
| `0x14033C050` | Wwise event-post gateway |
| `0x14034CA50` | Wwise game-object lookup |
| `0x140342060` | Playing-event association |
| `0x140352330` | Active voice-render context |
| `0x1403A77B0` | Source-to-destination matrix mixing |

The final default path does not install the old sink-pump, alternate-mix or low-level-mix diagnostic hooks. Those experiments helped establish the pipeline, but they are not all part of the active renderer.

The plugin checks the executable name, architecture and expected timestamp. Audio hook targets are checked against the executable's address range, and MinHook reports installation failures. The two additional crash guards also check specific instruction bytes or a call target.

There is **not** a full executable SHA-256 verification at runtime, and the general audio-hook installer does **not** fingerprint every hook site. An expected hash printed in the log is a reference value. The SHA-256 printed by the build script is for the compiled plugin DLL.

Guarded memory reads and finite-value checks reduce some failure cases. They do not make native hooks crash-proof, and a successful install summary does not prove that every hook or sound path is working. Check individual results when diagnosing a problem.

## Logs and testing

In this source version, `audioDebugLog=false` means reduced logging, not no logging:

- `plugins/choomaudio.log` records startup, configuration and the installation result.
- `plugins/choomaudio_audio.log` records hook installation and retains warning/error reporting. Set `audioDebugLog=true` for extended diagnostics.

The included Lua loader does not create a separate `choomaudio_loader.log`. If it fails, look for `ChoomAudio_Core` in IH's logs. No native logs can mean the DLL was not loaded, but file permissions or an early initialization failure are also possible.

For a listening check, return to a stationary sound such as a generator and move or rotate the camera around it. To compare against the original mix, change `enableAudioBridge`, restart, and return to the same scene. There is no live toggle in this build.

The KU 100 is a measured dummy head, not your own head and ears. Front/back ambiguity and different perceptions of elevation are possible. Camera movement can help make the direction clearer. The finite history tables, supported layouts and available source matches also place limits on coverage.

## Building from source

Install Visual Studio with **Desktop development with C++** and a Windows SDK, then run `BUILD.cmd` from the extracted project folder.

The script builds Release x64, checks the output's PE architecture and expected plugin markers, stages the three installation files, and creates `ChoomAudio_plugin.zip`.

MinHook, spdlog and fmt are bundled. The DLL uses a static C runtime and its own MinHook instance. It stays loaded until the game exits; live unloading is not supported.

The source still contains earlier version labels and diagnostic comments, including a `073_R1` plugin marker. These are inherited from the port and are also used by the current build script. They do not mean this v0.74 package has the old GUI enabled.

The parser test is in `tests/config_test.cpp`. `VALIDATION.md` contains historical porting checks, not a fresh audit of this release.

## Credits and source data

- Benjamin Bernschütz and TH Köln for the [Neumann KU 100 HRIR compilation](https://www.audiogroup.web.th-koeln.de/ku100hrir.html). The accompanying paper is [A Spherical Far Field HRIR/HRTF Compilation of the Neumann KU 100](https://www.audiogroup.web.th-koeln.de/FILES/AIA-DAGA2013_HRIRs.pdf), AIA/DAGA 2013. The dataset attribution and processing notes are retained in [MGSV_HRIR_KU100.h](src/MGSV_HRIR_KU100.h). The derived table is labelled [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/).
- Gardner and Martin's MIT KEMAR measurements, credited in [MIT_KEMAR_HRIR_48K_128_360.h](src/MIT_KEMAR_HRIR_48K_128_360.h). This earlier horizontal dataset remains in the source; KU 100 is the default 3D set.
- Infinite Heaven for loading the plugin. The original implementation was integrated into IHHook; its attribution is retained in `LICENSE-IHHook.txt`.
- [Yazed0071/MGSV_HookSample](https://github.com/Yazed0071/MGSV_HookSample) for the standalone plugin-loading example.
- MinHook, spdlog and fmt. Their notices are retained with the bundled source.

Keep the dataset attribution and third-party notices when redistributing the source or a build. The HRIR data has its own licence; the IHHook MIT notice does not replace it.
