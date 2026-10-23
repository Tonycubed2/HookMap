# HookMap

A standalone tool that scans a running Skyrim SE (1.5.97), AE (1.6.x) or VR (1.4.15) and shows which SKSE DLLs hook what, and where they collide: overwritten hooks, shared hooks, crash-handler stacking, version mismatches and overlay hooks. It produces a ranked HTML report, a JSON export, and can diff two scans.

HookMap only **reads** the game's memory. It is not an SKSE plugin and installs nothing into the game.

Download: Nexus Mods (link coming soon)

## Using it

1. Start Skyrim and load a save.
2. Run `HookMap.exe`. It asks whether to make the report shareable (removes your user name, PC name and folder paths).
3. The report opens in your browser. Start with **Conflicts, ranked**.

Compare two scans:

```
HookMap.exe --diff HookMap_old.json HookMap_new.json
```

Rebuild the HTML from a saved report:

```
HookMap.exe --render HookMap_old.json
```

Run `HookMap.exe --help` for all options.

### Danger levels

The top of the report rates four process-wide risks green / yellow / red. The overall rating is the worst of the four, not an average.

- **Hook collisions**: red for any clobbered or high conflict, yellow for medium.
- **Near memory (trampolines)**: free address space within 2 GB of the game exe, where every hook trampoline has to live. Rated on the largest free block, because fragmentation is what makes a plugin fail to get its trampoline.
- **TLS slots**: `TlsAlloc` slots used out of 1088, read exactly from the game process. Shared by the game, Windows, overlays and every DLL.
- **Static CRT (FLS slots)**: DLLs built with the static CRT each use about 2 Fiber Local Storage slots. The limit is 4080 on Windows 10 1903 and later (128 before), so on current Windows this is informational.

### allowlist.txt

DLLs that patch heavily by design (SKSE, Engine Fixes, overlays…). Findings that only involve allowlisted DLLs are marked *expected* and ranked lower. One DLL name per line, wildcards allowed, optional note after `|`.

## How it works

- Compares each module's code (and the game's vtables) in memory against the file on disk, with relocations applied.
- The Steam SkyrimSE.exe / SkyrimVR.exe is DRM-encrypted on disk; HookMap decrypts it in memory to get a clean copy (nothing is written). If that fails it falls back to finding calls/jumps that lead into DLLs, or you can pass `--clean-exe` with an unencrypted copy.
- Follows each redirected call/jump/pointer through trampolines and thunks to the DLL that owns it.
- Byte patches are attributed by finding the patch bytes in a DLL's data.
- Chain analysis: checks whether a hook's owner calls the original, or chains to another hook through its trampoline.
- An "overwrote" or "overlap" verdict needs site-specific evidence: the earlier hook's trampoline, holding that site's original bytes and jumping back to it, stored by that DLL but no longer reached. A DLL that merely holds the original function's address is listed as a reference, never as a victim.
- Reads each SKSE plugin's version data, the PE headers (Rich header, imports, debug info) and `skse64.log`.
- Names locations via Address Library IDs (SE `.bin`, AE `.bin` or VR `.csv`, matching the running game) and, if `CommonLibSSEPath_NG` is set, names harvested from CommonLibSSE-NG sources.

## Building

Requirements: Visual Studio 2022 (C++ workload), CMake 3.21+, Ninja. No other dependencies.

From a Developer Command Prompt:

```
cmake --preset release
```
```
cmake --build --preset release
```

Output: `build\release\HookMap.exe` and `allowlist.txt`.

## License

MIT — see [LICENSE](LICENSE).
