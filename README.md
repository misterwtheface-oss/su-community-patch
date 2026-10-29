# Siralim Ultimate — Unofficial Community Patch (SUUCP)

Fixes bugs in Siralim Ultimate so that effects work the way their in-game text says. Unofficial and fan-made; not
affiliated with Thylacine Studios. **Players:** see `publish/README.md` (install guide) and the release's
`PATCH_NOTES.pdf`. This file is for people working on the patch.

**Status:** version in `loader/VERSION` (0.9.1-beta), for Siralim Ultimate 2.0.38 (Steam build 20548371). Live fixes
and open items: `STATUS.md` (generated). In-game checks still wanted: `IN_GAME_TESTS.md` (generated).

## How it works
- **No game files are changed or shipped.** The patch is a small loader, `version.dll`, placed next to
  `SiralimUltimate.exe` (Windows loads it in place of its own `version.dll` and it forwards those functions). At start:
  1. it checks that the exe is the exact build the patch was made for (PE timestamp and image size, plus each edit's
     expected bytes) and does nothing on any other build;
  2. it applies each enabled fix in memory: most are a few bytes; some redirect one game call to a small corrected
     function in the loader (the "hook" pattern);
  3. it writes in-game text corrections to the game's own `localization_override` folder, built from the player's
     installed text (only the English line changes; a line the developer has since changed is skipped);
  4. it logs what it applied to `suucp.log` (the previous session is kept as `suucp.prev.log`); a fatal fault is
     recorded with its location.
- Every fix has an on/off switch in `suucp.ini`; `[groups] heavy` switches the larger rebuilds of core battle code
  together.
- Code the patch adds lives in zero-filled space the game image never uses: the tail of `.text`, the tail of `.data`
  (hook pointers and state), and the slack past the end of `.rdata` and `_RDATA` (made execute-read by the loader).

## Rules for this repo
- Ship only our own code, byte offsets and diffs. **Never** include decompiled game code, the exe, `data.win`, game
  CSVs or long game-text quotes. Records cite addresses and GML line numbers, not code listings.
- **The in-game text is the contract** (`RULINGS.md`): a fix makes an effect do what its text says.
- Only bugs and answered errata claims are recorded here. Behaviour the game text never describes is not listed.
- A new game version breaks the address table: the loader refuses to run on an unknown build rather than guess.

## Layout
- `bugs/` — **the bug registry, source of truth** (one JSON per bug, permanent `SU-` ids; schema in `bugs/README.md`).
  Text corrections are the records' `text_fix` entries; patch-notes text is their `release_notes`.
- `loader/` — the version.dll source (`suucp.c`, `text.c`, `hooks*.c`), `patches.json` (one patch per bug, same id;
  each edit with its expected bytes and a build-independent fingerprint), `gen_patches.py` (generated headers and
  `suucp.ini`), `build.cmd`, offline tests in `loader/test/`.
- `research/` — the hook batch builders (`build_hooks_*.py`), which verify every byte, call target and assumption
  against the exe, and their generated patch lists (`hooks_*.json`).
- `tools/` — `registry.py` (validate; STATUS.md, IN_GAME_TESTS.md), `anchor.py` (fingerprints), `verify_patches.py`
  (disassemble every patched site), `skip_audit.py` (patches that jump over game code must not skip state the later
  code relies on), `port_check.py` (check a game build), `gmlsite.py` (find code by GML line), `public_check.py`,
  `build_patch_notes.py` (PATCH_NOTES.pdf), `export_public.py` (release bundle).
- `publish/README.md` — the player README shipped with releases.

## Workflow
1. **New finding:** add a `bugs/SU-xxxx.json` record (next id from `bugs/.next_id`) for every bug and every errata
   claim we answer (fixed, or not a bug with the reason).
2. **Fix:** a builder (or a hand edit) adds the patch to `loader/patches.json` with `"bug": "SU-xxxx"`; then run
   `tools/anchor.py`, `loader/build.cmd`, `tools/verify_patches.py`, `tools/skip_audit.py` and `tools/port_check.py`
   (self-test must be all PRESENT); test in game; set the record to `patched` with its `release_notes`.
3. **Text:** add a `text_fix` entry to the record: `file`, `key`, `en_proposed`, `en_current_sha256` (SHA-256 of the
   installed English it was written against), and for long texts `en_find` (only that fragment is replaced) or
   `new_row` / `copy_other_languages_from` for a missing row. `loader/test/text_gen_test.c` checks them offline.
4. **New game build:** `tools/port_check.py <new exe> --record <build>` records, per bug, whether the code is still
   there (re-port) or changed (possibly fixed upstream: verify in game). Game ids are assumed stable across builds.
5. Before a commit, `tools/registry.py --check` and `tools/public_check.py` must pass (the pre-commit hook runs both).

## Releasing
1. Set `loader/VERSION`. `python tools/export_public.py` builds `dist/public/`: the player README, `PATCH_NOTES.pdf`
   (from the records' `release_notes`), `release/` (version.dll + suucp.ini, freshly built) and `source/` (loader
   sources with generated headers and a standalone build.cmd), and runs the public-safety check over it.
2. Attach `dist/public/` (zipped) to a GitHub Release.
