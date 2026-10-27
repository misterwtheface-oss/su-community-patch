# Bug registry

One JSON file per bug: `bugs/SU-0001.json` … The registry is the source of truth. `STATUS.md` is generated from it
(`python tools/registry.py`). Never reuse an id; a bug that turns out not to be one keeps its id with status `wontfix`.

## Why it survives a game update
Records are keyed by things a new build keeps: the effect's game id (trait runtime id / perk key / relic + rank / spell id),
its text key, and the GML function name. Addresses live only in `loader/patches.json`, where every edit also carries a
masked fingerprint (`tools/anchor.py`: a ≤16-byte seed plus a hash, so no run of game code is stored). `tools/port_check.py <new exe> --record <build>` finds each fix in the new
build and writes the result into the bug's `builds` map: still present, possibly fixed upstream, or changed.

## Fields
| Field | Meaning |
|---|---|
| `id` | `SU-0001`, permanent |
| `aliases` | older ids (triage `A01`, patch `C03`, community row `B6#37`, handoff `H02`) |
| `title` | one line, plain language |
| `subjects` | what it affects: `{kind: trait/perk/relic/spell/card/condition/system, name, runtime_id, key, rank, text_key}` |
| `problem` | what the game does vs what its text says |
| `category` | `bug` (code contradicts text or itself) · `not-a-bug` (an errata claim answered: works as its text says). Behaviour the text never describes is tracked outside this repo |
| `confidence` | `in-game-confirmed` · `code-certain` · `high` · `medium` · `unverified` |
| `decision` | `fix-code` · `fix-text` · `test-first` · `leave` (with `reason`) |
| `status` | `patched` · `planned` (small edit known) · `needs-hook` · `test-first` · `open` · `wontfix` |
| `patch` | patch id in `loader/patches.json` (= the bug id) or null |
| `text_overrides` | legacy field, always empty (text corrections are `text_fix`) |
| `app_note` | `{status: shipped/requested/none/not-needed, ref}`: the build calculator's clarify note for the **unpatched** game |
| `sources` | where it came from: `own:EO§5`, `community:B6#37`, `handoff:B`, `bug_report:x.md` |
| `builds` | per game build: `{present, verified_in_game, port}` |
| `reason` | why a record is `leave` / `wontfix` |
| `text_fix` | in-game text corrections: `{file, key, en_proposed, en_current_sha256, en_find?, new_row?, copy_other_languages_from?}` (shipped through `localization_override`; `en_find` replaces only that fragment) |
| `release_notes` | patch-notes text for a patched bug: `{section, effect, intended, actual, fix, impact, flags}` (`tools/build_patch_notes.py`) |
| `notes` | research: short text quote, evidence (function, GML line, address), fix sketch, in-game reports |

## Rules
- Every patch in `loader/patches.json` names its bug (`bug` field); every `patched` bug names its patch.
- Every `bug` record gets a note in the companion build calculator, which describes the unpatched game (`app_note`;
  the maintainer's tooling tracks the missing ones).
