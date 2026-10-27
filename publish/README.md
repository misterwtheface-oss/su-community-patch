# Siralim Ultimate — Unofficial Community Patch (SUUCP)

Fixes over 180 bugs in **Siralim Ultimate** so that traits, perks, relics, spells, cards and combat rules work the
way their in-game descriptions say they do. Some fixes make an effect stronger than it was while bugged, some weaker;
every change is listed in **[PATCH_NOTES.pdf](PATCH_NOTES.pdf)**.

> Unofficial and fan-made. Not affiliated with or endorsed by Thylacine Studios. Siralim Ultimate is © Thylacine Studios.
> This project contains no game files: you need your own copy of the game.

## Requirements
- **Siralim Ultimate 2.0.38** (Steam, Windows). The patch checks the game version when the game starts; on any other
  version it does nothing and the game runs unpatched.

## Install
1. In Steam, right-click **Siralim Ultimate → Manage → Browse local files**. This opens the game folder (the one with
   `SiralimUltimate.exe`).
2. Copy **`version.dll`** and **`suucp.ini`** from the `release` folder into that game folder.
3. Start the game as usual.

To check it's working, open **`suucp.log`** in the game folder after starting the game. The last lines should read
something like `176 of 176 enabled fixes applied` (the numbers depend on your settings).

## Uninstall
Delete these from the game folder: `version.dll`, `suucp.ini`, `suucp.log`, `suucp.prev.log`, and the `localization_override` folder.
Nothing else is changed: the patch never modifies the game's own files (it applies its fixes in memory when the game
starts), so Steam's "Verify integrity of game files" is unaffected and your saves keep working with or without it.

## Settings (`suucp.ini`)
Open `suucp.ini` in any text editor.
- **`[fixes]`** — every fix has its own switch, named after its id in the patch notes (`SU-0001=1` on, `=0` off).
- **`[groups]`** — `heavy=1` / `heavy=0` turns the larger rebuilds of core battle code on or off together (marked
  *heavy* in the patch notes). A fix runs only if both its own switch and its group are on.
- **`[text]`** — the few in-game text corrections. `all=0` turns them all off; `SU-xxxx=0` turns off one.

Changes take effect the next time the game starts.

## Game updates
The patch is made for one game version. When Siralim Ultimate updates, the patch switches itself off automatically
(`suucp.log` says so) until a matching update of the patch is released.

## Problems
- If the game crashes or misbehaves, open `suucp.log`: a crash is recorded there with its location. Each start moves
  the previous log to `suucp.prev.log`, so after relaunching, the crash is in that file. Try `heavy=0`,
  or switch off the fix you suspect.
- Report issues on this repository's issue tracker, with your `suucp.log` and what happened.

## How it works
`version.dll` is a small loader that Windows loads next to the game. It checks the game version, applies each enabled
fix in memory (most are changes of a few bytes; some route one game call through a small corrected function), passes
everything else through to Windows' own `version.dll`, and writes `suucp.log`. Text corrections are written to the
game's own `localization_override` folder, built from your installed game text, changing only the English line.

## Building from source
The `source` folder has the complete loader source. With **Visual Studio Build Tools** (MSVC, x64) installed, run
`source\build.cmd`; it produces `version.dll`.
