"""Build SU-0080 (Primordial Curse / Forsaken Wonder) as a hook, replacing the partial byte fix.

Text: "Debuffs inflicted by your creatures' Relics last forever." / "Buffs granted by your creatures' Relics last forever."
The game's own permanence check in scr_CritAddCondition (L80-L87) tests the *holder*; the function never gets the
inflicter. This build:
  1. the three buff/debuff event sites in bc_ExecuteEvents (L1549, L1613, L1752) call a cave trampoline instead of
     scr_CritAddCondition. It jumps through a pointer slot that the loader fills with hook_su0080_add_condition
     (loader/hooks.c): the C hook reads the event's `source` (the game's own var get), sets INFLICTER and FLAG, calls
     scr_CritAddCondition and restores them. The logic is in C so it has compiler unwind info and is independent of
     the load address (the game uses ASLR: no absolute address may appear in cave code);
  2. at the start of the Curse block (0x142016c40) a detour swaps the holder slot [rsp+0x78] with INFLICTER while
     FLAG is set and the inflicter is a real creature (instance id > 0, or an object/ref value; events with no source
     record -1 and are skipped, since reading a variable on -1 is a runtime error), so the game's checks
     (critconstant == 967 / scr_CritHasAncientSyn, side, scr_PerkLevel) test the inflicter; without FLAG both blocks
     are skipped, so the old drawback (permanence on your own Relic creature) stays fixed;
  3. at the end of the Wonder block (0x142017101) the slot is swapped back;
  4. Wonder's side constants are swapped (copy-paste bug: it asked for the enemy's perk level on your side);
  5. the two `duration = -2` writes are left as the game has them (the old partial fix NOP'ed them);
  6. the spread copies get duration -2 (forever) instead of the default; their source stays -1 so they don't re-spread
     (in-game test 2026-10-26: v3 made the primary target permanent but not the spread copies).
The detours make no calls and have no frame. Data lives in the zero-filled tail of .data (writable), code in the
zero-filled tail of .text.

python tools/build_h01b.py   (rewrites SU-0080 in loader/patches.json; then run tools/anchor.py and the build)
"""
import json, os, re, sys
import keystone, capstone

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.join(HERE, "..", "loader", "patches.json")
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

# game addresses (2.0.38)
ORIG = 0x142015940                     # scr_CritAddCondition
SITES = (0x1410e7a17, 0x1410eab4f, 0x1410f0c8f)   # its 3 calls in bc_ExecuteEvents (event RValue at [rsp+0x98e8])
DET_A, DET_A_NEXT, DET_A_SKIP = 0x142016c40, 0x142016c45, 0x142017101   # 'mov byte [rsp+0x20],0' (5 bytes)
DET_B, DET_B_NEXT = 0x142017101, 0x142017109                            # 'mov dword [rsp+0x60],0x5c' (8 bytes)
WONDER_SLOTGT0 = 0x142016fdc           # lea rdx,[RValue 0.0] used when slot > 0   -> 1.0
WONDER_SLOTEQ0 = 0x1420170a1           # lea rdx,[RValue 1.0] used when slot == 0  -> 0.0
RV_ZERO, RV_ONE = 0x149d50470, 0x149905100
# The spread copies (bc_OnBuffDebuff L53 Curse / L66 Wonder) are created with source -1 (so they don't re-spread) and
# duration -1 (default). The text says the Relic afflicts / grants them, so they last forever too: pass duration -2
# (the value the game's own "always has" effects pass, 52 sites in bc_MaintainPermanentEffects). Source stays -1.
SPREAD_DURATION = (0x141430f50, 0x141431656)   # lea rdx,[RValue -1.0] -> args[3] ([rbp+0xb0])
RV_MINUS1, RV_MINUS2 = 0x1498f28a0, 0x1498e1730

# our memory (must match loader/hooks.c)
INFLICTER = 0x149ed81c0                # 16-byte RValue (data tail of .data, RW, zero)
FLAG, SWAPPED = 0x149ed81d0, 0x149ed81d1
HOOKPTR = 0x149ed81e0                  # 8 bytes: filled at load time with the C hook's address
CODE = 0x1488bf680                     # code tail of .text

STUB_SITE = """
  jmp qword ptr [{hookptr:#x}]
"""
STUB_A = """
  cmp byte ptr [{flag:#x}], 0
  je skip
  mov r11d, dword ptr [{infl_kind:#x}]
  and r11d, 0xffffff
  cmp r11d, 0
  jne not_real
  movsd xmm0, qword ptr [{infl:#x}]
  xorps xmm1, xmm1
  comisd xmm0, xmm1
  jbe skip
  jmp swap
not_real:
  cmp r11d, 6
  je swap
  cmp r11d, 15
  jne skip
swap:
  movups xmm0, xmmword ptr [rsp + 0x78]
  movups xmm1, xmmword ptr [{infl:#x}]
  movups xmmword ptr [rsp + 0x78], xmm1
  movups xmmword ptr [{infl:#x}], xmm0
  mov byte ptr [{swapped:#x}], 1
  mov byte ptr [rsp + 0x20], 0
  jmp {next:#x}
skip:
  jmp {skipto:#x}
"""
STUB_B = """
  cmp byte ptr [{swapped:#x}], 0
  je done
  movups xmm0, xmmword ptr [rsp + 0x78]
  movups xmm1, xmmword ptr [{infl:#x}]
  movups xmmword ptr [rsp + 0x78], xmm1
  movups xmmword ptr [{infl:#x}], xmm0
  mov byte ptr [{swapped:#x}], 0
done:
  mov dword ptr [rsp + 0x60], 0x5c
  jmp {next:#x}
"""


def asm(src, addr):
    """Assemble at addr. The game is loaded at a random base (ASLR), so our code must be position-independent:
    every address has to be rip-relative or a rel32 branch. Reject anything absolute."""
    enc, _ = ks.asm(src, addr)
    code = bytes(enc)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(code, addr):
        if i.mnemonic == "movabs":                      # 64-bit immediates / moffs: absolute addresses
            raise SystemExit("absolute address in cave code @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
        if re.search(r"\[0x[0-9a-f]{6,}\]", i.op_str):
            raise SystemExit("absolute memory operand in cave code @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code


def chunks(addr, data, note):
    out = []
    for k in range(0, len(data), 32):
        part = data[k:k + 32]
        out.append({"va": hex(addr + k), "expect": "00" * len(part), "write": part.hex(), "note": note + " (cave code)"})
    return out


def main():
    fmt = dict(infl=INFLICTER, flag=FLAG, swapped=SWAPPED, hookptr=HOOKPTR, infl_kind=INFLICTER + 12)
    site = asm(STUB_SITE.format(**fmt), CODE)
    a_at = (CODE + len(site) + 15) // 16 * 16
    stub_a = asm(STUB_A.format(next=DET_A_NEXT, skipto=DET_A_SKIP, **fmt), a_at)
    b_at = (a_at + len(stub_a) + 15) // 16 * 16
    stub_b = asm(STUB_B.format(next=DET_B_NEXT, **fmt), b_at)
    end = b_at + len(stub_b)
    assert end < 0x1488c0000, "code cave overflow"
    edits = []
    edits += chunks(CODE, site, "event-site trampoline: jmp [HOOKPTR] -> hook_su0080_add_condition (loader/hooks.c)")
    edits += chunks(a_at, stub_a, "Curse block entry: swap holder slot with the inflicter (FLAG) or skip both blocks")
    edits += chunks(b_at, stub_b, "Wonder block exit: swap the holder slot back")
    le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
    for s in SITES:
        edits.append({"va": hex(s + 1), "expect": le(ORIG - (s + 5)), "write": le(CODE - (s + 5)),
                      "note": "bc_ExecuteEvents buff/debuff event: call scr_CritAddCondition -> trampoline"})
    edits.append({"va": hex(DET_A), "expect": "c644242000", "write": asm("jmp %#x" % a_at, DET_A).hex(),
                  "note": "scr_CritAddCondition L80 (Curse block start): detour"})
    jb = asm("jmp %#x" % b_at, DET_B)
    edits.append({"va": hex(DET_B), "expect": "c74424605c000000", "write": (jb + b"\x90" * (8 - len(jb))).hex(),
                  "note": "scr_CritAddCondition L92 marker (after Wonder block): detour"})
    for at, old, new, why in ((WONDER_SLOTGT0, RV_ZERO, RV_ONE, "slot > 0 -> scr_PerkLevel(655, 1)"),
                              (WONDER_SLOTEQ0, RV_ONE, RV_ZERO, "slot == 0 -> scr_PerkLevel(655, 0)")):
        edits.append({"va": hex(at + 3), "expect": le(old - (at + 7)), "write": le(new - (at + 7)),
                      "note": "Forsaken Wonder side constants (copy-paste swap): " + why})
    for at, which in zip(SPREAD_DURATION, ("Curse debuff", "Wonder buff")):
        edits.append({"va": hex(at + 3), "expect": le(RV_MINUS1 - (at + 7)), "write": le(RV_MINUS2 - (at + 7)),
                      "note": "bc_OnBuffDebuff spread copy (%s): duration -1 (default) -> -2 (forever)" % which})
    spec = json.load(open(PATCHES, encoding="utf-8"))
    spec["build"].setdefault("data_cave_start", "0x149ed81b0")          # never shrink an area other patches use
    spec["build"].setdefault("data_cave_end", "0x149ed8a00")
    p = next(p for p in spec["patches"] if p["id"] == "SU-0080")
    p["title"] = ("Primordial Curse / Forsaken Wonder: debuffs inflicted / buffs granted by your creatures' Relics "
                  "(and Ancient Synchronicity Avatars / Godspawn) last forever; no longer on your own Relic creature")
    p["edits"] = edits
    p["runtime_hooks"] = [{"slot_va": hex(HOOKPTR), "symbol": "hook_su0080_add_condition"}]
    json.dump(spec, open(PATCHES, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
    open(PATCHES, "a").write("\n")
    print("SU-0080: %d edits; code %#x-%#x (%d bytes)" % (len(edits), CODE, end, end - CODE))


if __name__ == "__main__":
    main()
