"""Build research/hooks_A2.json (round-2 hook batch A2). Checks every expected byte against the baseline exe,
every redirected call's current target, and that no jump lands inside the bytes a detour replaces.
python research/build_hooks_A2.py"""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
import keystone, capstone

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CODE_LO, CODE_HI = 0x1488bf810, 0x1488bfa00
DATA_LO, DATA_HI = 0x149ed8320, 0x149ed8400
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def asm(src, addr):
    enc, _ = ks.asm(src, addr)
    code = bytes(enc)
    for i in md.disasm(code, addr):
        if i.mnemonic == "movabs" or re.search(r"\[0x[0-9a-f]{6,}\]", i.op_str):
            raise SystemExit("absolute address @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code


def exe(va, n):
    return S.pe.get_data(va - S.BASE, n)


def code_edits(addr, data, note):
    assert CODE_LO <= addr and addr + len(data) <= CODE_HI, hex(addr)
    return [{"va": hex(addr + k), "expect": "00" * len(data[k:k + 32]), "write": data[k:k + 32].hex(),
             "note": note + " (cave code)"} for k in range(0, len(data), 32)]


def redirect(site, callee, tramp, note):
    b = exe(site, 5)
    assert b[0] == 0xE8, hex(site)
    assert int.from_bytes(b[1:], "little", signed=True) + site + 5 == callee, "%#x does not call %#x" % (site, callee)
    return {"va": hex(site + 1), "expect": le(callee - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def patch_bytes(va, new, note):
    old = exe(va, len(new))
    return {"va": hex(va), "expect": old.hex(), "write": new.hex(), "note": note}


def no_jumps_into(fn, lo, hi):
    a, b = S.func_range(fn)
    for i in S.disasm(a, b):
        if (i.mnemonic.startswith("j") or i.mnemonic == "call") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            assert not (lo < t < hi), "%s: jump %#x -> %#x lands inside %#x-%#x" % (fn, i.address, t, lo, hi)


def tramp(addr, slot):
    assert DATA_LO <= slot < DATA_HI
    return asm("jmp qword ptr [%#x]" % slot, addr)


VARGET, VARREF = 0x1478bbd70, 0x14028c090
P = []

# SU-0060 Windwalker
T, SL = 0x1488bf810, 0x149ed8320
P.append({"id": "SU-0060", "bug": "SU-0060", "default": 1,
          "title": "Windwalker: 5% avoid chance (up to 80%) for each time ALL your creatures dodged this battle (code counted only the damaged creature's own dodges)",
          "edits": code_edits(T, tramp(T, SL), "trampoline -> hook_su0060_varget")
          + [redirect(0x140d03977, VARGET, T, "bc_EventDamage L181: var get total_dodges -> party total (hook)")],
          "runtime_hooks": [{"slot_va": hex(SL), "symbol": "hook_su0060_varget"}]})

# SU-0133 Union
T1, S1, T2, S2 = 0x1488bf818, 0x149ed8328, 0x1488bf820, 0x149ed8330
P.append({"id": "SU-0133", "bug": "SU-0133", "default": 1,
          "title": "Union: each creature grants its % of Health from its Max Health at battle start, not compounded along the party",
          "edits": code_edits(T1, tramp(T1, S1), "trampoline -> hook_su0133_startup")
          + code_edits(T2, tramp(T2, S2), "trampoline -> hook_su0133_varget")
          + [redirect(0x1469c6a08, 0x141710e10, T1, "battle controller: call bc_StartupStatGain -> snapshot wrapper"),
             redirect(0x1417311c8, VARGET, T2, "bc_StartupStatGain L787: ally.hpmax -> snapshot value")],
          "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0133_startup"},
                            {"slot_va": hex(S2), "symbol": "hook_su0133_varget"}]})

# SU-0086 5740-NG rank 10
T1, S1, T2, S2 = 0x1488bf828, 0x149ed8338, 0x1488bf830, 0x149ed8340
P.append({"id": "SU-0086", "bug": "SU-0086", "default": 1,
          "title": "5740-NG rank 10: the relic attacks only if the bearer really took no damage this turn (avoided, dodged and prevented hits no longer count)",
          "edits": code_edits(T1, tramp(T1, S1), "trampoline -> hook_su0086_turnstart")
          + code_edits(T2, tramp(T2, S2), "trampoline -> hook_su0086_varget")
          + [redirect(0x140b23c3d, VARREF, T1, "bc_CreatureStartOfTurn L54 (damages reset): snapshot party damage_taken"),
             redirect(0x140abf4fe, VARGET, T2, "bc_CreatureEndOfTurn L210: bearer.damages -> took real damage since turn start")],
          "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0086_turnstart"},
                            {"slot_va": hex(S2), "symbol": "hook_su0086_varget"}]})

# SU-0128 Born Again
T1, S1 = 0x1488bf838, 0x149ed8348
assert exe(0x1469d339f, 5)[0] == 0xE8 and int.from_bytes(exe(0x1469d339f, 5)[1:], "little", signed=True) + 0x1469d339f + 5 == 0x14028c410
P.append({"id": "SU-0128", "bug": "SU-0128", "default": 1,
          "title": "Born Again: creatures killed by start-of-battle effects (including queued ones like Red Wedding) are resurrected with 50% Health",
          "edits": code_edits(T1, tramp(T1, S1), "trampoline -> hook_su0128_turnstart")
          + [patch_bytes(0x1469d339f, bytes.fromhex("0f1f440000"), "battle Step L1123: drop the early global.bornagain = true (assign call -> nop)"),
             redirect(0x140b23bcd, VARREF, T1, "bc_CreatureStartOfTurn L53: set global.bornagain = true at the first turn start")],
          "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0128_turnstart"}]})

# SU-0151 Filtered Truth: entry hooks + relocated prologues; remove the early base-field caps
edits = []
for fn, ent, orig_tramp, slot, cap_at, cap_end, sym in (
        ("crit_attack", 0x1417aa4d0, 0x1488bf850, 0x149ed8350, 0x1417bbc3c, 0x1417bbe22, "hook_su0151_attack"),
        ("crit_intelligence", 0x1417cf710, 0x1488bf860, 0x149ed8358, 0x1417e2647, 0x1417e2829, "hook_su0151_intelligence")):
    pro = exe(ent, 10)
    assert pro == bytes.fromhex("48895c24104c89442418"), (fn, pro.hex())
    no_jumps_into(fn, ent, ent + 10)
    edits += code_edits(orig_tramp, pro + asm("jmp %#x" % (ent + 10), orig_tramp + 10), fn + " original entry: relocated prologue + jmp back")
    j = asm("jmp qword ptr [%#x]" % slot, ent)
    edits.append({"va": hex(ent), "expect": pro.hex(), "write": (j + b"\x90" * (10 - len(j))).hex(),
                  "note": fn + " entry -> " + sym})
    cap = exe(cap_at, 8)
    assert cap[:4] == bytes.fromhex("c7442460"), (fn, cap.hex())
    no_jumps_into(fn, cap_at, cap_at + 8)
    jc = asm("jmp %#x" % cap_end, cap_at)
    edits.append({"va": hex(cap_at), "expect": cap.hex(), "write": (jc + b"\x90" * (8 - len(jc))).hex(),
                  "note": fn + ": skip the early cap against the other stat's base field"})
P.append({"id": "SU-0151", "bug": "SU-0151", "default": 1,
          "title": "Filtered Truth: enemies always have equal Attack and Intelligence, whichever FINAL value is lower (code compared base fields before bonuses)",
          "edits": edits,
          "runtime_hooks": [{"slot_va": "0x149ed8350", "symbol": "hook_su0151_attack"},
                            {"slot_va": "0x149ed8358", "symbol": "hook_su0151_intelligence"}]})

# SU-0144 Death Guild: three call-free detours in scr_CritAddCondition's party loop
FLAG = 0x149ed8360
fn = "scr_CritAddCondition"
d1, d2, d3 = 0x1488bf870, 0x1488bf8a0, 0x1488bf8d0
assert exe(0x142019e94, 10) == bytes.fromhex("488bb560030000" + "4533f6")
no_jumps_into(fn, 0x142019e94, 0x142019e9e)
s1 = asm("mov byte ptr [%#x], 0\nmov rsi, qword ptr [rbp + 0x360]\nxor r14d, r14d\njmp 0x142019e9e" % FLAG, d1)
assert exe(0x14201a0b7, 8) == bytes.fromhex("c744246030010000")
no_jumps_into(fn, 0x14201a0b7, 0x14201a0bf)
s2 = asm("cmp byte ptr [%#x], 0\njne skip\nmov dword ptr [rsp + 0x60], 0x130\njmp 0x14201a0bf\nskip:\njmp 0x142019ea0" % FLAG, d2)
assert exe(0x14201a29a, 5) == bytes.fromhex("e901fcffff")
s3 = asm("mov byte ptr [%#x], 1\njmp 0x142019ea0" % FLAG, d3)
P.append({"id": "SU-0144", "bug": "SU-0144", "default": 1,
          "title": "Death Guild: the Debuff Potency bonus is applied once per debuff (code added it once per living party creature, compounding)",
          "edits": code_edits(d1, s1, "loop entry: clear the guild-applied flag")
          + code_edits(d2, s2, "guild add: skip if already applied this call")
          + code_edits(d3, s3, "after the guild add: set the flag")
          + [{"va": "0x142019e94", "expect": exe(0x142019e94, 10).hex(),
              "write": (asm("jmp %#x" % d1, 0x142019e94) + b"\x90" * 5).hex(), "note": "scr_CritAddCondition L296: detour to clear flag"},
             {"va": "0x14201a0b7", "expect": exe(0x14201a0b7, 8).hex(),
              "write": (asm("jmp %#x" % d2, 0x14201a0b7) + b"\x90" * 3).hex(), "note": "scr_CritAddCondition L304: detour, skip repeat guild add"},
             {"va": "0x14201a29a", "expect": exe(0x14201a29a, 5).hex(),
              "write": asm("jmp %#x" % d3, 0x14201a29a).hex(), "note": "scr_CritAddCondition L305 continue: detour, set flag"}]})

# SU-0134 Artifact Spell Slot vs Nether Stone: save base+Smith chance at L2573, restore at L2586 (call-free)
SAVE, AFLAG, ARSP = 0x149ed8370, 0x149ed8380, 0x149ed8388
a1, a2 = 0x1488bf900, 0x1488bf940
fn = "bc_OnAttack"
assert exe(0x1413b0a6b, 11) == bytes.fromhex("c78424500102000d0a0000")
assert exe(0x1413b1694, 11) == bytes.fromhex("c78424500102001a0a0000")
no_jumps_into(fn, 0x1413b0a6b, 0x1413b0a76)
no_jumps_into(fn, 0x1413b1694, 0x1413b169f)
t1 = asm("movups xmm0, xmmword ptr [rsp + 0x16e20]\nmovups xmmword ptr [%#x], xmm0\nmov qword ptr [%#x], rsp\n"
         "mov byte ptr [%#x], 1\nmov dword ptr [rsp + 0x20150], 0xa0d\njmp 0x1413b0a76" % (SAVE, ARSP, AFLAG), a1)
t2 = asm("cmp byte ptr [%#x], 0\nje done\ncmp qword ptr [%#x], rsp\njne done\nmovups xmm0, xmmword ptr [%#x]\n"
         "movups xmmword ptr [rsp + 0x16e20], xmm0\ndone:\nmov byte ptr [%#x], 0\nmov dword ptr [rsp + 0x20150], 0xa1a\n"
         "jmp 0x1413b169f" % (AFLAG, ARSP, SAVE, AFLAG), a2)
P.append({"id": "SU-0134", "bug": "SU-0134", "default": 1,
          "title": "Artifact Spell Slot: the artifact's chance starts from its own base (+ Smith), not the chance left over from the Nether Stone's spells",
          "edits": code_edits(a1, t1, "save base + Smith chance (L2573)") + code_edits(a2, t2, "restore before the artifact roll (L2586)")
          + [{"va": "0x1413b0a6b", "expect": exe(0x1413b0a6b, 11).hex(),
              "write": (asm("jmp %#x" % a1, 0x1413b0a6b) + b"\x90" * 6).hex(), "note": "bc_OnAttack L2573 marker: detour (save)"},
             {"va": "0x1413b1694", "expect": exe(0x1413b1694, 11).hex(),
              "write": (asm("jmp %#x" % a2, 0x1413b1694) + b"\x90" * 6).hex(), "note": "bc_OnAttack L2586 marker: detour (restore)"}]})

for p in P:
    for e in p["edits"]:
        va = int(e["va"], 16)
        if not (CODE_LO <= va < CODE_HI):
            assert exe(va, len(bytes.fromhex(e["expect"]))).hex() == e["expect"], (p["id"], e["va"])
code_end = max(int(e["va"], 16) + len(bytes.fromhex(e["write"])) for p in P for e in p["edits"] if CODE_LO <= int(e["va"], 16) < CODE_HI)
assert code_end <= CODE_HI, hex(code_end)
json.dump({"patches": P}, open(os.path.join(HERE, "hooks_A2.json"), "w", encoding="utf-8", newline="\n"), indent=2)
print("%d patches, %d edits; code cave used up to %#x" % (len(P), sum(len(p["edits"]) for p in P), code_end))
