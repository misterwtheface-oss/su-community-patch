"""Build research/hooks_C2.json (round-2 batch C2). Checks every redirected call's current target in the baseline exe."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import keystone, capstone, pefile
EXE = os.path.join(HERE, "..", "..", "_baseline", "su_2x_steambuild_20548371", "game", "SiralimUltimate.exe")
pe = pefile.PE(EXE, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x1488bff50, 0x1488bfff0, 0x149ed88b0, 0x149ed8b00


def tramp(at, slot, note):
    assert CODE_LO <= at < CODE_HI and DATA_LO <= slot < DATA_HI
    b = bytes(ks.asm("jmp qword ptr [%#x]" % slot, at)[0])
    i = next(md.disasm(b, at)); assert i.mnemonic == "jmp" and "rip" in i.op_str, i.op_str
    return {"va": hex(at), "expect": "00" * len(b), "write": b.hex(), "note": note + " (cave code)"}


def redirect(site, old, new, note):
    raw = pe.get_data(site - BASE, 5)
    assert raw[0] == 0xE8 and int.from_bytes(raw[1:], "little", signed=True) + site + 5 == old, (hex(site), raw.hex())
    return {"va": hex(site + 1), "expect": le(old - (site + 5)), "write": le(new - (site + 5)), "note": note}


P = []
T1, S1 = 0x1488bff50, 0x149ed88b0
P.append({"id": "SU-0050", "bug": "SU-0050", "default": 1,
          "title": "Gambler's Game: otherwise it gains a random trait, as the text says (code gave a random debuff)",
          "edits": [tramp(T1, S1, "trampoline: jmp [slot] -> hook_su0050_gambler (loader/hooks_C2.c)"),
                    redirect(0x140c3eb11, 0x140fdb040, T1, "bc_CreatureStartOfTurn L3668: bc_EventDebuff(random debuff) -> trait event")],
          "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0050_gambler"}]})
T2, S2 = 0x1488bff58, 0x149ed88b8
P.append({"id": "SU-0028-turns", "bug": "SU-0028", "default": 1,
          "title": "Master of Cataclysms (needs SU-0028): the qualifying party's traits roll at the start of EVERY creature's turn (code: only on that party's own turns)",
          "edits": [tramp(T2, S2, "trampoline: jmp [slot] -> hook_su0028_cata_gate (loader/hooks_C2.c)"),
                    redirect(0x140b5755c, 0x141f0b2d0, T2, "L748 gate (enemy turn): scr_AnyEnemyHasPassive(2191) -> some side qualifies"),
                    redirect(0x140b57731, 0x141f0a8a0, T2, "L748 gate (your turn): scr_AnyAllyHasPassive(2191) -> some side qualifies"),
                    redirect(0x140b57981, 0x140601da0, T2, "L749 gate (enemy turn): bc_AllRace(Cataclysm, 0) -> some side qualifies"),
                    redirect(0x140b57bad, 0x140601da0, T2, "L749 gate (your turn): bc_AllRace(Cataclysm, 1) -> some side qualifies")],
          "runtime_hooks": [{"slot_va": hex(S2), "symbol": "hook_su0028_cata_gate"},
                            {"slot_va": "0x149ed8478", "symbol": "c2_cataclysm_holder"}]})
json.dump({"patches": P}, open(os.path.join(HERE, "hooks_C2.json"), "w", encoding="utf-8", newline="\n"), indent=2)
print(len(P), "patches,", sum(len(p["edits"]) for p in P), "edits")
