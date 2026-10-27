"""Build hook batch E (research/hook_batches.json "E") into research/hooks_E.json (loader/patches.json schema).

C side: loader/hooks_E.c. Code cave 0x1488bfa00-0x1488bfbff, data 0x149ed8400-0x149ed85ff (batch E's ranges).
Every call edit checks that the site is an E8 call to the expected function; every other edit's expected bytes are read
from the baseline exe. python research/build_hooks_E.py
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
from build_h01b import chunks
import gmlsite as S
import re, keystone, capstone
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def asm(src, addr):
    """Assemble at addr; reject anything absolute (the game uses ASLR): movabs, moffs forms and absolute memory
    operands. Long instructions with only rsp/rbp-relative memory and immediates are fine."""
    code = bytes(_KS.asm(src, addr)[0])
    for i in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(code, addr):
        if i.mnemonic == "movabs" or re.search(r"\[0x[0-9a-f]+\]", i.op_str):
            raise SystemExit("absolute address in cave code @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code

OUT = os.path.join(HERE, "hooks_E.json")
CODE_LO, CODE_HI = 0x1488bfa00, 0x1488bfc00
DATA_LO, DATA_HI = 0x149ed8400, 0x149ed8600
ANY_ALLY, ANY_ENEMY, HAS_PASSIVE, HAS_CONDITION = 0x141f0a8a0, 0x141f0b2d0, 0x14202c2c0, 0x14202b010
IS_DEBUFF, RANDOM_BUFF, EVENT_BUFF, EVENT_DEBUFF, EQ = 0x141fa5120, 0x141168b80, 0x140ccac40, 0x140fdb040, 0x14028c8d0
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
raw = lambda va, n: S.pe.get_data(va - S.BASE, n)

code_ptr, data_ptr = [CODE_LO], [DATA_LO]


def alloc_code(n):
    a = code_ptr[0]; code_ptr[0] = (a + n + 7) // 8 * 8
    assert code_ptr[0] <= CODE_HI, "code range overflow"
    return a


def alloc_data(n):
    a = data_ptr[0]; data_ptr[0] = (a + n + 7) // 8 * 8
    assert data_ptr[0] <= DATA_HI, "data range overflow"
    return a


def call_edit(site, expect_target, new_target, note):
    b = raw(site, 5)
    assert b[0] == 0xE8, "%#x is not a call" % site
    cur = site + 5 + int.from_bytes(b[1:5], "little", signed=True)
    assert cur == expect_target, "%#x calls %#x, expected %#x" % (site, cur, expect_target)
    return {"va": hex(site + 1), "expect": b[1:5].hex(), "write": le(new_target - (site + 5)), "note": note}


def trampoline(symbol, patch):
    slot = alloc_data(8)
    code = asm("jmp qword ptr [%#x]" % slot, CODE_LO)   # length probe
    at = alloc_code(len(code))
    code = asm("jmp qword ptr [%#x]" % slot, at)
    patch["edits"] += chunks(at, code, "trampoline: jmp [slot] -> %s (loader/hooks_E.c)" % symbol)
    patch.setdefault("runtime_hooks", []).append({"slot_va": hex(slot), "symbol": symbol})
    return at


def nop_jcc(site, note):
    b = raw(site, 6)
    assert b[0] == 0x0F and 0x80 <= b[1] <= 0x8F, "%#x is not a jcc rel32" % site
    return {"va": hex(site), "expect": b.hex(), "write": "660f1f440000", "note": note}


def disp_edit(ins, ins_len, disp_off, new_target, note):
    old = raw(ins + disp_off, 4)
    return {"va": hex(ins + disp_off), "expect": old.hex(), "write": le(new_target - (ins + ins_len)), "note": note}


def patch(pid, title):
    return {"id": pid, "bug": pid, "default": 1, "title": title, "edits": []}


P = []

# ---- Elf traits: global (both side calls of each gate -> either side) -------------------------------------------
ELF = [("SU-0093", "Life And Other Illusions", "attack", "bc_OnAttack L25", 0x1412d4383, 0x1412d454c),
       ("SU-0094", "Madness And Other Ideals", "defend", "bc_OnDefend first block", 0x1415337e1, 0x141533888),
       ("SU-0095", "Forgiveness And Other Blunders", "provoke", "bc_OnProvoke first block", 0x141564ba2, 0x141564c56),
       ("SU-0096", "Love And Other Disasters", "are afflicted with a buff or debuff", "bc_OnBuffDebuff L34", 0x14143082d, 0x1414308e4),
       ("SU-0174", "Hate And Other Triumphs", "die", "bc_OnDeath L150", 0x14146f143, 0x14146f30c),
       ("SU-0175", "Justice And Other Fallacies", "are resurrected", "bc_OnResurrect L209", 0x1415825f1, 0x1415826a3)]
for pid, name, verb, where, s_ally, s_enemy in ELF:
    p = patch(pid, "%s: effects that activate when creatures %s are ignored whichever side holds the trait (code: only "
                   "when the opposing side held it)" % (name, verb))
    t = trampoline("hook_e_either_side_passive", p)
    p["edits"].append(call_edit(s_ally, ANY_ALLY, t, where + ": AnyAllyHasPassive -> either side"))
    p["edits"].append(call_edit(s_enemy, ANY_ENEMY, t, where + ": AnyEnemyHasPassive -> either side"))
    P.append(p)

# ---- Beelzebub / Leviathan: enemy kills only ---------------------------------------------------------------------
for pid, name, site, cond in (("SU-0124", "Beelzebub", 0x1414c2f8f, 58), ("SU-0125", "Leviathan", 0x1414c1e7d, 57)):
    p = patch(pid, "%s: triggers when its master kills an enemy (code: any kill, allies too)" % name)
    t = trampoline("hook_e_minion_kill", p)
    p["edits"].append(call_edit(site, HAS_CONDITION, t, "bc_OnDeath: scr_CritHasCondition(killer, %d) -> only if the dead creature was on the other side" % cond))
    P.append(p)

# ---- Spiderlings: enemy damage only; 50% of the master's current Health ------------------------------------------
p = patch("SU-0126", "Spiderlings: explode after the master takes damage from an enemy, for 50% of the master's Current "
                     "Health (code: any sourced hit, allies too; Maximum Health)")
t = trampoline("hook_e_spiderling", p)
p["edits"].append(call_edit(0x140f3449a, HAS_CONDITION, t, "bc_EventDamage L6595: scr_CritHasCondition(creature, 45) -> only if the source is on the other side"))
p["edits"].append(disp_edit(0x140f345e1, 6, 2, 0x1499e0a88, "bc_EventDamage L6596: burst amount reads creature.hpmax -> creature.hp"))
P.append(p)

# ---- Haunting Memories: trait found on a dead holder ---------------------------------------------------------------
p = patch("SU-0162", "Haunting Memories: works while its holder is dead, as the text says (code: the trait lookup skipped dead holders)")
t = trampoline("hook_e_haunting", p)
p["edits"].append(call_edit(0x140b0080b, HAS_PASSIVE, t, "bc_CreatureEndOfTurn L1194: scr_CritHasPassive(e, 878) -> with alive_only = 0"))
P.append(p)

# ---- Horde: holders don't receive ------------------------------------------------------------------------------------
p = patch("SU-0163", "Horde: the shared Speed is not applied to creatures that have the trait (code: holders received it)")
ta = trampoline("hook_e_horde_ally", p); te = trampoline("hook_e_horde_enemy", p)
p["edits"].append(call_edit(0x1417f3296, ANY_ALLY, ta, "crit_speed Horde gate (your side): false when the creature has 141"))
p["edits"].append(call_edit(0x1417f3744, ANY_ENEMY, te, "crit_speed Horde gate (enemy side): false when the creature has 141"))
P.append(p)

# ---- Periphery: enemy holders too ------------------------------------------------------------------------------------
p = patch("SU-0153", "Periphery: works for the holder's own side, enemy holders included (code: player side only)")
for site, jcc, sym, where in ((0x1406e429a, 0x1406e413f, "hook_e_periphery_dodge", "bc_CreatureAttack L1535 (always dodge)"),
                              (0x140eb016b, 0x140eb000a, "hook_e_periphery_taken", "bc_EventDamage L5175 (50% more damage taken)"),
                              (0x140ed38bb, 0x140ed375a, "hook_e_periphery_crit", "bc_EventDamage L5844 (always crit)")):
    t = trampoline(sym, p)
    p["edits"].append(nop_jcc(jcc, where + ": drop the 'slot > 0' test"))
    p["edits"].append(call_edit(site, ANY_ALLY, t, where + ": AnyAllyHasPassive(603) -> the holder's own side"))
P.append(p)

# ---- Master of Cataclysms (partial): only the master's side's traits ------------------------------------------------
p = patch("SU-0028", "Master of Cataclysms: only your all-Cataclysm party's traits get the 10% activation (code: enemies' Wrath "
                     "traits rolled too). Partial: the 'each creature's turn' half is not built")
t = trampoline("hook_e_cataclysm", p)
for site in (0x140b58066, 0x140b58854, 0x140b59042, 0x140b59830, 0x140b5a01e, 0x140b5a80c, 0x140b5affa, 0x140b5b7e8,
             0x140b5bfd6, 0x140b5c7c4, 0x140b5cfb2):
    p["edits"].append(call_edit(site, HAS_PASSIVE, t, "bc_CreatureStartOfTurn Cataclysm sweep: scr_CritHasPassive -> master's side only"))
P.append(p)

# ---- Ejector Seat: the ally rule covers the indirect branch too ---------------------------------------------------
p = patch("SU-0029", "Ejector Seat: ignored if an ally has the same trait, for indirect damage too (code: only the attack/spell "
                     "immunity checked allies)")
DT = alloc_data(1)
at1 = alloc_code(16)
c1 = asm("test al, al\n setne byte ptr [%#x]\n jmp 0x140eecd4c" % DT, at1)   # setne: rip-relative (mov [m], al
                                                                              # would encode an absolute moffs)
at2 = alloc_code(32)
c2 = asm("cmp byte ptr [%#x], 0\n je 0x140eefa63\n mov dword ptr [rsp + 0x30178], 0x17a2\n jmp 0x140eed385" % DT, at2)
p["edits"] += chunks(at1, c1, "Ejector Seat: remember 'attack/spell' (dtype > -1), always run the ally check")
p["edits"] += chunks(at2, c2, "Ejector Seat: after the ally check, indirect damage goes to the Health = 0 branch")
d1 = asm("jmp %#x" % at1, 0x140eecd41)
assert raw(0x140eecd41, 11).hex() == "0fb6c085c00f84172d0000"
p["edits"].append({"va": "0x140eecd41", "expect": "0fb6c085c00f84172d0000", "write": (d1 + b"\x90" * (11 - len(d1))).hex(),
                   "note": "bc_EventDamage L6041: dtype test result -> cave (no branch here any more)"})
d2 = asm("jmp %#x" % at2, 0x140eed37a)
assert raw(0x140eed37a, 11).hex() == "c7842478010300a2170000"
p["edits"].append({"va": "0x140eed37a", "expect": "c7842478010300a2170000", "write": (d2 + b"\x90" * (11 - len(d2))).hex(),
                   "note": "bc_EventDamage L6050 (no ally holds it): branch on the remembered damage type"})
P.append(p)

# ---- Disposability: other creatures' buffs only ---------------------------------------------------------------------
p = patch("SU-0107", "Disposability: only your other creatures' buffs persist through death (code: the holder's own buffs and "
                     "every minion persisted too)")
te = trampoline("hook_e_dispose_enemy", p); ta = trampoline("hook_e_dispose_ally", p); tb = trampoline("hook_e_dispose_not_buff", p)
p["edits"].append(call_edit(0x1412a3050, ANY_ENEMY, te, "bc_HandleDeath L60 (enemy side): not when the dying creature holds 512"))
p["edits"].append(call_edit(0x1412a3135, ANY_ALLY, ta, "bc_HandleDeath L60 (your side): not when the dying creature holds 512"))
p["edits"].append(call_edit(0x1412a3338, IS_DEBUFF, tb, "bc_HandleDeath L64: remove unless the condition is a buff"))
P.append(p)

# ---- Better, Faster, Stronger + Writhelings: repeat the debuff -----------------------------------------------------
p = patch("SU-0146", "Better, Faster, Stronger: Writhelings afflict a random enemy with a random debuff a second time (code "
                     "repeated Pleasant Disease's random buff on an ally)")
for ins in (0x140f73e55, 0x140f73e7d):
    assert raw(ins, 8).hex() == "488d8c2478210200"
    p["edits"].append({"va": hex(ins + 4), "expect": "78210200", "write": "f8220200",
                       "note": "bc_EventDamage L7076/77: pick from the enemies array [rsp+0x222f8] (was allies [rsp+0x22178])"})
t = trampoline("hook_e_bfs_random_debuff", p)
p["edits"].append(call_edit(0x140f73fcb, RANDOM_BUFF, t, "bc_EventDamage L7077: bc_GetRandomBuff(t) -> bc_GetRandomDebuff(-1, t)"))
p["edits"].append(call_edit(0x140f747c4, EVENT_BUFF, EVENT_DEBUFF, "bc_EventDamage L7078: bc_EventBuff -> bc_EventDebuff (same 9-argument layout, see SU-0129)"))
P.append(p)

# ---- Pumpkin Spice: one swap per side ---------------------------------------------------------------------------------
p = patch("SU-0156", "Pumpkin Spice: each side with a holder swaps its creatures' Maximum Health and Defense, once (code: "
                     "only the first holder's side)")
b = raw(0x141769835, 6); assert b[:2].hex() == "0f84"
p["edits"].append({"va": "0x141769837", "expect": b[2:6].hex(), "write": le(0x1417695a0 - (0x141769835 + 6)),
                   "note": "bc_StartupStatLoss: inner-loop exit continues the outer loop (was: leave the whole effect)"})
t = trampoline("hook_e_pumpkin", p)
p["edits"].append(call_edit(0x1417696e1, HAS_PASSIVE, t, "bc_StartupStatLoss: scr_CritHasPassive(c, 333) -> first holder per side only"))
P.append(p)

# ---- Valiant Heart: other creatures with a real matching fusion ------------------------------------------------------
p = patch("SU-0158", "Valiant Heart: +1 attack / cast for each other creature with the same secondary Fusion (code: counted "
                     "itself, and unfused creatures all matched)")
for ins in (0x1406c6b0f, 0x14074699c):
    assert raw(ins, 3).hex() == "488d15"
    p["edits"].append(disp_edit(ins, 7, 3, 0x1498e0f40, "bc_GetAlliesOf include_self: true -> false"))
t = trampoline("hook_e_valiant_eq", p)
for site in (0x1406c6cbd, 0x140746b5c):
    p["edits"].append(call_edit(site, EQ, t, "fuse2 == fuse2 -> never equal when either is -1 (unfused)"))
P.append(p)

# ---- Vicar's Blessing: one roll per event ------------------------------------------------------------------------------
p = patch("SU-0159", "Vicar's Blessing: one 35% chance per Blight tick, whatever the number of holders (code: one roll per "
                     "holder)")
p["edits"].append(nop_jcc(0x1410bcf6c, "bc_ExecuteEvents L821: ignore the per-enemy 35% roll"))
t = trampoline("hook_e_vicar", p)
p["edits"].append(call_edit(0x1410bd139, HAS_PASSIVE, t, "bc_ExecuteEvents L821: first holder makes the single 35% roll"))
P.append(p)

json.dump({"patches": P}, open(OUT, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
open(OUT, "a").write("\n")
print("%d patches, %d edits; code %#x-%#x, data %#x-%#x" % (len(P), sum(len(p["edits"]) for p in P),
                                                            CODE_LO, code_ptr[0], DATA_LO, data_ptr[0]))
