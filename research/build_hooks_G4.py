"""Build research/hooks_G4.json: SU-0109 Petra & Aes 70, SU-0135 Reliquary Stat Bonus, SU-0143 Witchcraft
(see loader/hooks_G4.c). Verifies every expect byte and call target against the exe. Assigned space only:
code 0x1488bff70-0x1488bffff (zero tail of the .text page), data 0x149ed85a0-0x149ed85ff (.data BSS)."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x1488bff70, 0x1488bffff, 0x149ed85a0, 0x149ed85ff
SLOT = lambda k: DATA_LO + 8 * k                            # pointer slots P0..P8 (filled by the loader)
SAVED_RBP, WITCH_FLAG = 0x149ed85e8, 0x149ed85f0            # must match loader/hooks_G4.c
DIMINISH, SPEED = 0x1460713c0, 0x1417e3430
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def je_to_jmp(va, target, note):
    b = S.pe.get_data(va - S.BASE, 6)
    assert b[:2] == b"\x0f\x84" and va + 6 + int.from_bytes(b[2:], "little", signed=True) == target, hex(va)
    return {"va": hex(va), "expect": b.hex(), "write": "e9" + le(target - (va + 5)) + "90", "note": note}


def tramp(at, slot, save_rbp=False):
    src = ("mov qword ptr [%#x], rbp\n" % SAVED_RBP if save_rbp else "") + "jmp qword ptr [%#x]" % slot
    code = asm(src, at)
    return code


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def main():
    used = []

    def cave(at, slot, sym, save_rbp=False):
        code = tramp(at, slot, save_rbp)
        assert CODE_LO <= at and at + len(code) - 1 <= CODE_HI and DATA_LO <= slot and slot + 7 <= DATA_HI
        for lo, n in used:
            assert at + len(code) <= lo or lo + n <= at, hex(at)
        used.append((at, len(code)))
        return chunks(at, code, "trampoline -> " + sym), [res(at, len(code), "trampoline -> " + sym),
                                                          res(slot, 8, "hook pointer " + sym)]

    # ---- SU-0109
    e, rv, hooks = [], [], []
    for at, k, sym, rbp, site, gate, gtarget, where in [
            (0x1488bff70, 0, "hook_su0109_damage", False, 0x1415aa80f, 0x14163c5fe, 0x14163c798, "bc_SpellDamage L437 / L2297"),
            (0x1488bff78, 1, "hook_su0109_healing", True, 0x141648c97, 0x141650f94, 0x141651027, "bc_SpellHealing L193"),
            (0x1488bff88, 2, "hook_su0109_stat", True, 0x141656784, 0x14165e7c6, 0x14165e857, "bc_SpellStat L232")]:
        c, r = cave(at, SLOT(k), sym, rbp); e += c; rv += r
        e.append(call_redirect(site, DIMINISH, at, where + " scr_Diminish(stat, pool) -> hook: pool + 15% Speed under Petra & Aes 70"))
        e.append(je_to_jmp(gate, gtarget, where.split()[0] + " Petra & Aes 70 gate: je -> jmp (skip the old flat +15% Speed on the final amount)"))
        hooks.append({"slot_va": hex(SLOT(k)), "symbol": sym})
    rv.append(res(SAVED_RBP, 8, "caller rbp saved by the healing / stat trampolines"))
    petra = {"id": "SU-0109", "bug": "SU-0109", "default": 1,
             "title": "Petra & Aes (rank 70): spell potency increased by 15% of Speed, folded into the casting stat like "
                      "Swiftcasting (code: flat 15% of Speed added to the final amount)",
             "edits": e, "runtime_hooks": hooks, "reserves": rv}

    # ---- SU-0135
    e, rv, hooks = [], [], []
    for at, k, sym, site, target, name in [
            (0x1488bff98, 3, "hook_su0135_attack", 0x1417aaeba, 0x1417aa4d0, "crit_attack L17"),
            (0x1488bffa0, 4, "hook_su0135_defense", 0x1417bd132, 0x1417bc7d0, "crit_defense L13"),
            (0x1488bffa8, 5, "hook_su0135_intelligence", 0x1417d00cc, 0x1417cf710, "crit_intelligence L13"),
            (0x1488bffb0, 6, "hook_su0135_speed", 0x1417e3d59, SPEED, "crit_speed L14")]:
        c, r = cave(at, SLOT(k), sym); e += c; rv += r
        e.append(call_redirect(site, target, at, name + " owner redirect -> hook: Relic gets +1%/rank Stat Bonus (x2 with Abandoned Altar)"))
        hooks.append({"slot_va": hex(SLOT(k)), "symbol": sym})
    reliq = {"id": "SU-0135", "bug": "SU-0135", "default": 1,
             "title": "Reliquary Stat Bonus: raises the Relic's stats by 1% per rank (100% more with Abandoned Altar) "
                      "(code: the Relic stat redirect returned before the bonus)",
             "edits": e, "runtime_hooks": hooks, "reserves": rv}

    # ---- SU-0143
    e, rv, hooks = [], [], []
    c, r = cave(0x1488bffb8, SLOT(7), "hook_su0143_cast"); e += c; rv += r
    e.append(call_redirect(0x14077bb08, 0x140aab480, 0x1488bffb8,
                           "bc_CreatureCast L1880 Witchcraft auto-cast bc_CreatureCastSpellGem -> hook: flag this cast"))
    c, r = cave(0x1488bffc0, SLOT(8), "hook_su0143_eventcast"); e += c; rv += r
    e.append(call_redirect(0x140aaf793, 0x140cd8d00, 0x1488bffc0,
                           "bc_CreatureCastSpellGem L288 bc_EventCast -> hook: flagged cast targets one random living creature"))
    hooks = [{"slot_va": hex(SLOT(7)), "symbol": "hook_su0143_cast"}, {"slot_va": hex(SLOT(8)), "symbol": "hook_su0143_eventcast"}]
    rv.append(res(WITCH_FLAG, 8, "Witchcraft cast flag (int)"))
    assert WITCH_FLAG + 7 <= DATA_HI and SLOT(8) + 8 <= SAVED_RBP
    witch = {"id": "SU-0143", "bug": "SU-0143", "default": 1,
             "title": "Witchcraft: Cursed enemies cast one of their single-target damage spells on a random creature "
                      "(either side, living, not itself) (code: always hit the caster's opponents)",
             "edits": e, "runtime_hooks": hooks, "reserves": rv}

    json.dump({"patches": [petra, reliq, witch]}, open(os.path.join(HERE, "hooks_G4.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_G4.json: 3 patches; code", [(hex(a), n) for a, n in used])


if __name__ == "__main__":
    main()
