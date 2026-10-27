"""Build hook batch R into research/hooks_R.json (merged into loader/patches.json by the parent session).

Each hook: one game `call` -> a cave trampoline -> the C function in loader/hooks_R.c (via a pointer slot the loader
fills). "rbp" trampolines first store the caller's rbp in a data slot (for rbp-framed callers' locals).
Ranges owned by batch R: code cave 0x1488bf760-0x1488bf9ff, data 0x149ed8200-0x149ed83ff
(hook pointer slots 0x149ed8200 + 8n, rbp slots 0x149ed8300 + 8n).
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
from build_h01b import asm, chunks
import gmlsite as S

CODE0, CODE1 = 0x1488bf760, 0x1488bfa00
SLOT0, RBP0, DATA1 = 0x149ed8200, 0x149ed8300, 0x149ed8400

# (bug, title, [ (site, expected callee, symbol, rbp slot index or None, note) ])
HOOKS = [
    ("SU-0007", "Brambleskin rank 100: the first time the bearer is killed, it resurrects with 100% Health and gains 50% stats (its rank test never passed on a real death)",
     [(0x1415055a5, 0x14202d600, "hook_su0007_relicperk_allow_dead", None, "bc_OnDeath L1945: scr_CritHasRelicPerk(dying, 25, 10) -> hook (adds allow_dead = true)")]),
    ("SU-0008", "Fable rank 80: the bearer's on-death effects activate 1 additional time (its rank test never passed on a real death)",
     [(0x1410a6f22, 0x14202d600, "hook_su0008_relicperk_allow_dead", None, "bc_ExecuteEvents L453: scr_CritHasRelicPerk(creature, 29, 8) -> hook (adds allow_dead = true)")]),
    ("SU-0006", "Lamora rank 90: +30% Intelligence per enemy with Blighted only from rank 90 (code applied it from rank 30)",
     [(0x1415a7159, 0x14202b010, "hook_su0006_damage", None, "bc_SpellDamage L354: Blighted count scr_CritHasCondition -> hook (0 unless Lamora rank 90)"),
      (0x14164807d, 0x14202b010, "hook_su0006_healing", 0, "bc_SpellHealing L139-148: Blighted count -> hook (rbp handed over)"),
      (0x141655a1b, 0x14202b010, "hook_su0006_stat", 1, "bc_SpellStat L177-186: Blighted count -> hook (rbp handed over)")]),
    ("SU-0085", "Covenant: once your creatures have cast each Rune spell, their on-attack effects activate 1 additional time, only with Covenant (code gave it to any caster without the perk)",
     [(0x1408be001, 0x1402f4230, "hook_su0085_covenant_add", None, "bc_CreatureCast L9798 Rune case: n += 1 -> hook (only for your caster with perk 289)")]),
    ("SU-0127", "Bolster: less damage from attacks and spells only (code also cut indirect damage)",
     [(0x140e06372, 0x1464eb110, "hook_su0127_bolster_gate", None, "bc_EventDamage L2092: scr_PerkLevel(58) -> hook (0 unless dtype is attack 0 / spell 1)")]),
    ("SU-0009", "Starwrath rank 100: enemies without Confused get a 10% chance to act as if Confused; Confused enemies keep their normal chance (code lowered them to 10%)",
     [(0x1406a303d, 0x14028c530, "hook_su0009_attack", None, "bc_CreatureAttack L100: chance = 10 -> hook (skipped for a Confused actor)"),
      (0x140715ae0, 0x14028c530, "hook_su0009_cast", None, "bc_CreatureCast L208: chance = 10 -> hook (skipped for a Confused caster)")]),
    ("SU-0042", "Reliquary heal upgrade: heals from your Relics are increased by the Reliquary heal upgrade, doubled with Abandoned Altar (code computed the bonus and never applied it)",
     [(0x14103f06d, 0x14028c410, "hook_su0042_assign", 2, "bc_EventHeal L249: scratch = bonus (assign) -> hook adds it to the heal bonus pool"),
      (0x14103f2a2, 0x140290b30, "hook_su0042_double", 3, "bc_EventHeal L251 (Abandoned Altar): scratch *= 2 -> hook adds it to the pool again")]),
]


def main():
    le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
    code, slot_n, out = CODE0, 0, []
    for bug, title, sites in HOOKS:
        edits, rh = [], []
        for site, callee, sym, rbp, note in sites:
            ins = next(S.md.disasm(S.pe.get_data(site - S.BASE, 5), site))
            assert ins.mnemonic == "call" and int(ins.op_str, 16) == callee, (bug, hex(site), ins.op_str)
            slot = SLOT0 + 8 * slot_n
            src = ("mov qword ptr [%#x], rbp\n  " % (RBP0 + 8 * rbp) if rbp is not None else "") + "jmp qword ptr [%#x]" % slot
            tramp = asm(src, code)
            assert code + len(tramp) <= CODE1 and slot < RBP0 and (rbp is None or RBP0 + 8 * rbp < DATA1)
            edits += chunks(code, tramp, "trampoline -> %s" % sym)
            edits.append({"va": hex(site + 1), "expect": le(callee - (site + 5)), "write": le(code - (site + 5)), "note": note})
            rh.append({"slot_va": hex(slot), "symbol": sym})
            code = (code + len(tramp) + 15) // 16 * 16
            slot_n += 1
        out.append({"id": bug, "bug": bug, "default": 1, "title": title, "edits": edits, "runtime_hooks": rh})
    json.dump({"patches": out}, open(os.path.join(HERE, "hooks_R.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("%d patches, code up to %#x, %d slots" % (len(out), code, slot_n))


if __name__ == "__main__":
    main()
