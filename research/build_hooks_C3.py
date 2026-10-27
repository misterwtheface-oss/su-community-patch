"""Build research/hooks_C3.json: SU-0140 Internal Combustion (byte edit) and SU-0164 Kiichi's Aggression (2 hooks).
Splashing-style splash damage (see loader/hooks_C3.c). Verifies every expect byte and call target against the exe."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

EVENT_DAMAGE = 0x140cda820
TICK_SITE, KIICHI_SITE = 0x140b7042e, 0x140b767bd          # bc_CreatureStartOfTurn: Bleed tick / Kiichi splash
IC_DTYPE = 0x1410a593b                                     # bc_ExecuteEvents L431: lea rdx,[RValue 1.0] = dtype
RV_ONE_IC, RV_MINUS1 = 0x1498eeae0, 0x1498f1650             # the IC dtype constant; the static -1.0 Splashing uses
CODE_TICK, CODE_KIICHI = 0x1488bff60, 0x1488bff68
SLOT_TICK, SLOT_KIICHI = 0x149ed88c0, 0x149ed88c8
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def main():
    # IC: verify the lea and the constants
    b = S.pe.get_data(IC_DTYPE - S.BASE, 7)
    assert b[:3] == bytes.fromhex("488d15") and IC_DTYPE + 7 + int.from_bytes(b[3:], "little", signed=True) == RV_ONE_IC
    assert S.pe.get_data(RV_ONE_IC - S.BASE, 16).hex() == "000000000000f03f0000000000000000"
    assert S.pe.get_data(RV_MINUS1 - S.BASE, 16).hex() == "000000000000f0bf0000000000000000"
    ic = {"id": "SU-0140", "bug": "SU-0140", "default": 1,
          "title": "Internal Combustion: when the target is killed, all other enemies take 25% of the damage dealt as a "
                   "splash (Splashing's form: no second round of spell bonuses or crit, no chaining; kills count for the caster)",
          "edits": [{"va": hex(IC_DTYPE + 3), "expect": le(RV_ONE_IC - (IC_DTYPE + 7)), "write": le(RV_MINUS1 - (IC_DTYPE + 7)),
                     "note": "bc_ExecuteEvents L431 IC splash bc_EventDamage: dtype RValue 1.0 (spell) -> static -1.0 (indirect, as Splashing)"}]}
    edits = []
    edits += chunks(CODE_TICK, asm("jmp qword ptr [%#x]" % SLOT_TICK, CODE_TICK), "trampoline -> hook_su0164_bleed_tick")
    edits += chunks(CODE_KIICHI, asm("jmp qword ptr [%#x]" % SLOT_KIICHI, CODE_KIICHI), "trampoline -> hook_su0164_kiichi")
    edits.append(call_redirect(TICK_SITE, EVENT_DAMAGE, CODE_TICK,
                               "bc_CreatureStartOfTurn Bleed tick bc_EventDamage -> hook: remember the amount it deals"))
    edits.append(call_redirect(KIICHI_SITE, EVENT_DAMAGE, CODE_KIICHI,
                               "bc_CreatureStartOfTurn Kiichi's Aggression splash bc_EventDamage -> hook: 50% of the tick's dealt amount"))
    kiichi = {"id": "SU-0164", "bug": "SU-0164", "default": 1,
              "title": "Kiichi's Aggression: after an enemy takes damage from Bleeding, all other enemies take 50% of the damage it actually took (code: 50% of the pre-reduction Bleed amount)",
              "edits": edits,
              "runtime_hooks": [{"slot_va": hex(SLOT_TICK), "symbol": "hook_su0164_bleed_tick"},
                                {"slot_va": hex(SLOT_KIICHI), "symbol": "hook_su0164_kiichi"}]}
    json.dump({"patches": [ic, kiichi]}, open(os.path.join(HERE, "hooks_C3.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_C3.json: 2 patches,", 1 + len(edits), "edits")


if __name__ == "__main__":
    main()
