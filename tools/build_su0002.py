"""Build SU-0002 (Master of Gorgons always on): route the Gorgon block's bc_CountRace call through a C hook
(loader/hooks.c hook_su0002_count_race) that returns 0 unless the attacker's side holds Master of Gorgons (1442).
python tools/build_su0002.py  (then tools/anchor.py and the build)"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_h01b import asm, chunks, PATCHES

SITE = 0x140e5889a           # call bc_CountRace in the Gorgon block (bc_EventDamage L3600)
COUNT_RACE = 0x14068f7b0
CODE = 0x1488bf740           # cave code slot (after SU-0080's code, which ends at 0x1488bf735)
HOOKPTR = 0x149ed81e8        # pointer slot filled by the loader


def main():
    tramp = asm("jmp qword ptr [%#x]" % HOOKPTR, CODE)
    le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
    edits = chunks(CODE, tramp, "trampoline: jmp [HOOKPTR] -> hook_su0002_count_race (loader/hooks.c)")
    edits.append({"va": hex(SITE + 1), "expect": le(COUNT_RACE - (SITE + 5)), "write": le(CODE - (SITE + 5)),
                  "note": "bc_EventDamage L3600 Gorgon bonus: call bc_CountRace -> trampoline (0 unless the side has 1442)"})
    spec = json.load(open(PATCHES, encoding="utf-8"))
    p = next((p for p in spec["patches"] if p["id"] == "SU-0002"), None)
    if p is None:
        p = {"id": "SU-0002", "bug": "SU-0002", "default": 1}
        spec["patches"].append(p)
    p.update({"title": "Master of Gorgons: the Gorgon damage bonus needs the trait on the attacker's side (code gave it to every Gorgon). Confirmed in game",
              "edits": edits, "runtime_hooks": [{"slot_va": hex(HOOKPTR), "symbol": "hook_su0002_count_race"}]})
    json.dump(spec, open(PATCHES, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
    open(PATCHES, "a").write("\n")
    print("SU-0002: %d edits" % len(edits))


if __name__ == "__main__":
    main()
