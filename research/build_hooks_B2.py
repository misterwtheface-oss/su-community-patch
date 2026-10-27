"""Build hook batch B2 (research/hook_batches.json, round 2) into research/hooks_B2.json (loader/patches.json schema).

C side: loader/hooks_B2.c. Code cave 0x1488bfaf0-0x1488bfbff and 0x1488bfcb0-0x1488bfdff, data 0x149ed84d0-0x149ed85ff
and 0x149ed86c0-0x149ed87ff (batch B2's ranges). Every call edit checks that the site is an E8 call to the expected
function; the edits are checked against every other patch file for overlap. python research/build_hooks_B2.py
"""
import json, os, sys, glob
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
from build_h01b import chunks
import gmlsite as S
import re, keystone, capstone
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
_CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def asm(src, addr):
    """Assemble at addr; reject anything absolute (the game uses ASLR): movabs and absolute memory operands."""
    code = bytes(_KS.asm(src, addr)[0])
    for i in _CS.disasm(code, addr):
        if i.mnemonic == "movabs" or re.search(r"\[0x[0-9a-f]+\]", i.op_str):
            raise SystemExit("absolute address in cave code @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code

OUT = os.path.join(HERE, "hooks_B2.json")
CODE = [[0x1488bfaf0, 0x1488bfc00], [0x1488bfcb0, 0x1488bfe00]]   # [next free, end) per range
DATA = [[0x149ed84d0, 0x149ed8600], [0x149ed86c0, 0x149ed8800]]
HAS_RELIC_PERK, PERK_LEVEL, CRIT_INT, SUB_INT, ASSIGN = 0x14202d600, 0x1464eb110, 0x1417cf710, 0x1402c47f0, 0x14028c410
ANY_ALLY, ANY_ENEMY = 0x141f0a8a0, 0x141f0b2d0
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
raw = lambda va, n: S.pe.get_data(va - S.BASE, n)


def alloc(ranges, n):
    for r in ranges:
        a = r[0]; e = (a + n + 7) // 8 * 8
        if e <= r[1]:
            r[0] = e; return a
    raise SystemExit("B2 range overflow")


def call_edit(site, expect_target, new_target, note):
    b = raw(site, 5)
    assert b[0] == 0xE8, "%#x is not a call" % site
    cur = site + 5 + int.from_bytes(b[1:5], "little", signed=True)
    assert cur == expect_target, "%#x calls %#x, expected %#x" % (site, cur, expect_target)
    return {"va": hex(site + 1), "expect": b[1:5].hex(), "write": le(new_target - (site + 5)), "note": note}


def trampoline(symbol, patch):
    slot = alloc(DATA, 8)
    n = len(asm("jmp qword ptr [%#x]" % slot, CODE[0][0]))
    at = alloc(CODE, n)
    code = asm("jmp qword ptr [%#x]" % slot, at)
    patch["edits"] += chunks(at, code, "trampoline: jmp [slot] -> %s (loader/hooks_B2.c)" % symbol)
    patch.setdefault("runtime_hooks", []).append({"slot_va": hex(slot), "symbol": symbol})
    return at


def next_ins(site):
    return next(_CS.disasm(raw(site + 5, 16), site + 5))


def patch(pid, title):
    return {"id": pid, "bug": pid, "default": 1, "title": title, "edits": []}


P = []

# ---- SU-0087 Amalgam 50 / 60 / 100: only an enemy's Inverted ---------------------------------------------------------
p = patch("SU-0087", "Amalgam ranks 50 / 60 / 100: work only on an enemy's Inverted, as the texts say (code: your own "
                     "Inverted creatures healed enemies twice, kept and regained their Inverted)")
td = trampoline("hook_su0087_damage", p); th = trampoline("hook_su0087_heal", p)
for site, t, where in ((0x140fadc11, td, "bc_EventDamage L7685 (R60 extra heal)"),
                       (0x140fae989, td, "bc_EventDamage L7698 (R50 potency kept)"),
                       (0x140faf71b, td, "bc_EventDamage L7711 (R100 re-apply)"),
                       (0x141044b7a, th, "bc_EventHeal L401 (R50 potency kept)"),
                       (0x1410450b2, th, "bc_EventHeal L427 (R100 re-apply)")):
    p["edits"].append(call_edit(site, HAS_RELIC_PERK, t, where + ": scr_CritHasRelicPerk -> false when the Inverted source is on the bearer's side"))
P.append(p)

# ---- SU-0088 relic follow-up attacks: never on the attacker's own side -------------------------------------------------
p = patch("SU-0088", "On-attack relic follow-ups ('this relic attacks that target / the enemy'): skipped when the bearer "
                     "hits its own side (code: a Confused bearer's relic attacked the ally too)")
t = trampoline("hook_su0088_relic_attack", p)
for site, line in ((0x141325411, 1047), (0x141325830, 1051), (0x141336dd8, 1259), (0x141337a35, 1270),
                   (0x141337e54, 1274), (0x141338273, 1278)):
    p["edits"].append(call_edit(site, HAS_RELIC_PERK, t, "bc_OnAttack L%d: scr_CritHasRelicPerk -> false when attacker and target share a side" % line))
P.append(p)

# ---- SU-0030 Fable 50: on-debuff effects repeat once more ----------------------------------------------------------------
p = patch("SU-0030", "Fable rank 50: the bearer's on-debuff effects activate 1 additional time, as on-buff ones already do "
                     "(code: only Unbound Hatred repeated them)")
t = trampoline("hook_su0030_perk_level", p)
p["edits"].append(call_edit(0x1410f018b, PERK_LEVEL, t, "bc_ExecuteEvents debuff case L1744: Unbound Hatred repeat bound -> +1 for a Fable 50 bearer"))
P.append(p)

# ---- SU-0131 Impending Victory: heal and stat spells too -----------------------------------------------------------------
p = patch("SU-0131", "Impending Victory: the 50% highest-stat blend also applies to healing and stat Arsenal spells "
                     "(code: damage spells only)")
for site, sym, where in ((0x141645e9f, "hook_su0131_healing", "bc_SpellHealing L16"),
                         (0x141652ca5, "hook_su0131_stat", "bc_SpellStat L22")):
    t = trampoline(sym, p)
    p["edits"].append(call_edit(site, CRIT_INT, t, where + ": potency stat crit_intelligence -> 50% highest stat with perk 596 and an Arsenal spell"))
P.append(p)

# ---- SU-0170 Master of Stags x Prism: 200% ---------------------------------------------------------------------------------
p = patch("SU-0170", "Master of Stags: Prism uses 200% of the potency-modifier stats for an all-Stag party with the Master "
                     "(user ruling: 100% more effective doubles the numbers). Christmas Is Canceled not built")
te = trampoline("hook_su0170_prism_enemy", p); ta = trampoline("hook_su0170_prism_ally", p)
tas = trampoline("hook_su0170_prism_assign", p)
GATES = {  # function: [(enemy gate, ally gate, assign)]
    "bc_SpellDamage": [(0x1415ab0ae, 0x1415ab283, 0x1415ab2d8), (0x1415abe9c, 0x1415ac071, 0x1415ac0c6),
                       (0x1415acc8a, 0x1415ace5f, 0x1415aceb4), (0x1415ada78, 0x1415adc4d, 0x1415adca2)],
    "bc_SpellHealing": [(0x141648ffe, 0x1416490a9, 0x1416493e0), (0x1416494d1, 0x14164957e, 0x1416498b5),
                        (0x1416499a6, 0x141649a53, 0x141649d8a), (0x141649e7b, 0x141649f28, 0x141649f4c)],
    "bc_SpellStat": [(0x141656adb, 0x141656b86, 0x141656eba), (0x141656fa9, 0x141657056, 0x14165738a),
                     (0x141657479, 0x141657526, 0x14165785a), (0x141657949, 0x1416579f6, 0x141657a19)]}
for fn, rows in GATES.items():
    lo, hi = S.func_range(fn)
    for ge, ga, asn in rows:
        for s in (ge, ga, asn): assert lo <= s < hi, (fn, hex(s))
        nx = next_ins(asn)
        assert "rax" not in nx.op_str and "eax" not in nx.op_str, "%#x: result used after the assign (%s %s)" % (asn, nx.mnemonic, nx.op_str)
        p["edits"].append(call_edit(ge, ANY_ENEMY, te, "%s Prism gate (enemy side): note Master of Stags" % fn))
        p["edits"].append(call_edit(ga, ANY_ALLY, ta, "%s Prism gate (your side): note Master of Stags" % fn))
        p["edits"].append(call_edit(asn, ASSIGN, tas, "%s Prism: stat = modifier stat, doubled under Master of Stags" % fn))
P.append(p)

# ---- SU-0176 Touch of Red: count every attack ----------------------------------------------------------------------------
p = patch("SU-0176", "Touch of Red: +25% for each attack in the chain, the first one included (code: each additional attack)")
t = trampoline("hook_su0176_hits", p)
assert raw(0x1406d7ed3, 6).hex() == "41b801000000", "Touch of Red: r8d = 1 not found"
p["edits"].append(call_edit(0x1406d7ee9, SUB_INT, t, "bc_CreatureAttack L1253: hits - 1 -> hits when hits > 1"))
P.append(p)

# ---- checks: every edit's bytes match the exe; no overlap with any other patch file -------------------------------------
mine = []
for q in P:
    for e in q["edits"]:
        a = int(e["va"], 16); n = len(e["write"]) // 2
        in_cave = any(lo <= a < hi for lo, hi in ((0x1488bfaf0, 0x1488bfc00), (0x1488bfcb0, 0x1488bfe00)))
        assert in_cave or raw(a, n).hex() == e["expect"], "expect mismatch @%s" % e["va"]   # cave: zero-filled at runtime
        mine.append((a, a + n, q["id"]))
    for h in q.get("runtime_hooks", []):
        a = int(h["slot_va"], 16); mine.append((a, a + 8, q["id"]))
mine.sort()
for (a, b, i), (c, d, j) in zip(mine, mine[1:]):
    assert b <= c, "self overlap %s/%s @%#x" % (i, j, c)
others = [os.path.join(HERE, "..", "loader", "patches.json")] + [f for f in glob.glob(os.path.join(HERE, "hooks_*.json")) if not f.endswith("hooks_B2.json")]
for f in others:
    d = json.load(open(f, encoding="utf-8")); pl = d["patches"] if isinstance(d, dict) else d
    for q in pl:
        spans = [(int(e["va"], 16), int(e["va"], 16) + len(e["write"]) // 2) for e in q.get("edits", [])]
        spans += [(int(h["slot_va"], 16), int(h["slot_va"], 16) + 8) for h in q.get("runtime_hooks", [])]
        for x, y in spans:
            for a, b, i in mine:
                assert not (a < y and x < b), "%s overlaps %s (%s) @%#x" % (i, q["id"], os.path.basename(f), a)

json.dump({"patches": P}, open(OUT, "w", encoding="utf-8"), indent=1)
print("wrote", OUT, len(P), "patches,", sum(len(q["edits"]) for q in P), "edits; code next", [hex(r[0]) for r in CODE],
      "data next", [hex(r[0]) for r in DATA])
