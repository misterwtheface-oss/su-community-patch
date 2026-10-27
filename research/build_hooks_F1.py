"""Build research/hooks_F1.json (round-3 hook batch F1). Checks every expected byte against the baseline exe,
every redirected call's current target, and that no jump lands inside the bytes an edit replaces.
python research/build_hooks_F1.py"""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
import keystone, capstone

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CODE_LO, CODE_HI = 0x1488bfcb0, 0x1488bfe00
DATA_LO, DATA_HI = 0x149ed86c0, 0x149ed8800
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


def no_jumps_into(fn, lo, hi):
    a, b = S.func_range(fn)
    for i in S.disasm(a, b):
        if (i.mnemonic.startswith("j") or i.mnemonic == "call") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            assert not (lo < t < hi), "%s: jump %#x -> %#x lands inside %#x-%#x" % (fn, i.address, t, lo, hi)


def jump_over(fn, va, old_hex, target, note):
    old = exe(va, len(bytes.fromhex(old_hex)))
    assert old.hex() == old_hex, (fn, hex(va), old.hex())
    no_jumps_into(fn, va, va + len(old))
    j = asm("jmp %#x" % target, va)
    assert len(j) <= len(old)
    return {"va": hex(va), "expect": old.hex(), "write": (j + b"\x90" * (len(old) - len(j))).hex(), "note": note}


def tramp(addr, slot):
    assert DATA_LO <= slot < DATA_HI
    return asm("jmp qword ptr [%#x]" % slot, addr)


VARGET = 0x1478bbd70
HAS_PASSIVE, ADD_COND, REMOVE_COND = 0x14202c2c0, 0x142015940, 0x14203dbf0
P = []

# SU-0044 Master of Revenants: only the loop's last pass heals (one heal per creature turn)
P.append({"id": "SU-0044", "bug": "SU-0044", "default": 1,
          "title": "Master of Revenants: each Revenant heals 50% of its Health at the end of its own turn while your party is all Revenants (code healed once per party creature)",
          "edits": [jump_over("bc_CreatureEndOfTurn", 0x140af8bb8, "c74424405b040000", 0x140af9303,
                              "bc_CreatureEndOfTurn L1115: non-matching pass -> loop continue (no extra heal)")]})

# SU-0045 Unrealized Potential: the copy is queued with the pre-halving amount (it halves itself -> 50 + 50)
T, SL = 0x1488bfcb8, 0x149ed86c8
sites = (("bc_EventGainAttack", 0x140ff3f9f, "L341"), ("bc_EventGainDefense", 0x14100341f, "L349"),
         ("bc_EventGainIntelligence", 0x14101302f, "L340"), ("bc_EventGainSpeed", 0x141031a13, "L344"),
         ("bc_EventGainMaxHP", 0x141022064, "L335"))
P.append({"id": "SU-0045", "bug": "SU-0045", "default": 1,
          "title": "Unrealized Potential: the stat gain is split evenly over two gains (50% + 50%; code halved the copy again, 50% + 25%)",
          "edits": code_edits(T, tramp(T, SL), "trampoline -> hook_su0045_copy_amount")
          + [redirect(va, VARGET, T, "%s %s: var get amount for the copy -> pre-halving amount (hook)" % (fn, ln))
             for fn, va, ln in sites],
          "runtime_hooks": [{"slot_va": hex(SL), "symbol": "hook_su0045_copy_amount"}]})

# SU-0048 Puppet Master: drop the extra damage-taken block (the 5%-per-minion one at L1797 stays)
P.append({"id": "SU-0048", "bug": "SU-0048", "default": 1,
          "title": "Puppet Master: +20% damage dealt per minion, as the text says (code added a second +10% per temporary ally); the 5% less damage taken per minion is unchanged",
          "edits": [jump_over("bc_EventDamage", 0x140e6832d, "0f843b060000", 0x140e6896e,
                              "L3868: always skip the extra +10% per temporary ally block (to L3883)")]})

# SU-0052 Sugar Rush: re-check the same index after a removal shifted the conditions array
T, SL = 0x1488bfcc0, 0x149ed86d0
P.append({"id": "SU-0052", "bug": "SU-0052", "default": 1,
          "title": "Sugar Rush: all of the creature's buffs are removed at the end of its turn (code skipped the buff after each removed one)",
          "edits": code_edits(T, tramp(T, SL), "trampoline -> hook_su0052_remove")
          + [redirect(0x140ac1efb, REMOVE_COND, T, "bc_CreatureEndOfTurn L240: remove buff -> no index skip after a removal")],
          "runtime_hooks": [{"slot_va": hex(SL), "symbol": "hook_su0052_remove"}]})

# SU-0064 Careful What You Wish For / Grim Ailment: slot only (hook_su0080_add_condition calls it through the slot)
P.append({"id": "SU-0064", "bug": "SU-0064", "default": 1, "edits": [],
          "title": "Careful What You Wish For / Grim Ailment: buffs on that side / debuffs from that side last 1 turn, as the text says (limit was missing). Needs SU-0080 (shared add-condition hook)",
          "runtime_hooks": [{"slot_va": "0x149ed86c0", "symbol": "f1_su0064_args"}]})

# SU-0170-xmas Master of Stags x Christmas Is Canceled: 3 more random enemies Disarmed
T1, S1, T2, S2 = 0x1488bfcc8, 0x149ed86d8, 0x1488bfcd0, 0x149ed86e0
P.append({"id": "SU-0170-xmas", "bug": "SU-0170", "default": 1,
          "title": "Master of Stags: Christmas Is Canceled Disarms 6 random enemies instead of 3 (innate traits 100% more effective)",
          "edits": code_edits(T1, tramp(T1, S1), "trampoline -> hook_su0170_xmas_gate")
          + code_edits(T2, tramp(T2, S2), "trampoline -> hook_su0170_xmas_add")
          + [redirect(0x1416b5180, HAS_PASSIVE, T1, "bc_StartupBuffsDebuffs L1414: HasPassive(1020) gate -> remember holder"),
             redirect(0x1416b60ed, ADD_COND, T2, "bc_StartupBuffsDebuffs L1459: add Disarmed -> +3 targets under Master of Stags")],
          "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0170_xmas_gate"},
                            {"slot_va": hex(S2), "symbol": "hook_su0170_xmas_add"}]})

for p in P:
    for e in p["edits"]:
        va = int(e["va"], 16)
        if not (CODE_LO <= va < CODE_HI):
            assert exe(va, len(bytes.fromhex(e["expect"]))).hex() == e["expect"], (p["id"], e["va"])

# no overlap with anything already shipped or built by other batches
mine = [(int(e["va"], 16), int(e["va"], 16) + len(bytes.fromhex(e["write"])), p["id"]) for p in P for e in p["edits"]]
slots = {int(h["slot_va"], 16) for p in P for h in p.get("runtime_hooks", [])}
others = [os.path.join(HERE, "..", "loader", "patches.json")] + [
    os.path.join(HERE, f) for f in os.listdir(HERE) if f.startswith("hooks_") and f.endswith(".json") and f != "hooks_F1.json"]
for path in others:
    for q in json.load(open(path, encoding="utf-8"))["patches"]:
        for e in q["edits"]:
            a = int(e["va"], 16); b = a + len(bytes.fromhex(e["write"]))
            for lo, hi, pid in mine:
                assert hi <= a or b <= lo, "%s overlaps %s (%s) @%#x" % (pid, q["id"], os.path.basename(path), a)
        for h in q.get("runtime_hooks", []):
            assert int(h["slot_va"], 16) not in slots, (q["id"], h["slot_va"])

code_end = max(int(e["va"], 16) + len(bytes.fromhex(e["write"])) for p in P for e in p["edits"] if CODE_LO <= int(e["va"], 16) < CODE_HI)
assert code_end <= CODE_HI, hex(code_end)
json.dump({"patches": P}, open(os.path.join(HERE, "hooks_F1.json"), "w", encoding="utf-8", newline="\n"), indent=2)
print("%d patches, %d edits; code cave used up to %#x" % (len(P), sum(len(p["edits"]) for p in P), code_end))
