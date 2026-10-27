"""Hook batch C (combat engine): builds research/hooks_C.json. Each fix function returns a patch entry.

Run: python research/build_hooks_C.py   (verifies every expect byte against the baseline exe; no file outside
research/hooks_C.json is written). C hooks live in loader/hooks_C.c.
Code cave for this batch: 0x1488bfe00-0x1488bffef. Data (pointer slots): 0x149ed8800-0x149ed89ff.
"""
import json, os, re, sys
import keystone, capstone, pefile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
EXE = os.path.join(ROOT, "..", "_baseline", "su_2x_steambuild_20548371", "game", "SiralimUltimate.exe")
OUT = os.path.join(HERE, "hooks_C.json")
pe = pefile.PE(EXE, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CODE_LO, CODE_HI = 0x1488bfe00, 0x1488bfff0
DATA_LO, DATA_HI = 0x149ed8800, 0x149ed8a00
_code = [CODE_LO]
_data = [DATA_LO]
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def asm(src, addr):
    """Position-independent only (the game uses ASLR): no movabs, no absolute memory operands."""
    enc, _ = ks.asm(src, addr)
    code = bytes(enc)
    for i in md.disasm(code, addr):
        if i.mnemonic == "movabs":
            raise SystemExit("absolute address in cave code @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
        if re.search(r"\[0x[0-9a-f]{6,}\]", i.op_str):
            raise SystemExit("absolute memory operand @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code


def exe(va, n):
    return pe.get_data(va - BASE, n)


def edit(va, expect_hex, write, note):
    exp = bytes.fromhex(expect_hex) if isinstance(expect_hex, str) else expect_hex
    got = exe(va, len(exp))
    assert got == exp, "%#x: exe has %s, expected %s (%s)" % (va, got.hex(), exp.hex(), note)
    w = write if isinstance(write, bytes) else bytes.fromhex(write)
    assert len(w) == len(exp), "%#x: length mismatch" % va
    return {"va": hex(va), "expect": exp.hex(), "write": w.hex(), "note": note}


def cave(src_fn, note, align=16):
    """Place cave code (src_fn(addr) -> asm text) in this batch's code range; returns (addr, edits)."""
    a = (_code[0] + align - 1) // align * align
    code = asm(src_fn(a), a)
    assert a + len(code) <= CODE_HI, "batch C code cave full"
    _code[0] = a + len(code)
    out = []
    for k in range(0, len(code), 32):
        part = code[k:k + 32]
        out.append({"va": hex(a + k), "expect": "00" * len(part), "write": part.hex(), "note": note + " (cave code)"})
    return a, out


def slot():
    a = _data[0]; _data[0] += 8
    assert _data[0] <= DATA_HI
    return a


def jmp_over(va, size, target, note):
    """Replace a `size`-byte instruction at va with `jmp target` + NOPs (target inside the same function)."""
    j = asm("jmp %#x" % target, va)
    assert len(j) <= size
    return edit(va, exe(va, size), j + b"\x90" * (size - len(j)), note)


def detour(va, size, body_fn, note):
    """Frameless detour: replace a `size`-byte instruction (>= 5) at va with jmp to cave code that runs body, then the
    displaced instruction, then jumps back. body_fn(addr) -> asm text that must end by falling through to the
    displaced instruction (label 'resume:' is appended). The displaced instruction must be position-independent."""
    orig = exe(va, size)
    ins = next(md.disasm(orig, va))
    assert ins.size == size and "rip" not in ins.op_str, "displaced instruction must be a self-contained %d-byte op" % size
    disp = "%s %s" % (ins.mnemonic, ins.op_str)

    def src(a):
        return body_fn(a) + "\nresume:\n  %s\n  jmp %#x\n" % (disp, va + size)
    a, ed = cave(src, note)
    j = asm("jmp %#x" % a, va)
    return ed + [edit(va, orig, j + b"\x90" * (size - len(j)), note + " (detour)")]


def call_hook(site, callee, symbol, note):
    """House pattern: redirect `call callee` at site to a trampoline jmp [slot]; the loader fills slot with symbol."""
    s = slot()
    a, ed = cave(lambda a: "jmp qword ptr [%#x]" % s, "trampoline -> %s (loader/hooks_C.c)" % symbol, align=8)
    e = edit(site + 1, le(callee - (site + 5)), le(a - (site + 5)), note)
    assert exe(site, 1) == b"\xe8"
    return ed + [e], {"slot_va": hex(s), "symbol": symbol}


_shared = {}


def call_hook_shared(site, callee, symbol, note):
    """Like call_hook, but all sites hooked with the same symbol share one trampoline and slot."""
    if symbol not in _shared:
        s = slot()
        a, ed = cave(lambda a: "jmp qword ptr [%#x]" % s, "trampoline -> %s (loader/hooks_C.c)" % symbol, align=8)
        _shared[symbol] = (a, s, ed)
        first = True
    else:
        first = False
    a, s, ed = _shared[symbol]
    assert exe(site, 1) == bytes([0xE8])
    e = edit(site + 1, le(callee - (site + 5)), le(a - (site + 5)), note)
    return (ed if first else []) + [e], ({"slot_va": hex(s), "symbol": symbol} if first else None)


def patch(bug, title, edits, hooks=()):
    p = {"id": bug, "bug": bug, "default": 1, "title": title, "edits": edits}
    hooks = [h for h in hooks if h]
    if hooks:
        p["runtime_hooks"] = list(hooks)
    return p


# ---------------------------------------------------------------- fixes

def su0038():
    """Multi-hit attacks (also SU-0033 Confused leak). bc_CreatureAttack keeps one bonus pool ([rsp+0x3b8]) for the
    whole attack: zeroed at L10, reused as the Confused redirect chance at L88-L102 and never cleared, then every hit of
    the hit loop (L1076-L1892) adds its '% more damage' terms (L1169-L1713) and uses the pool at L1720. Hit k got the
    bonuses of hits 1..k, and every hit carried the leftover Confused chance as flat damage. Fix: zero the pool at the
    top of every hit iteration (L1077 marker @0x1406d05c9, reached from the loop condition only). Reference kinds
    (string / array / object) are left alone (fail safe; the pool is always a number)."""
    def body(a):
        return """
  mov eax, dword ptr [rsp + 0x3c4]
  and eax, 0x1f
  mov ecx, eax
  mov eax, 1
  shl eax, cl
  test eax, 0x46
  jne resume
  mov qword ptr [rsp + 0x3b8], 0
  mov dword ptr [rsp + 0x3c4], 0
"""
    ed = detour(0x1406d05c9, 8, body, "bc_CreatureAttack L1077 (top of each hit): bonus pool = 0")
    return patch("SU-0038", "Multi-hit attacks: every hit gets each '% more damage' bonus once (the pool no longer "
                 "piles up hit after hit); also stops the Confused chance leaking into damage (SU-0033)", ed)


def su0040():
    """Mindbender: 'This creature has a 30% chance to avoid damage from spells.' The avoid branch (bc_EventDamage L4922)
    only set amount = 0; the bonus pool and later flat terms still landed. Fix: the branch jumps to the game's own
    'amount = 0; return the event' tail (Spiritual Attunement's L7287 / L7288, @0x140f89579), i.e. it behaves like
    any Prevented hit: 0 damage, nothing below runs. No floater (Mindbender had none)."""
    return patch("SU-0040", "Mindbender: an avoided spell deals no damage at all (its bonus damage no longer lands)",
                 [jmp_over(0x140ea3b3c, 11, 0x140f89579, "bc_EventDamage L4921 (Mindbender avoid branch): -> L7287 amount = 0; L7288 return the event")])


def su0071():
    """Frozen: '25% chance to thaw at the start of their turn. This chance doubles after each of their turns.'
    bc_CreatureStartOfTurn L4425 doubles the chance `for i = 1 .. lifespan`, and lifespan is already 1 at the first
    thaw roll (conditions age earlier in the same turn start), so the first roll was 50% (resistant 100%). Start the
    loop at 2: first roll 25% (resistant 50%), then doubling after each turn. Yeti card cuts per doubling follow."""
    return patch("SU-0071", "Frozen: 25% chance to thaw on the first turn (50% if resistant), doubling after each turn "
                 "(code started at 50%)", [edit(0x140c7c615, "01", "02", "bc_CreatureStartOfTurn L4425: doubling loop starts at i = 2")])


def su0115():
    """No Head Necessary: 'While this creature is dead, it has a 50% chance to attack enemies at the start of their
    turns.' L5076 made one shared roll, then every dead holder attacked. The shared roll's skip is removed and the
    L5080 attack goes through hook_su0115_attack, which rolls 50% per holder."""
    ed = [edit(0x140cafb9b, "0f8477070000", "660f1f440000", "bc_CreatureStartOfTurn L5076: shared 50% roll -> always pass")]
    e, h = call_hook(0x140cb030e, 0x14069c200, "hook_su0115_attack", "L5080: bc_CreatureAttack -> hook (50% roll per dead holder)")
    return patch("SU-0115", "No Head Necessary: each dead holder has its own 50% chance to attack (code: one roll for all)",
                 ed + e, [h])


def su0148():
    """Colony: dead Griffons no longer Defend (bc_OnDefend L442-L456 loop had no Health test)."""
    e, h = call_hook(0x14153e51a, 0x140ab0390, "hook_su0148_defend", "bc_OnDefend L456: bc_CreatureDefend -> hook (living Griffons only)")
    return patch("SU-0148", "Colony: only your living Griffons defend as well (code: dead ones too)", e, [h])


def su0161():
    """Greybeard's Blessing: only heals given by the holder's side are boosted (code: every heal on a Blighted enemy)."""
    e1, h1 = call_hook(0x14103cbdd, 0x141f0b2d0, "hook_su0161_enemy_gate", "bc_EventHeal Greybeard gate (enemy holder) -> hook: healer must be an enemy")
    e2, h2 = call_hook(0x14103ccae, 0x141f0a8a0, "hook_su0161_ally_gate", "bc_EventHeal Greybeard gate (your holder) -> hook: healer must be yours")
    return patch("SU-0161", "Greybeard's Blessing: your creatures' heals on enemies with Blighted are doubled (code: every heal on them, "
                 "the enemies' own and Mending included)", e1 + e2, [h1, h2])


def su0016():
    """Celestial Nexus: the Barrier / Shell test moves from the hit creature (L395) to the Nexus holder (L398)."""
    ed = [edit(0x140d4a63c, "e8ef3b57ff", "b001909090", "bc_EventDamage L395: Barrier||Shell on the hit creature -> always true (al = 1)")]
    e, h = call_hook(0x140d4ab42, 0x14202c2c0, "hook_su0016_nexus_holder", "L398: scr_CritHasPassive(ally, 1710) -> hook: holder must have Barrier or Shell")
    return patch("SU-0016", "Celestial Nexus: takes hits for your other creatures while IT has Barrier or Shell (code tested the creature that was hit)",
                 ed + e, [h])


def su0165():
    """Kiichi's Persistence: the extra end-of-turn hit uses the base Bleed amount (no Bleed modifiers)."""
    ed, hooks = [], []
    e, h = call_hook(0x140acec38, 0x140671f30, "hook_su0165_bleed", "bc_CreatureEndOfTurn: extra hit's bc_CalculateBleedDamage -> hook (modifiers off)")
    ed += e; hooks.append(h)
    gates = [(0x1406724a3, 0x141f0a8a0, "hook_su0165_any_ally", "Master of Pilwizes (1472)"),
             (0x14067267a, 0x141f0b2d0, "hook_su0165_any_enemy", "Master of Pilwizes (1472)"),
             (0x140672a5f, 0x141f0b2d0, "hook_su0165_any_enemy", "trait 1304"),
             (0x140672ad0, 0x141f0b2d0, "hook_su0165_any_enemy", "trait 1305"),
             (0x140672da0, 0x141cf6e10, "hook_su0165_card", "card power 3"),
             (0x140672f42, 0x141f0b2d0, "hook_su0165_any_enemy", "trait 2192"),
             (0x1406731cb, 0x141f0a8a0, "hook_su0165_any_ally", "trait 2192"),
             (0x1406737cb, 0x14202d600, "hook_su0165_relic", "relic rank"),
             (0x14067397f, 0x141f0a8a0, "hook_su0165_any_ally", "trait 2045"),
             (0x140673a6f, 0x141f0b2d0, "hook_su0165_any_enemy", "trait 2045"),
             (0x140673d0c, 0x141cf6e10, "hook_su0165_card", "card power 1"),
             (0x140673f24, 0x141cf6e10, "hook_su0165_card", "card power 2")]
    for site, callee, sym, what in gates:
        e, h = call_hook_shared(site, callee, sym, "bc_CalculateBleedDamage %s gate -> %s (false during Persistence's hit)" % (what, sym))
        ed += e; hooks.append(h)
    return patch("SU-0165", "Kiichi's Persistence: the extra hit is not modified by effects that affect Bleeding (code applied Master of "
                 "Pilwizes, the Pilwiz cards and other Bleed modifiers)", ed, hooks)


def su0023():
    """Book of the Arsonist: only Burned debuffs it applies to enemies get +30% (code: every debuff)."""
    e, h = call_hook(0x140fe1f2c, 0x14202c2c0, "hook_su0023_arsonist", "bc_EventDebuff L246: scr_CritHasPassive(source, 404) -> hook (Burned on an enemy only)")
    return patch("SU-0023", "Book of the Arsonist: enemies' Burned debuffs it applies deal 30% more damage (code boosted every debuff it applied)", e, [h])


def su0047():
    """Death flags only on a real death (bc_OnDeath L76 / L179 / L185 / L190 / L194 can_resurrect = false)."""
    ed, hooks = [], []
    for site, what in ((0x141467c9b, "Epigraphy L76"), (0x1414731bf, "End On a High Note L179"), (0x14147379d, "Feast and Famine L185"),
                       (0x141473bda, "Burn Their Corpses L190"), (0x141474017, "Endwalker L194")):
        e, h = call_hook_shared(site, 0x1478bc260, "hook_su0047_deathflag", "bc_OnDeath %s: can_resurrect = false -> hook (dead creatures only)" % what)
        ed += e; hooks.append(h)
    return patch("SU-0047", "Death flags ('cannot be resurrected') apply only to creatures that really died (on-death effects run on a living "
                 "creature, e.g. Mortal Terror + Feast and Famine, no longer mark it)", ed, hooks)


def su0057():
    e, h = call_hook(0x140e6e63b, 0x1417a2e70, "hook_su0057_details", "bc_EventDamage L4006: big_mult(amount, 0.5) -> hook (cut to half of a neutral hit)")
    return patch("SU-0057", "Details Matter: hits on your creatures end at half of a neutral hit, as if they were strong against the attacker's "
                 "class (code halved whatever the class step gave, so weak hits ended at a quarter and strong ones at full)", e, [h])


def su0147():
    ed, hooks = [], []
    for term_site, mul_site, ln in ((0x140e6f816, 0x140e6fc9d, 4039), (0x140e70315, 0x140e7079c, 4045), (0x140e70e14, 0x140e7129b, 4051),
                                    (0x140e71913, 0x140e71d9a, 4057), (0x140e72412, 0x140e72899, 4063)):
        e, h = call_hook_shared(term_site, 0x1417a2e70, "hook_su0147_term", "bc_EventDamage L%d: Class Strength term big_mult -> record it" % ln)
        ed += e; hooks.append(h)
        e, h = call_hook_shared(mul_site, 0x1402e05e0, "hook_su0147_braze", "bc_EventDamage L%d: Braze amount x 0.5 -> recorded term x 0.5" % (ln + 2))
        ed += e; hooks.append(h)
    return patch("SU-0147", "Braze: your creatures' Class Strength Artifact properties deal 50% more damage (code: a flat +50% of the hit for "
                 "any creature with an Artifact, property or not)", ed, hooks)


def su0058():
    ed, hooks = [], []
    for term_site, mul_site, ln in ((0x140df62be, 0x140df6791, 1818), (0x140df6e55, 0x140df7328, 1824), (0x140df79ec, 0x140df7ebf, 1830),
                                    (0x140df8583, 0x140df8a56, 1836), (0x140df911a, 0x140df95ed, 1842)):
        e, h = call_hook_shared(term_site, 0x1417a2e70, "hook_su0058_term", "bc_EventDamage L%d: Class Strength reduction big_mult -> record it" % ln)
        ed += e; hooks.append(h)
        e, h = call_hook_shared(mul_site, 0x1402e05e0, "hook_su0058_unbreakable", "bc_EventDamage L%d: Unbreakable amount x 0.5 -> recorded term x 0.5" % (ln + 2))
        ed += e; hooks.append(h)
    return patch("SU-0058", "Unbreakable: your creatures' Class Strength Artifact properties prevent 50% more damage (code: a flat extra 50% "
                 "reduction for any creature with an Artifact, property or not)", ed, hooks)


def su0149():
    e1, h1 = call_hook(0x14175e6c6, 0x14028c630, "hook_su0149_max", "bc_StartupStatGain L1474: Max Health += total -> Max Health = total")
    e2, h2 = call_hook(0x14175e77b, 0x14028c630, "hook_su0149_hp", "bc_StartupStatGain L1475: Health += total -> += total - own Max Health")
    return patch("SU-0149", "Diabolic Link: each Diabolic Horde gets the others' Maximum Health (code also added its own again, so a lone one "
                 "ended at 50% instead of 25%)", e1 + e2, [h1, h2])


def su0043():
    """Cloak of Shadows, Immobility, Enchanted Arrows: once per turn. Their blocks (bc_CreatureStartOfTurn L327-L354,
    0x140b373de..0x140b396ce) sit inside the per-condition loop (L270, for i = 1 .. conditions[0]), so they ran once per
    condition the creature has, and never with none. They don't read the loop's state. The block has one entry (its
    top) and one exit (L358 @0x140b396ce); the loop has one real exit (jmp @0x140b341a9 -> 0x140b410a7). Inside the loop
    the block is now skipped; the loop exit sets FLAG and runs the block once; the block's exit, with FLAG set, clears
    it and continues where the loop used to exit. Frameless detours, no calls."""
    flag = _data[0]; _data[0] += 8
    B0, B1, EXIT = 0x140b373de, 0x140b396ce, 0x140b410a7
    ed = []
    ed += detour(B0, 11, lambda a: "  cmp byte ptr [%#x], 0\n  jne resume\n  jmp %#x\n" % (flag, B1),
                 "L327 (block top): inside the loop -> skip the block")
    ed += detour(B1, 11, lambda a: "  cmp byte ptr [%#x], 0\n  je resume\n  mov byte ptr [%#x], 0\n  jmp %#x\n" % (flag, flag, EXIT),
                 "L358 (block exit): after the once-per-turn run -> continue after the loop")
    a, e = cave(lambda a: "  mov byte ptr [%#x], 1\n  jmp %#x\n" % (flag, B0), "loop exit: run the block once")
    ed += e
    ed.append(edit(0x140b341a9, exe(0x140b341a9, 5), asm("jmp %#x" % a, 0x140b341a9), "L270 loop exit: -> once-per-turn block run"))
    return patch("SU-0043", "Cloak of Shadows, Immobility, Enchanted Arrows: activate once per turn (code: once per condition the creature had, "
                 "and never with none)", ed)


def su0160():
    ed = [edit(0x140b24619, bytes.fromhex("7474"), bytes.fromhex("eb74"), "bc_CreatureStartOfTurn L93: Grandiose +3 at the start of the turn -> skipped")]
    hooks = []
    for site in (0x1408b6260, 0x1469d1c59, 0x1469d1e78, 0x1469d21c0, 0x1469d23d9, 0x1469d6407, 0x1469d64fa, 0x1469d65ed):
        e, h = call_hook_shared(site, 0x140ab2ad0, "hook_su0160_end_of_turn", "bc_CreatureEndOfTurn call -> Grandiose +3 first")
        ed += e; hooks.append(h)
    return patch("SU-0160", "Grandiose: the +3 turn counter comes at the end of your creatures' turns, as the text says (code: at the start)",
                 ed, hooks)


FIXES = [su0038, su0040, su0071, su0115, su0148, su0161, su0016, su0165, su0023, su0047, su0057, su0147, su0058, su0149, su0043, su0160]


def main():
    out = {"patches": []}
    for f in FIXES:
        out["patches"].append(f())
    # overlap check inside this batch
    seen = set()
    for p in out["patches"]:
        for e in p["edits"]:
            a = int(e["va"], 16)
            for x in range(a, a + len(bytes.fromhex(e["expect"]))):
                assert x not in seen, "%s overlaps at %#x" % (p["id"], x)
                seen.add(x)
    json.dump(out, open(OUT, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
    print("hooks_C.json: %d patches, %d edits; code used to %#x, data to %#x" % (
        len(out["patches"]), sum(len(p["edits"]) for p in out["patches"]), _code[0], _data[0]))


if __name__ == "__main__":
    main()


def show():
    """Disassemble this batch's cave code as one stream, plus every game-side edit."""
    d = json.load(open(OUT, encoding="utf-8"))
    cav = {}
    for p in d["patches"]:
        for e in p["edits"]:
            a = int(e["va"], 16)
            if CODE_LO <= a < CODE_HI:
                cav[a] = bytes.fromhex(e["write"])
            else:
                for i in md.disasm(bytes.fromhex(e["write"]), a):
                    print("%s game %#x %-22s %s %s" % (p["id"], i.address, i.bytes.hex(), i.mnemonic, i.op_str))
    if cav:
        lo = min(cav); buf = bytearray(max(a + len(b) for a, b in cav.items()) - lo)
        for a, b in cav.items():
            buf[a - lo:a - lo + len(b)] = b
        for i in md.disasm(bytes(buf), lo):
            if i.bytes != b"\x00\x00":
                print("cave %#x %-26s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))


if len(sys.argv) > 1 and sys.argv[1] == "show":
    show()
