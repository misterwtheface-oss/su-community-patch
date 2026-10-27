"""Build research/hooks_I.json: errata round 2, batch I (damage pipeline). See loader/hooks_I.c.

  SU-0297 Ravish            : bc_EventDamage L7050 scr_CritHasPassive(creature, 1100) -> hook (enemy source only)
  SU-0270 Father Shadow     : bc_EventDamage L6547 scr_CritHasPassive(source, 1300)   -> hook (enemy target only)
  SU-0303 Savior            : bc_EventDamage L7149 / L7154 / L7158 Any*HasPassive(66) -> hook (a holder other than the
                              damaged creature)
  SU-0267 Emerald Attunement: bc_EventDamage L4306-L4312, the ally-side +50% runs only when the enemy side's didn't
  SU-0225 Materium rank 30  : bc_EventDamage L4005 Any*HasPassive(1167) -> hook (strong hits on the bearer end as if the
                              bearer were strong, like the game's own neutral-hit handling at L3995-L3997)
  SU-0260 Defer Pain        : bc_EventDamage L6110 `creature != creatureturn` -> hook (only the release hit is exempt)
  SU-0290 Mesmer            : bc_EventDamage L6909-L6917 class targets -> the Quantum Flux mapping (user ruling)
  SU-0178 I HATE YOU !@#$ING ALL: both `slot > 0` side tests dropped, holder test by the creature's own side (hook)

Verifies every expect byte, call target, constant and jump assumption against the exe. Assigned space only:
code 0x14a343100-0x14a3434ff (xcave), data 0x149ed88d0-0x149ed894f (.data tail).
"""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x14a343100, 0x14a3434ff, 0x149ed88d0, 0x149ed894f
OWN = ("SU-0297", "SU-0270", "SU-0303", "SU-0267", "SU-0225", "SU-0260", "SU-0290", "SU-0178")
# hook slots (must match loader/hooks_I.c)
SLOT = {"0297": 0x149ed88d0, "0270": 0x149ed88d8, "0303e": 0x149ed88e0, "0303a": 0x149ed88e8,
        "0225e": 0x149ed88f0, "0225a": 0x149ed88f8, "0260": 0x149ed8900, "0178d": 0x149ed8908, "0178t": 0x149ed8910}

HAS_PASSIVE, ANY_ALLY, ANY_ENEMY = 0x14202c2c0, 0x141f0a8a0, 0x141f0b2d0
HAS_RELIC_PERK, NE, EVENT_DAMAGE = 0x14202d600, 0x1402954d0, 0x140cda820
ED_LINE = "dword ptr [rsp + 0x30178]"                                   # bc_EventDamage line slot
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
ED = S.func_range("bc_EventDamage")
EOT = S.func_range("bc_CreatureEndOfTurn")
SOT = S.func_range("bc_CreatureStartOfTurn")


def ins_from(lo, hi):
    return S.disasm(lo, hi)


def marker(va, slot, line):
    i = S.disasm(va, va + 16)[0]
    dst, _, imm = i.op_str.partition(", ")
    assert i.mnemonic == "mov" and dst == slot and int(imm, 0) == line, (hex(va), i.op_str)
    return i


def rip_target(i):
    m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
    return i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)


def check_call(mark, line, site, callee, ident=None, argc=None, slot=ED_LINE):
    """site is an instruction boundary reached from the GML line marker, calls callee; the last rip constant loaded
    into rdx before it is the id (gate scripts), and r9d holds argc."""
    marker(mark, slot, line)
    seq = ins_from(mark, site + 5)
    assert seq[-1].address == site, "%#x not an instruction boundary from %#x" % (site, mark)
    c = seq[-1]
    assert c.mnemonic == "call" and int(c.op_str, 16) == callee, (hex(site), c.op_str)
    if ident is not None:
        ids = [S.const_at(rip_target(i)) for i in seq if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip")]
        assert ids and ids[-1] == float(ident), (hex(site), ids)
    if argc is not None:
        r9 = [i for i in seq if i.mnemonic == "mov" and i.op_str.startswith("r9d, ")]
        assert r9 and int(r9[-1].op_str.split(", ")[1], 0) == argc, (hex(site), r9[-1].op_str if r9 else None)
    return seq


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def raw(va, expect_hex, write_hex, note):
    assert S.pe.get_data(va - S.BASE, len(expect_hex) // 2).hex() == expect_hex, (hex(va), expect_hex)
    assert len(expect_hex) == len(write_hex)
    return {"va": hex(va), "expect": expect_hex, "write": write_hex, "note": note}


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def jumps(lo, hi):
    out = []
    for i in S.disasm(lo, hi):
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            out.append((i.address, int(i.op_str, 16), i.mnemonic))
    return out


def side_gate(mark, line, slot_read_call, je_va, je_target, slot=ED_LINE):
    """`creature.slot > 0` at the start of the gate: the >int call with edx = 0, then je to the gate's false merge."""
    seq = ins_from(mark, je_va + 6)
    assert seq[-1].address == je_va and seq[-1].mnemonic == "je" and int(seq[-1].op_str, 16) == je_target
    gt = [i for i in seq if i.mnemonic == "call"]
    assert int(gt[-1].op_str, 16) == 0x14028ca10 and gt[-1].address == slot_read_call, hex(gt[-1].address)
    vg = [i for i in seq if i.mnemonic == "mov" and i.op_str.startswith("edx, dword ptr [rip")]
    assert rip_target(vg[-1]) == 0x1499e0aa8, "not the slot variable"            # creature.slot
    assert any(i.mnemonic == "xor" and i.op_str == "edx, edx" for i in seq[-6:]), "not `> 0`"
    return S.pe.get_data(je_va - S.BASE, 6).hex()


def main():
    taken = []
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_I.json"):
            continue
        for p in json.load(open(f, encoding="utf-8"))["patches"]:
            if p["id"] in OWN:
                continue
            for e in p["edits"]:
                taken.append((int(e["va"], 16), int(e["va"], 16) + len(e["expect"]) // 2, p["id"]))
            for r in p.get("reserves", []):
                taken.append((int(r["start"], 16), int(r["end"], 16) + 1, p["id"]))
    b = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["build"]
    assert any(int(x["start"], 16) <= CODE_LO and CODE_HI < int(x["end"], 16) for x in b["xcaves"]), "code range not in an xcave"
    assert int(b["data_cave_start"], 16) <= DATA_LO and DATA_HI < int(b["data_cave_end"], 16), "data range outside the data cave"

    at = [CODE_LO]

    def tramp(key, sym):
        code = asm("jmp qword ptr [%#x]" % SLOT[key], at[0])
        lo = at[0]; at[0] += len(code)
        assert at[0] - 1 <= CODE_HI
        return lo, chunks(lo, code, "trampoline -> " + sym), res(lo, len(code), "trampoline -> " + sym), \
            res(SLOT[key], 8, "hook pointer " + sym), {"slot_va": hex(SLOT[key]), "symbol": sym}

    patches = []

    def patch(pid, title, edits, reserves, hooks):
        patches.append({"id": pid, "bug": pid, "default": 1, "title": title, "edits": edits, "reserves": reserves,
                        "runtime_hooks": hooks})

    # ---- SU-0297 Ravish (L7050: source > -1 && HasPassive(creature, 1100) && amount > 0)
    check_call(0x140f707d5, 7050, 0x140f70a0e, HAS_PASSIVE, 1100, 2)
    t, e, r1, r2, h = tramp("0297", "hook_i_su0297_ravish")
    patch("SU-0297", "Ravish hits back only when the damage came from an enemy (code: any source, allies and itself "
          "included)", e + [call_redirect(0x140f70a0e, HAS_PASSIVE, t, "bc_EventDamage L7050 scr_CritHasPassive(creature, "
                                          "1100) -> hook: false when source and creature are on the same side")],
          [r1, r2], [h])

    # ---- SU-0270 Father Shadow (L6547: dtype > -1 && source > -1 && HasPassive(source, 1300) && amount > 0)
    check_call(0x140f2ccad, 6547, 0x140f2cf2e, HAS_PASSIVE, 1300, 2)
    t, e, r1, r2, h = tramp("0270", "hook_i_su0270_father")
    patch("SU-0270", "Father Shadow's extra hit follows only damage to an enemy (code: also damage to its own allies)",
          e + [call_redirect(0x140f2cf2e, HAS_PASSIVE, t, "bc_EventDamage L6547 scr_CritHasPassive(source, 1300) -> hook: "
                                                          "false when source and creature are on the same side")],
          [r1, r2], [h])

    # ---- SU-0303 Savior: four holder lookups (L7149 gate, L7154 / L7158 holder) on the damaged creature's side
    check_call(0x140f7c60e, 7149, 0x140f7c7f4, ANY_ENEMY, 66, 1)
    check_call(0x140f7c60e, 7149, 0x140f7c9f4, ANY_ALLY, 66, 1)
    check_call(0x140f7cd02, 7154, 0x140f7ce68, ANY_ENEMY, 66, 1)
    check_call(0x140f7ce8d, 7158, 0x140f7cff3, ANY_ALLY, 66, 1)
    # L7149 tests slot == 0 before the enemy lookup and slot > 0 before the ally lookup; the halving follows at L7151
    seq = ins_from(0x140f7ca27, 0x140f7cc4b)
    assert int(seq[-1].op_str, 16) == 0x1417a2e70 and S.const_at(0x1498e9e80) == 0.5
    # L7160 holder != creature skips the forward (je @0x140f7d058)
    assert S.disasm(0x140f7d04e, 0x140f7d05e)[-1].op_str == "0x140f7d98b"
    te, ee, re1, re2, he = tramp("0303e", "hook_i_su0303_enemy")
    ta, ea, ra1, ra2, ha = tramp("0303a", "hook_i_su0303_ally")
    patch("SU-0303", "Savior takes half of the damage dealt to your other creatures and no longer halves the damage "
          "dealt to itself (code: halved every hit on its side before checking who was hit)",
          ee + ea + [call_redirect(0x140f7c7f4, ANY_ENEMY, te, "bc_EventDamage L7149 scr_AnyEnemyHasPassive(66) -> hook: a holder other than the damaged creature"),
                     call_redirect(0x140f7c9f4, ANY_ALLY, ta, "bc_EventDamage L7149 scr_AnyAllyHasPassive(66) -> hook: a holder other than the damaged creature"),
                     call_redirect(0x140f7ce68, ANY_ENEMY, te, "bc_EventDamage L7154 scr_AnyEnemyHasPassive(66) -> hook (holder)"),
                     call_redirect(0x140f7cff3, ANY_ALLY, ta, "bc_EventDamage L7158 scr_AnyAllyHasPassive(66) -> hook (holder)")],
          [re1, re2, ra1, ra2], [he, ha])

    # ---- SU-0267 Emerald Attunement: L4306 enemy side +50% / L4310 ally side +50%, now one or the other
    JE_ENEMY, L4310, L4310_END, L4316 = 0x140e7fca1, 0x140e7feb0, 0x140e7febb, 0x140e80244
    check_call(0x140e7fb1c, 4306, 0x140e7fc82, ANY_ENEMY, 44, 1)
    check_call(L4310, 4310, 0x140e80016, ANY_ALLY, 44, 1)
    marker(L4316, ED_LINE, 4316)
    assert S.disasm(L4310, L4310 + 11)[0].size == 11
    j = S.disasm(JE_ENEMY, JE_ENEMY + 6)[0]
    assert j.mnemonic == "je" and int(j.op_str, 16) == L4310
    # nothing outside [L4310, L4316) jumps into it except the enemy gate's je; nothing lands inside the marker store
    for a, tgt, m in jumps(*ED):
        if L4310 < tgt < L4316 and not (L4310 <= a < L4316):
            raise SystemExit("jump into the Emerald ally block %#x -> %#x" % (a, tgt))
        assert not (L4310 < tgt < L4310_END), "jump into the L4310 marker %#x" % a
        if tgt == L4310:
            assert a == JE_ENEMY, "another jump to L4310 %#x" % a
    for a, tgt, m in jumps(L4310, L4316):
        assert L4310 <= tgt < L4316 or tgt == L4316, "jump out of the ally block %#x -> %#x" % (a, tgt)
    jmp = asm("jmp %#x" % L4316, L4310)
    assert len(jmp) == 5
    patch("SU-0267", "Emerald Attunement does not stack: one +50% even when both sides have it (code: +50% per side, "
          "+100% with both)",
          [raw(JE_ENEMY, "0f8409020000", "0f84" + le(L4310_END - (JE_ENEMY + 6)),
               "bc_EventDamage L4306: enemy side without it -> the ally-side block, past its line marker"),
           raw(L4310, S.pe.get_data(L4310 - S.BASE, 11).hex(), (jmp + b"\x90" * 6).hex(),
               "bc_EventDamage L4310 marker: reached only after the enemy side's +50% -> skip the ally side's (L4316)")],
          [], [])

    # ---- SU-0225 Materium rank 30: the Details Matter gate lookups at L4005 (one of the two runs for every hit)
    marker(0x140e6c36c, ED_LINE, 3951)
    assert int(S.disasm(0x140e6c3b9, 0x140e6c3bf)[0].op_str, 16) == 0x140e6e02e          # strength != -1 -> L4005
    check_call(0x140e6db19, 3995, 0x140e6dd59, HAS_RELIC_PERK, 3, 3)                      # rank 30 (relic 15, perk 3)
    assert S.const_at(0x1498eb8d0) == 15.0 and S.const_at(0x1498eb980) == 3.0
    check_call(0x140e6e02e, 4005, 0x140e6e214, ANY_ENEMY, 1167, 1)
    check_call(0x140e6e02e, 4005, 0x140e6e414, ANY_ALLY, 1167, 1)
    seq = ins_from(0x140e6e02e, 0x140e6e214)                                              # slot == 0 before the enemy lookup
    assert any(i.mnemonic == "call" and int(i.op_str, 16) == 0x14028c8f0 for i in seq)
    te, ee, re1, re2, he = tramp("0225e", "hook_i_su0225_enemy")
    ta, ea, ra1, ra2, ha = tramp("0225a", "hook_i_su0225_ally")
    patch("SU-0225", "Materium, Shifting Gem of Aurum rank 30: hits from a class strong against the bearer also end as "
          "if the bearer were strong (code: they still dealt double damage)",
          ee + ea + [call_redirect(0x140e6e214, ANY_ENEMY, te, "bc_EventDamage L4005 scr_AnyEnemyHasPassive(1167) -> hook: Materium rank 30 on a strong hit, then the lookup"),
                     call_redirect(0x140e6e414, ANY_ALLY, ta, "bc_EventDamage L4005 scr_AnyAllyHasPassive(1167) -> hook: Materium rank 30 on a strong hit, then the lookup")],
          [re1, re2, ra1, ra2], [he, ha])

    # ---- SU-0260 Defer Pain: L6110 `creature != creatureturn`
    seq = check_call(0x140f00955, 6110, 0x140f00be1, NE)
    assert seq[-2].op_str == "rcx, [rsp + 0x21fd8]" and seq[-3].op_str == "rdx, qword ptr [rsp + 0xe700]"
    check_call(0x140f00955, 6110, 0x140f00b46, HAS_PASSIVE, 501, 2)
    # release: bc_CreatureStartOfTurn L1927 bc_EventDamage(-1, creature, pain, ...) is called directly; its return
    # address is what the hook looks for at [bc_EventDamage frame + 0x30488]
    check_call(0x140bb0bea, 1927, 0x140bb12f4, EVENT_DAMAGE, slot="dword ptr [rsp + 0x25d20]")
    pro = S.disasm(EVENT_DAMAGE, EVENT_DAMAGE + 0x24)
    assert [i.op_str for i in pro[4:7]] == ["eax, 0x30488", "0x147cb31d0", "rsp, rax"], [i.op_str for i in pro[4:7]]
    assert pro[0].op_str == "dword ptr [rsp + 0x20], r9d" and pro[3].op_str == "qword ptr [rsp + 8], rcx"
    assert all("rsp" not in i.op_str or i.mnemonic != "push" for i in pro)
    for lo, hi, pid in taken:                                                             # nobody wraps the release call
        assert hi <= 0x140bb12f4 or 0x140bb12f9 <= lo, "release call patched by %s" % pid
    t, e, r1, r2, h = tramp("0260", "hook_i_su0260_turn_ne")
    patch("SU-0260", "Defer Pain also delays damage taken during the holder's own turn; only the delayed damage coming "
          "back is exempt (code: nothing taken on its own turn was delayed)",
          e + [call_redirect(0x140f00be1, NE, t, "bc_EventDamage L6110 creature != creatureturn -> hook: true unless this is "
                                                 "the Defer Pain release hit")], [r1, r2], [h])

    # ---- SU-0290 Mesmer: the five class targets take Quantum Flux's mapping (the class strong against the holder)
    def branches(l0, l1):
        lo = marker(l0, ED_LINE, {0x140f6083e: 6907, 0x140f62655: 6925}[l0]).address
        out = [(i.address, rip_target(i)) for i in ins_from(lo, l1)
               if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip") and 0x149d5f000 <= rip_target(i) < 0x149d61000]
        assert len(out) == 11 and out[0][1] == 0x149d60830, out
        return out[1:]
    mes = branches(0x140f6083e, 0x140f619e2)
    qf = branches(0x140f62655, 0x140f637f9)
    qmap = {qf[k][1]: qf[k + 1][1] for k in range(0, 10, 2)}
    assert set(qmap) == {mes[k][1] for k in range(0, 10, 2)}
    check_call(0x140f60595, 6906, 0x140f607ce, HAS_PASSIVE, 1168, 2)
    me = []
    for k in range(0, 10, 2):
        cls, (va, old) = mes[k][1], mes[k + 1]
        new = qmap[cls]
        assert new != old
        b0 = S.pe.get_data(va - S.BASE, 7)
        assert b0[:3] == bytes.fromhex("488d15")
        me.append({"va": hex(va + 3), "expect": le(old - (va + 7)), "write": le(new - (va + 7)),
                   "note": "bc_EventDamage Mesmer: class key %#x -> %#x (as Quantum Flux maps the holder's class %#x)" % (old, new, cls)})
    patch("SU-0290", "Mesmer changes the enemy's class to the holder's class weakness, the class strong against the "
          "holder, as Quantum Flux reads the same words (code: the class the holder is strong against)", me, [], [])

    # ---- SU-0178 I HATE YOU !@#$ING ALL: both gates `slot > 0 && ... AnyAllyHasPassive(610)`
    ex1 = side_gate(0x140e1c501, 2528, 0x140e1c574, 0x140e1c57e, 0x140e1c7a9)
    check_call(0x140e1c501, 2528, 0x140e1c795, ANY_ALLY, 610, 1)
    ex2 = side_gate(0x140b07828, 1310, 0x140b0786a, 0x140b07874, 0x140b079e3, slot="dword ptr [rsp + 0x40]")
    seq = check_call(0x140b07828, 1310, 0x140b079cf, ANY_ALLY, 610, 1, slot="dword ptr [rsp + 0x40]")
    assert any(i.op_str == "rcx, qword ptr [rsp + 0x48]" for i in seq[:12]), "slot read is not on [rsp+0x48]"
    # [rsp+0x48] = the global creatureturn, fetched in the prologue and never rewritten
    eot = S.disasm(*EOT)
    w48 = [i for i in eot if i.op_str.startswith("qword ptr [rsp + 0x48],")]
    assert len(w48) == 1 and w48[0].address == 0x140ab2b9d
    g = S.disasm(0x140ab2b8b, 0x140ab2ba2)
    assert rip_target(g[0]) == 0x1499e1f18 and int(g[2].op_str, 16) == 0x140297c10
    # the Provoke at L1312 is of the same creature
    seq = ins_from(0x140b079fb, 0x140b07bb2)
    assert int(seq[-1].op_str, 16) == 0x140b1cf30 and any(i.op_str == "rdx, qword ptr [rsp + 0x48]" for i in seq)
    td, ed, rd1, rd2, hd = tramp("0178d", "hook_i_su0178_damage")
    tt, et, rt1, rt2, ht = tramp("0178t", "hook_i_su0178_endturn")
    patch("SU-0178", "I HATE YOU !@#$ING ALL works for an enemy holder too: its team Provokes at the end of its turns "
          "and takes 90% less damage while Provoking (code: your side only)",
          ed + et + [raw(0x140e1c57e, ex1, "90" * 6, "bc_EventDamage L2528: drop the `creature.slot > 0` test"),
                     call_redirect(0x140e1c795, ANY_ALLY, td, "bc_EventDamage L2528 scr_AnyAllyHasPassive(610) -> hook: the damaged creature's own side"),
                     raw(0x140b07874, ex2, "90" * 6, "bc_CreatureEndOfTurn L1310: drop the `slot > 0` test"),
                     call_redirect(0x140b079cf, ANY_ALLY, tt, "bc_CreatureEndOfTurn L1310 scr_AnyAllyHasPassive(610) -> hook: the creature's own side")],
          [rd1, rd2, rt1, rt2], [hd, ht])

    # space and overlap
    seen = []
    for p in patches:
        for r in p["reserves"]:
            lo, hi = int(r["start"], 16), int(r["end"], 16)
            assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), r
        for x in [(int(r["start"], 16), int(r["end"], 16) + 1) for r in p["reserves"]] + \
                 [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in p["edits"]]:
            for lo, hi, pid in taken:
                assert x[1] <= lo or hi <= x[0], "%s %#x overlaps %s" % (p["id"], x[0], pid)
        for d in p["edits"]:
            x = (int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2)
            for lo, hi, pid in seen:
                assert x[1] <= lo or hi <= x[0], "%s %#x overlaps own %s" % (p["id"], x[0], pid)
            seen.append((x[0], x[1], p["id"]))
    json.dump({"patches": patches}, open(os.path.join(HERE, "hooks_I.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_I.json: %d patches; code %#x-%#x (%d of %d bytes); data %#x-%#x" % (
        len(patches), CODE_LO, at[0] - 1, at[0] - CODE_LO, CODE_HI - CODE_LO + 1, DATA_LO, max(SLOT.values()) + 7))


if __name__ == "__main__":
    main()
