"""Build research/hooks_H.json: heavy batch H. SU-0055 (redirected attacks use the interceptor's Defense) and SU-0136
(Fleshripper rank 50 deals a real Bleed tick). See loader/hooks_H.c. Both patches are group "heavy".
Verifies every expect byte, call target and jump-safety assumption against the exe. Assigned space only:
code 0x1488bfcd8-0x1488bfdff (zero tail of the .text page), data 0x149ed86f0-0x149ed87ff (.data BSS)."""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x1488bfcd8, 0x1488bfdff, 0x149ed86f0, 0x149ed87ff
# data (must match loader/hooks_H.c)
H_ACTIVE, H_REPLAY, H_SAVED = 0x149ed86f0, 0x149ed86f8, 0x149ed8700     # SU-0055 state (qwords)
H_SLOT_DMG, H_SLOT_ADD = 0x149ed8708, 0x149ed8710                       # SU-0136 hook pointers
H_SKIP, H_DEPTH = 0x149ed8718, 0x149ed871c                              # SU-0136 ints
MAGIC = 0x53550136                                                      # bleed-only argc for bc_CreatureStartOfTurn
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()

# ---- SU-0055: bc_CreatureAttack (line slot [rsp+0x40], 8-byte markers)
CA_SLOT = 0x40
L182, L407, L448, L478, L696 = 0x1406a8827, 0x1406b5f6e, 0x1406b867a, 0x1406b9e84, 0x1406c1f54
CA_TARGET = 0x98                                                        # target RValue local
# ---- SU-0136: bc_CreatureStartOfTurn (line slot [rsp+0x25d20], 11-byte markers), bc_OnAttack rank-50 site
SOT = 0x140b204e0
SOT_L2, SOT_L3, SOT_L1059, SOT_L1083, SOT_L1096, SOT_L1252 = 0x140b22374, 0x140b2237f, 0x140b6cb0b, 0x140b6d8fe, 0x140b6edfa, 0x140b79759
SOT_EPILOGUE = 0x140cc1a2f                                              # after L5387: ret value + destructors
SOT_ARGC = 0x26068                                                      # r9d home slot after `sub rsp, 0x26048`
DMG_SITE, DMG_FN = 0x141346d90, 0x140cda820                             # bc_OnAttack L1427 bc_EventDamage
ADD_SITE, ADD_FN = 0x141346e1f, 0x141ef3830                             # bc_OnAttack L1427 scr_AddEventToStack

FLAG_READ = re.compile(r"^(j(?!mp)|set|cmov|adc|sbb|pushf|lahf)")
FLAG_WRITE = {"cmp", "test", "add", "sub", "and", "or", "xor", "inc", "dec", "neg", "shl", "shr", "sar", "imul", "popf", "sahf"}


def marker(va, slot, line):
    """The GML line marker `mov dword ptr [rsp+slot], line` at va; returns its bytes."""
    i = S.disasm(va, va + 16)[0]
    dst, _, imm = i.op_str.partition(", ")
    assert i.mnemonic == "mov" and dst == "dword ptr [rsp + %#x]" % slot and int(imm, 0) == line, (hex(va), i.op_str)
    return bytes(i.bytes)


def flags_dead(va):
    """Flags are not read at va before being written (our stubs clobber them)."""
    for i in S.disasm(va, va + 160):
        if FLAG_READ.match(i.mnemonic):
            raise SystemExit("flags live at %#x (%s %s)" % (va, i.mnemonic, i.op_str))
        if i.mnemonic in FLAG_WRITE or i.mnemonic in ("call", "ret") or i.mnemonic == "jmp":
            return


def detour(site, size, stub_at, note):
    b = S.pe.get_data(site - S.BASE, size)
    return {"va": hex(site), "expect": b.hex(), "write": "e9" + le(stub_at - (site + 5)) + "90" * (size - 5), "note": note}


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def jumps(lo, hi):
    out = []
    for i in S.disasm(lo, hi):
        if (i.mnemonic.startswith("j") or i.mnemonic == "call") and i.op_str.startswith("0x"):
            out.append((i.address, int(i.op_str, 16), i.mnemonic))
    return out


def check_su0055():
    fn_lo, fn_hi = S.func_range("bc_CreatureAttack")
    for va, ln in [(L182, 182), (L407, 407), (L448, 448), (L478, 478), (L696, 696)]:
        assert len(marker(va, CA_SLOT, ln)) == 8
        flags_dead(va + 8)
    flags_dead(L448)
    J = jumps(fn_lo, fn_hi)
    # the replay segments run straight to the next detour: no jump leaves them
    for lo, hi in [(L182, L407), (L448, L478)]:
        for a, t, m in J:
            if lo <= a < hi and m != "call":
                assert lo <= t < hi or t in (L407, L478), "jump out of replay segment %#x -> %#x" % (a, t)
    # nothing jumps into the window [L182, L696) from outside except at L182, and nothing lands inside a patched marker
    for a, t, m in J:
        if m == "call":
            continue
        if not (L182 <= a < L696) and L182 < t < L696:
            raise SystemExit("jump into the window %#x -> %#x" % (a, t))
        for s in (L182, L407, L478, L696):
            assert not (s < t < s + 8), "jump into a patched marker %#x -> %#x" % (a, t)
    # no recursion inside the window (single global state)
    for a, t, m in J:
        if m == "call" and L182 <= a < L696:
            assert S.NAMES.get(t) not in ("bc_CreatureAttack", "bc_ExecuteEvents", "bc_OnAttack"), hex(a)


def check_su0136():
    fn_lo, fn_hi = S.func_range("bc_CreatureStartOfTurn")
    assert fn_lo == SOT
    for va, ln in [(SOT_L2, 2), (SOT_L3, 3), (SOT_L1059, 1059), (SOT_L1083, 1083), (SOT_L1096, 1096), (SOT_L1252, 1252)]:
        marker(va, 0x25d20, ln)
    assert SOT_L2 + 11 == SOT_L3                                        # the L2 store is overwritten at once by L3
    for va in (SOT_L3, SOT_L1059, SOT_L1096, SOT_L1083 + 11, SOT_L1252 + 11, SOT_EPILOGUE):
        flags_dead(va)
    e = S.disasm(SOT_EPILOGUE, SOT_EPILOGUE + 8)[0]
    assert e.mnemonic == "mov" and e.op_str == "rax, qword ptr [rsp + 0x26060]", e.op_str
    pro = S.disasm(SOT, SOT + 0x20)
    assert pro[0].op_str == "dword ptr [rsp + 0x20], r9d" and any(i.op_str == "eax, 0x26048" for i in pro)
    ins = S.disasm(fn_lo, fn_hi)
    assert not any("[rsp + %#x]" % SOT_ARGC in i.op_str or "[rsp + 0x26070]" in i.op_str for i in ins), "argc/args read"
    R = [(SOT_L1059, SOT_L1083), (SOT_L1096, SOT_L1252)]
    inr = lambda a: any(x <= a < y for x, y in R)
    for i in ins:
        if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if inr(i.address):
                assert inr(t) or t in (SOT_L1083, SOT_L1252), "jump out of the Bleed block %#x -> %#x" % (i.address, t)
            elif inr(t):
                assert t in (SOT_L1059, SOT_L1096), "jump into the Bleed block %#x -> %#x" % (i.address, t)
            for s in (SOT_L2, SOT_L1083, SOT_L1252):
                assert not (s < t < s + 11), "jump into a patched marker %#x -> %#x" % (i.address, t)
    # the subject is the global creatureturn, read through the pointer fetched in the prologue
    g = S.disasm(0x140b20603, 0x140b2061d)
    assert g[0].op_str == "edx, dword ptr [rip + 0x8ec190f]" and g[1].op_str == "rcx, qword ptr [rip + 0x8ed51b8]"
    assert int(g[2].op_str, 16) == 0x140297c10 and g[3].op_str == "qword ptr [rsp + 0xba58], rax"


def main():
    check_su0055()
    check_su0136()
    taken = []                                                          # every other patch's bytes
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_H.json"):
            continue
        for p in json.load(open(f, encoding="utf-8"))["patches"]:
            if p["id"] in ("SU-0055", "SU-0136"):                      # our own entries once merged into patches.json
                continue
            for e in p["edits"]:
                taken.append((int(e["va"], 16), int(e["va"], 16) + len(e["expect"]) // 2, p["id"]))
            for r in p.get("reserves", []):
                taken.append((int(r["start"], 16), int(r["end"], 16) + 1, p["id"]))
    b = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["build"]
    assert int(b["cave_start"], 16) <= CODE_LO and CODE_HI < int(b["cave_end"], 16), "code range outside the .text cave"

    at = [CODE_LO]

    def put(src, note):
        code = asm(src, at[0])
        lo = at[0]; at[0] += len(code)
        assert at[0] - 1 <= CODE_HI, "code range full at %s (%d bytes over)" % (note, at[0] - 1 - CODE_HI)
        return lo, code

    F = dict(active=H_ACTIVE, replay=H_REPLAY, saved=H_SAVED, slot=CA_SLOT, tgt=CA_TARGET, tgt8=CA_TARGET + 8)

    # ---- SU-0055
    e, rv = [], []
    d0, c = put("""
        cmp qword ptr [{replay:#x}], rsp
        je go
        mov qword ptr [{active:#x}], rsp
        push qword ptr [rsp + {tgt:#x}]
        pop qword ptr [{saved:#x}]
    go:
        mov dword ptr [rsp + {slot:#x}], 0xb6
        jmp {nxt:#x}""".format(nxt=L182 + 8, **F), "D0")
    e += chunks(d0, c, "SU-0055 D0 (L182): record the first target, or let the replay pass through")
    rv.append(res(d0, len(c), "SU-0055 D0 stub (L182)"))
    d1, c = put("""
        cmp qword ptr [{replay:#x}], rsp
        je {l448:#x}
        mov dword ptr [rsp + {slot:#x}], 0x197
        jmp {nxt:#x}""".format(l448=L448, nxt=L407 + 8, **F), "D1")
    e += chunks(d1, c, "SU-0055 D1 (L407): the replay pass skips L407-L447 (Hoodwink / Invisible re-target, already done)")
    rv.append(res(d1, len(c), "SU-0055 D1 stub (L407)"))
    d2, c = put("""
        cmp qword ptr [{replay:#x}], rsp
        jne orig
        and qword ptr [{replay:#x}], 0
        mov dword ptr [rsp + {slot:#x}], 0x2b8
        jmp {after696:#x}
    orig:
        mov dword ptr [rsp + {slot:#x}], 0x1de
        jmp {nxt:#x}""".format(after696=L696 + 8, nxt=L478 + 8, **F), "D2")
    e += chunks(d2, c, "SU-0055 D2 (L478): the replay pass ends here and skips the intercepts (already resolved)")
    rv.append(res(d2, len(c), "SU-0055 D2 stub (L478)"))
    d3, c = put("""
        cmp qword ptr [{active:#x}], rsp
        jne done
        and qword ptr [{active:#x}], 0
        push rax
        mov rax, qword ptr [rsp + {tgt8:#x}]
        cmp rax, qword ptr [{saved:#x}]
        pop rax
        je done
        mov qword ptr [{replay:#x}], rsp
        jmp {l182:#x}
    done:
        mov dword ptr [rsp + {slot:#x}], 0x2b8
        jmp {nxt:#x}""".format(l182=L182, nxt=L696 + 8, **F), "D3")
    e += chunks(d3, c, "SU-0055 D3 (L696): target changed by an intercept -> re-run L182-L476 for the new target")
    rv.append(res(d3, len(c), "SU-0055 D3 stub (L696)"))
    e += [detour(L182, 8, d0, "bc_CreatureAttack L182 marker -> SU-0055 D0"),
          detour(L407, 8, d1, "bc_CreatureAttack L407 marker -> SU-0055 D1"),
          detour(L478, 8, d2, "bc_CreatureAttack L478 marker -> SU-0055 D2"),
          detour(L696, 8, d3, "bc_CreatureAttack L696 marker -> SU-0055 D3")]
    rv += [res(H_ACTIVE, 8, "SU-0055 frame (rsp) of the attack being resolved"),
           res(H_REPLAY, 8, "SU-0055 frame (rsp) in the replay pass"),
           res(H_SAVED, 8, "SU-0055 first target value")]
    su0055 = {"id": "SU-0055", "bug": "SU-0055", "default": 1, "group": "heavy",
              "title": "Redirected attacks (Guardian, Vigilance, Pocket Tank, Provoke and the other intercepts) are "
                       "computed with the interceptor's Defense (code: the first target's)",
              "edits": e, "runtime_hooks": [], "reserves": rv}

    # ---- SU-0136
    e, rv = [], []
    G = dict(argc=SOT_ARGC, magic=MAGIC)
    t1, c = put("jmp qword ptr [%#x]" % H_SLOT_DMG, "T1")
    e += chunks(t1, c, "trampoline -> hook_h_su0136_damage"); rv.append(res(t1, len(c), "trampoline -> hook_h_su0136_damage"))
    t2, c = put("jmp qword ptr [%#x]" % H_SLOT_ADD, "T2")
    e += chunks(t2, c, "trampoline -> hook_h_su0136_addevent"); rv.append(res(t2, len(c), "trampoline -> hook_h_su0136_addevent"))
    # The skipped L3-L1058 is where the two iterator locals [rsp+0x25d28] / [rsp+0x25d48] are constructed; the epilogue
    # destructor (0x1402f41b0) frees their +0x10 pointer when non-zero, so clear it as an unconstructed iterator would be.
    s1, c = put("""
        cmp dword ptr [rsp + {argc:#x}], {magic:#x}
        jne {l3:#x}
        and qword ptr [rsp + 0x25d38], 0
        and qword ptr [rsp + 0x25d58], 0
        jmp {l1059:#x}""".format(l1059=SOT_L1059, l3=SOT_L3, **G), "S1")
    e += chunks(s1, c, "SU-0136 S1 (start of turn L2): bleed-only call -> the Bleed tick count (L1059)")
    rv.append(res(s1, len(c), "SU-0136 S1 stub (L2)"))
    s2, c = put("""
        cmp dword ptr [rsp + {argc:#x}], {magic:#x}
        je {l1096:#x}
        mov dword ptr [rsp + 0x25d20], 0x43b
        jmp {nxt:#x}""".format(l1096=SOT_L1096, nxt=SOT_L1083 + 11, **G), "S2")
    e += chunks(s2, c, "SU-0136 S2 (start of turn L1083): bleed-only call skips L1083-L1095 (not Bleed)")
    rv.append(res(s2, len(c), "SU-0136 S2 stub (L1083)"))
    s3, c = put("""
        cmp dword ptr [rsp + {argc:#x}], {magic:#x}
        je {epi:#x}
        mov dword ptr [rsp + 0x25d20], 0x4e4
        jmp {nxt:#x}""".format(epi=SOT_EPILOGUE, nxt=SOT_L1252 + 11, **G), "S3")
    e += chunks(s3, c, "SU-0136 S3 (start of turn L1252): bleed-only call returns after the Bleed tick")
    rv.append(res(s3, len(c), "SU-0136 S3 stub (L1252)"))
    e += [detour(SOT_L2, 11, s1, "bc_CreatureStartOfTurn L2 marker -> SU-0136 S1"),
          detour(SOT_L1083, 11, s2, "bc_CreatureStartOfTurn L1083 marker -> SU-0136 S2"),
          detour(SOT_L1252, 11, s3, "bc_CreatureStartOfTurn L1252 marker -> SU-0136 S3"),
          call_redirect(DMG_SITE, DMG_FN, t1, "bc_OnAttack L1427 Fleshripper rank 50 bc_EventDamage -> hook: run one Bleed tick"),
          call_redirect(ADD_SITE, ADD_FN, t2, "bc_OnAttack L1427 scr_AddEventToStack -> hook: skip when the tick replaced the hit")]
    rv += [res(H_SLOT_DMG, 8, "hook pointer hook_h_su0136_damage"), res(H_SLOT_ADD, 8, "hook pointer hook_h_su0136_addevent"),
           res(H_SKIP, 4, "SU-0136 skip-the-push flag"), res(H_DEPTH, 4, "SU-0136 nesting depth")]
    su0136 = {"id": "SU-0136", "bug": "SU-0136", "default": 1, "group": "heavy",
              "title": "Fleshripper rank 50: the extra damage is a real Bleed tick, so every Bleed-damage modifier and "
                       "reaction applies (code: a plain hit of the Bleed amount)",
              "edits": e, "runtime_hooks": [{"slot_va": hex(H_SLOT_DMG), "symbol": "hook_h_su0136_damage"},
                                            {"slot_va": hex(H_SLOT_ADD), "symbol": "hook_h_su0136_addevent"}],
              "reserves": rv}

    # space and overlap
    for p in (su0055, su0136):
        for r in p["reserves"]:
            lo, hi = int(r["start"], 16), int(r["end"], 16)
            assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), r
        for x in [(int(r["start"], 16), int(r["end"], 16) + 1) for r in p["reserves"]] + \
                 [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in p["edits"]]:
            for lo, hi, pid in taken:
                assert x[1] <= lo or hi <= x[0], "%s %#x overlaps %s" % (p["id"], x[0], pid)
    json.dump({"patches": [su0055, su0136]}, open(os.path.join(HERE, "hooks_H.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_H.json: 2 patches; code %#x-%#x (%d of %d bytes)" % (CODE_LO, at[0] - 1, at[0] - CODE_LO, CODE_HI - CODE_LO + 1))
    for name, a in [("D0", d0), ("D1", d1), ("D2", d2), ("D3", d3), ("T1", t1), ("T2", t2), ("S1", s1), ("S2", s2), ("S3", s3)]:
        print(" ", name, hex(a))


if __name__ == "__main__":
    main()
