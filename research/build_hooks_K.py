"""Build research/hooks_K.json: errata round 2, batch K (battle start, timeline, event execution). See loader/hooks_K.c.

  SU-0216 Forsaken Wonder   : the start-of-battle Relic buffs (bc_StartupBuffsDebuffs L877 / L883 / L895 / L907 / L913 /
                              L919 / L922) and Bloodseeker's 'always has' buffs (bc_MaintainPermanentEffects L675 / L681)
                              spread to your other creatures like in-battle Relic buffs; with the perks owned, the
                              start-of-battle Relic buffs (Forsaken Wonder) and Blazefury 40's Burning (L889, Primordial
                              Curse) last forever (closes SU-0080's 'partial')
  SU-0218 Photosynthesis    : every other scr_CritAddCondition call of bc_StartupBuffsDebuffs counts a buff / minion the
                              Herbling receives, like bc_OnBuffDebuff / bc_OnMinion do for in-battle grants
  SU-0206 Misery            : scr_CritAddCondition refuses buffs for your creatures (L46 realm 'Maximum Buffs' gate ->
                              the L51 refusal exit) while global.nemesis == 2
  SU-0219 Sacrifice x artifact Health: bc_StartupStatGain L1123 / L1124 swap their target variables (byte edits)
  SU-0183 Hymn of Panic     : bc_CreateCreatureList L196 / L200 sort keys -> uniform random key
  SU-0189 Lord Zantai       : bc_ExecuteEvents L1053 boss battle-type list gets 37
  SU-0310 Terminus          : bc_ExecuteEvents resurrect case L1312 also requires can_resurrect (with the queue-time
                              exemptions)
  SU-0204 realm 'Next battle' boosts: scr_RealmBoostExists no longer switches them off outside ordinary battles

Verifies every expect byte, call target, constant and jump / flags assumption against the exe. Assigned space only:
code 0x14a343900-0x14a343cff (xcave), data 0x149ed89d0-0x149ed8a4f (.data tail). python research/build_hooks_K.py
"""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x14a343900, 0x14a343cff, 0x149ed89d0, 0x149ed8a4f
OWN = ("SU-0216", "SU-0218", "SU-0206", "SU-0219", "SU-0183", "SU-0189", "SU-0310", "SU-0204")
# data (must match loader/hooks_K.c)
SLOT = {"189": 0x149ed89d0, "310": 0x149ed89d8, "183": 0x149ed89e0, "206": 0x149ed89e8,
        "216s": 0x149ed89f0, "216m": 0x149ed89f8, "218": 0x149ed8a00}
K_MISERY = 0x149ed8a08                                                  # byte: SU-0206 refusal armed (L46 -> L48)

ADD_COND, REALM_HAS_PROP, EQ_INT, LE_INT, GT_INT = 0x142015940, 0x146639f60, 0x14028c8f0, 0x1402bd5d0, 0x14028ca10
INT_SET, INT64_SET, VARGET, VARSET = 0x14028c530, 0x1402f41e0, 0x1478bbd70, 0x1478bc260
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
FLAG_READ = re.compile(r"^(j(?!mp)|set|cmov|adc|sbb|pushf|lahf)")
FLAG_WRITE = {"cmp", "test", "add", "sub", "and", "or", "xor", "inc", "dec", "neg", "shl", "shr", "sar", "imul", "popf", "sahf"}


def rip_target(i):
    m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
    return i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)


def ins_at(va):
    return S.disasm(va, va + 16)[0]


def marker(va, slot, line):
    i = ins_at(va)
    dst, _, imm = i.op_str.partition(", ")
    assert i.mnemonic == "mov" and dst == slot and int(imm, 0) == line, (hex(va), i.op_str)
    return i


def flags_dead(va):
    for i in S.disasm(va, va + 160):
        if FLAG_READ.match(i.mnemonic):
            raise SystemExit("flags live at %#x (%s %s)" % (va, i.mnemonic, i.op_str))
        if i.mnemonic in FLAG_WRITE or i.mnemonic in ("call", "ret", "jmp"):
            return


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def raw(va, expect_hex, write_hex, note):
    assert S.pe.get_data(va - S.BASE, len(expect_hex) // 2).hex() == expect_hex, (hex(va), expect_hex)
    assert len(expect_hex) == len(write_hex)
    return {"va": hex(va), "expect": expect_hex, "write": write_hex, "note": note}


def detour(site, size, stub_at, note):
    b = S.pe.get_data(site - S.BASE, size)
    return {"va": hex(site), "expect": b.hex(), "write": "e9" + le(stub_at - (site + 5)) + "90" * (size - 5), "note": note}


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def callers(target, fn):
    lo, hi = S.func_range(fn)
    data = S.pe.get_data(lo - S.BASE, hi - lo)
    out = []
    for m in re.finditer(b"\xe8", data):
        o = m.start()
        if o + 5 <= len(data) and lo + o + 5 + int.from_bytes(data[o + 1:o + 5], "little", signed=True) == target:
            out.append(lo + o)
    # keep only real instruction boundaries
    ins = {i.address for i in S.disasm(lo, hi)}
    return [a for a in out if a in ins]


def line_of(fn_lo, slot, site, ins_cache={}):
    """GML line of the marker that last precedes site (address order)."""
    if fn_lo not in ins_cache:
        lo, hi = S.func_range(S.NAMES[fn_lo])
        ins_cache[fn_lo] = S.disasm(lo, hi)
    ln = None
    for i in ins_cache[fn_lo]:
        if i.address >= site:
            break
        if i.mnemonic == "mov" and i.op_str.startswith(slot + ",") and re.search(r", 0x[0-9a-f]+$", i.op_str):
            ln = int(i.op_str.rsplit(", ", 1)[1], 16)
    return ln


def add_args(site, argc):
    """The scr_CritAddCondition call at site: r9d = argc, and the rip constants copied into its argument slots."""
    seq = S.disasm(site - 0x420, site + 5)
    seq = [i for i in seq if i.address <= site]
    assert seq[-1].address == site, hex(site)
    r9 = [i for i in seq if i.mnemonic == "mov" and i.op_str.startswith("r9d, ")]
    assert r9 and int(r9[-1].op_str.split(", ")[1], 0) == argc, (hex(site), r9[-1].op_str if r9 else None)
    return [S.const_at(rip_target(i)) for i in seq if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip")]


# ---------------------------------------------------------------------------------------------------------------------
def check_su0204():
    lo, hi = S.func_range("scr_RealmBoostExists")
    seq = S.disasm(0x146630278, 0x1466302de)
    assert seq[0].mnemonic == "call" and int(seq[0].op_str, 16) == 0x141f1f3f0          # scr_BattleType(battletype)
    j = ins_at(0x1466302c6)
    assert j.mnemonic == "jne" and int(j.op_str, 16) == 0x1466302d7 and j.size == 2
    assert ins_at(0x1466302c3).op_str == "sil, sil"                                     # sil = (scr_BattleType == 0)
    f = S.disasm(0x1466302c8, 0x1466302d4)                                              # fall-through: return false
    assert f[0].op_str == "dword ptr [rbp - 0x80], 4" and f[1].mnemonic == "jmp"
    # the skipped fall-through only sets the line marker and leaves; r15d is already 0 (0x14663027d), as at 0x1466302d4
    assert ins_at(0x14663027d).op_str == "r15d, r15d"


def check_su0219():
    out = []
    for va, var, call, new in ((0x14174b346, 0x1499e0b68, VARGET, 0x1499e0a88), (0x14174b4aa, 0x1499e0b68, VARSET, 0x1499e0a88),
                               (0x14174b66e, 0x1499e0a88, VARGET, 0x1499e0b68), (0x14174b7d2, 0x1499e0a88, VARSET, 0x1499e0b68)):
        i = ins_at(va)
        assert i.mnemonic == "mov" and i.op_str.startswith("edx, dword ptr [rip") and rip_target(i) == var and i.size == 6
        nxt = [x for x in S.disasm(va, va + 24) if x.mnemonic == "call"][0]
        assert int(nxt.op_str, 16) == call, hex(va)
        disp_old = var - (va + 6); disp_new = new - (va + 6)
        b = S.pe.get_data(va - S.BASE, 6)
        assert b[:2] == b"\x8b\x15" and int.from_bytes(b[2:], "little", signed=True) == disp_old
        out.append((va + 2, le(disp_old), le(disp_new)))
    # both lines read crit_hpmax_adj between their get and set: after the swap the Health line runs first
    c = [x for x in S.disasm(0x14174b346, 0x14174b4aa) if x.mnemonic == "call" and int(x.op_str, 16) == 0x1417cf2f0]
    d = [x for x in S.disasm(0x14174b66e, 0x14174b7d2) if x.mnemonic == "call" and int(x.op_str, 16) == 0x1417cf2f0]
    assert len(c) == 1 and len(d) == 1
    marker(0x14174b195, "dword ptr [rsp + 0x40]", 1123); marker(0x14174b4bd, "dword ptr [rsp + 0x40]", 1124)
    return out


def check_su0189():
    seq = S.disasm(0x1410c9a5a, 0x1410c9ae6)
    cmps = [(i, seq[k - 2]) for k, i in enumerate(seq) if i.mnemonic == "call" and int(i.op_str, 16) == EQ_INT]
    assert [int(p.op_str.split(", ")[1], 16) for _, p in cmps] == [0x26, 0x27, 0x24, 0x58]
    assert cmps[-1][0].address == 0x1410c9ad0
    assert ins_at(0x1410c9ad5).op_str == "byte ptr [rsp + 0x100], al"                    # the last compare is the result
    assert all(seq[k - 1].op_str == "rcx, qword ptr [rsp + 0x39a0]" for k, i in enumerate(seq)
               if i.mnemonic == "call")


def check_su0310():
    seq = S.disasm(0x1410da588, 0x1410da603)
    marker(0x1410da588, "dword ptr [rsp + 0xf608]", 0x520)
    vg = [i for i in seq if i.mnemonic == "call"]
    assert [int(i.op_str, 16) for i in vg] == [VARGET, VARGET, LE_INT] and vg[-1].address == 0x1410da5f3
    ld = [i for i in seq if i.mnemonic == "mov" and i.op_str.startswith("edx, dword ptr [rip")]
    assert [rip_target(i) for i in ld] == [0x1499e3228, 0x1499e0a88]                     # event.creature, .hp
    assert any(i.op_str == "rcx, [rsp + 0x98e8]" for i in seq) and any(i.op_str == "r9, [rsp + 0x9968]" for i in seq)
    assert any(i.op_str == "rcx, [rsp + 0x9968]" for i in seq)                          # hp read on that creature
    assert ins_at(0x1410da5f8).op_str == "eax, al" and ins_at(0x1410da5fd).mnemonic == "je"
    # self / other of bc_ExecuteEvents live at [rsp + 0xf8c0] / [rsp + 0xf8c8] for every script call
    lo, hi = S.func_range("bc_ExecuteEvents")
    ins = S.disasm(lo, hi)
    n = sum(1 for k, i in enumerate(ins) if i.mnemonic == "call" and k >= 2 and
            ins[k - 1].op_str == "rcx, qword ptr [rsp + 0xf8c0]" and ins[k - 2].op_str == "rdx, qword ptr [rsp + 0xf8c8]")
    assert n > 100, n
    assert not any(i.mnemonic in ("sub", "add") and i.op_str.startswith("rsp,") for i in ins[40:-40]), "rsp moves"
    # the can_resurrect reader (bc_EventResurrect) compares the same variable with false
    r = S.disasm(0x141082226, 0x141082251)
    assert rip_target(r[0]) == 0x1499e1ce8 and int(r[-1].op_str, 16) == 0x14028c8d0


def check_su0183():
    a = S.disasm(0x14069aa45, 0x14069aa5e)
    assert a[0].op_str == "rcx, [rbp - 0x78]" and a[1].op_str == "al, al" and a[2].mnemonic == "je" \
        and int(a[2].op_str, 16) == 0x14069aaaa
    marker(0x14069aa4d, "dword ptr [rbp - 0x80]", 196)
    assert ins_at(0x14069aa54).op_str == "edx, 1"
    marker(0x14069aaaa, "dword ptr [rbp - 0x80]", 200)
    m = ins_at(0x14069aab1)
    assert m.mnemonic == "movabs" and m.op_str == "rdx, 0x71afd498cfc7a"                # 1999999999999098
    for nxt in (0x14069aa5e, 0x14069aac0):                                             # rax not used after the setters
        assert ins_at(nxt).op_str.startswith("rdx, qword ptr [rip")
    # the value lands in turnspeed: [rbp - 0x78] -> varset 0x1499e1b98 (L200 merge)
    v = S.disasm(0x14069ab0f, 0x14069ab29)
    assert v[0].op_str == "r9, [rbp - 0x78]" and rip_target(v[2]) == 0x1499e1b98 and int(v[-1].op_str, 16) == VARSET
    assert 2.0 ** 53 > 1999999999999098                                                # exact as a real


def check_su0206():
    lo, hi = S.func_range("scr_CritAddCondition")
    pro = S.disasm(lo, lo + 0x30)
    assert pro[0].op_str == "rax, rsp" and any(i.op_str == "rbp, [rax - 0x3d8]" for i in pro) \
        and any(i.op_str == "rsp, 0x4a0" for i in pro)
    assert sum(1 for i in pro if i.mnemonic == "push") == 7                             # rbp = rsp + 0x100
    # L30: isbuff = scr_ConditionIsBuff(cond), cond = [rbp - 0x38] = rsp + 0xc8; L55 tests the same local
    assert ins_at(0x142015f3a).op_str == "rax, [rbp - 0x38]" and int(ins_at(0x142015f61).op_str, 16) == 0x141fa4c50
    assert ins_at(0x142016667).op_str == "rcx, [rbp - 0x38]"
    # L46: slot > 0 && isbuff && scr_RealmHasProperty(31) -> L48 ... L51 refusal exit
    marker(0x1420163eb, "dword ptr [rsp + 0x60]", 46)
    seq = S.disasm(0x1420163eb, 0x1420164b6)
    calls = [i for i in seq if i.mnemonic == "call" and int(i.op_str, 16) != 0x14028c140]   # (conditional temp release)
    assert [int(i.op_str, 16) for i in calls] == [VARGET, GT_INT, 0x1402be100, 0x14028c4a0, REALM_HAS_PROP, 0x1402be230]
    assert calls[4].address == 0x1420164a1 and seq[-1].mnemonic == "je" and int(seq[-1].op_str, 16) == 0x14201665a
    assert any(i.op_str == "rdx, [rip + 0x78eed3f]" for i in seq) and S.const_at(0x1499051b0) == 31.0
    assert any(i.op_str == "r9d, edi" for i in seq)                                     # argc 1 (edi = 1 here)
    marker(0x1420164b6, "dword ptr [rsp + 0x60]", 48)
    flags_dead(0x1420164be)
    marker(0x14201664d, "dword ptr [rsp + 0x60]", 51)
    j = ins_at(0x142016655)
    assert j.mnemonic == "jmp" and int(j.op_str, 16) == 0x14201b668
    # nothing jumps into the patched marker, nor into L48-L50 from outside it
    for i in S.disasm(lo, hi):
        if (i.mnemonic.startswith("j") or i.mnemonic == "call") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            assert not (0x1420164b6 < t < 0x1420164be), hex(i.address)
            if not (0x1420164b6 <= i.address < 0x14201664d):
                assert not (0x1420164b6 < t < 0x14201664d), "jump into L48-L50 %#x -> %#x" % (i.address, t)


RELIC_START = [  # (line, site, condition id, what)
    (877, 0x14169ad42, 12.0, "Whisper rank 10 (Invisible)"),
    (883, 0x14169b4a2, 5.0, "Triumvir rank 10 (Arcane)"),
    (889, 0x14169bc02, 18.0, "Blazefury rank 40 (Burning on the bearer: Primordial Curse permanence only)"),
    (895, 0x14169c362, 11.0, "Salus rank 10 (Mending)"),
    (907, 0x14169d222, 7.0, "Ferro rank 10 (Proficient)"),
    (913, 0x14169d982, 13.0, "Arbiter rank 10 (Shelled)"),
    (919, 0x14169e0e2, 4.0, "Prime & Ventus rank 10 (Agile)"),
    (922, 0x14169e768, 1.0, "Prime & Ventus rank 50 (Savage)")]
RELIC_MAINTAIN = [(675, 0x1412bbb12, 10.0, "Bloodseeker rank 30 'always has'"),
                  (681, 0x1412bbe97, 11.0, "Bloodseeker rank 60 'always has'")]


def check_relic_sites():
    sb = S.func_range("bc_StartupBuffsDebuffs")
    for line, site, cond, what in RELIC_START:
        assert line_of(sb[0], "dword ptr [rsp + 0x40]", site) == line, (hex(site), what)
        consts = add_args(site, 8)
        assert consts[-8:] == [cond, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0] or consts[-7:] == [cond, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0], (hex(site), consts[-9:])
    mp = S.func_range("bc_MaintainPermanentEffects")
    for line, site, cond, what in RELIC_MAINTAIN:
        assert line_of(mp[0], "dword ptr [rsp + 0x70]", site) == line, (hex(site), what)
        consts = add_args(site, 8)
        assert consts[-7:] == [cond, -2.0, -1.0, -1.0, -1.0, -1.0, -1.0], (hex(site), consts[-8:])
    # the rank gates right before them (Bloodseeker = relic 17, ranks 30 / 60)
    for start, gate, rank in ((0x1412bb82d, 0x1412bb877, 3.0), (0x1412bbbb2, 0x1412bbbfc, 6.0)):
        g = S.disasm(start, gate + 5)
        assert g[-1].address == gate and int(g[-1].op_str, 16) == 0x14202d600
        assert [S.const_at(rip_target(i)) for i in g if i.mnemonic == "lea" and "rip" in i.op_str][-2:] == [17.0, rank]


def main():
    check_su0204()
    s219 = check_su0219()
    check_su0189()
    check_su0310()
    check_su0183()
    check_su0206()
    check_relic_sites()

    taken = []
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_K.json"):
            continue
        for p in json.load(open(f, encoding="utf-8"))["patches"]:
            if p["id"] in OWN:
                continue
            for e in p["edits"]:
                taken.append((int(e["va"], 16), int(e["va"], 16) + len(e["expect"]) // 2, p["id"]))
            for r in p.get("reserves", []):
                taken.append((int(r["start"], 16), int(r["end"], 16) + 1, p["id"]))
            for h in p.get("runtime_hooks", []):
                taken.append((int(h["slot_va"], 16), int(h["slot_va"], 16) + 8, p["id"]))
    b = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["build"]
    assert any(int(x["start"], 16) <= CODE_LO and CODE_HI < int(x["end"], 16) for x in b["xcaves"]), "code not in an xcave"
    assert int(b["data_cave_start"], 16) <= DATA_LO and DATA_HI < int(b["data_cave_end"], 16), "data outside the data cave"
    for v in list(SLOT.values()) + [K_MISERY]:
        assert DATA_LO <= v and v + 7 <= DATA_HI

    at = [CODE_LO]
    listing = []

    def put(src, note):
        code = asm(src, at[0])
        lo = at[0]; at[0] += len(code)
        assert at[0] - 1 <= CODE_HI, "code range full at " + note
        listing.append((lo, code, note))
        return lo, code

    def tramp(key, sym):
        lo, code = put("jmp qword ptr [%#x]" % SLOT[key], "trampoline -> " + sym)
        return lo, chunks(lo, code, "trampoline -> " + sym), [res(lo, len(code), "trampoline -> " + sym),
                                                              res(SLOT[key], 8, "hook pointer " + sym)], \
            {"slot_va": hex(SLOT[key]), "symbol": sym}

    patches = []

    def patch(pid, title, edits, reserves, hooks, group=None):
        p = {"id": pid, "bug": pid, "default": 1, "title": title, "edits": edits, "reserves": reserves,
             "runtime_hooks": hooks}
        if group:
            p["group"] = group
        patches.append(p)

    # ---- SU-0216 Forsaken Wonder (+ SU-0080's start-of-battle permanence)
    t1, e1, r1, h1 = tramp("216s", "hook_k_su0216_start")
    t2, e2, r2, h2 = tramp("216m", "hook_k_su0216_always")
    e = e1 + e2
    for line, site, cond, what in RELIC_START:
        e.append(call_redirect(site, ADD_COND, t1, "bc_StartupBuffsDebuffs L%d %s: scr_CritAddCondition -> hook "
                                                   "(forever + spread under the perks)" % (line, what)))
    for line, site, cond, what in RELIC_MAINTAIN:
        e.append(call_redirect(site, ADD_COND, t2, "bc_MaintainPermanentEffects L%d %s: scr_CritAddCondition -> hook "
                                                   "(spread after a real gain under Forsaken Wonder)" % (line, what)))
    patch("SU-0216", "Forsaken Wonder: the Relic buffs given at the start of battle (Arbiter, Ferro, Prime & Ventus, "
                     "Salus, Triumvir, Whisper) and Bloodseeker's 'always has' buffs spread to your other creatures and "
                     "last forever; with Primordial Curse, Blazefury 40's start-of-battle Burning lasts forever "
                     "(code: no spread, no permanence for these direct adds)", e, r1 + r2, [h1, h2])

    # ---- SU-0218 Photosynthesis: every other start-of-battle add
    sb_sites = callers(ADD_COND, "bc_StartupBuffsDebuffs")
    assert len(sb_sites) == 171, len(sb_sites)
    relic = {s for _, s, _, _ in RELIC_START}
    other_owned = {lo - 1 for lo, hi, pid in taken if hi - lo == 4}                     # call-target edits of others
    skip = relic | {s for s in sb_sites if s in other_owned}
    assert 0x1416b60ed in skip                                                          # SU-0170-xmas owns its add
    t, e, r, h = tramp("218", "hook_k_su0218_add")
    mine = [s for s in sb_sites if s not in skip]
    sbl = S.func_range("bc_StartupBuffsDebuffs")[0]
    for s in mine:
        e.append(call_redirect(s, ADD_COND, t, "bc_StartupBuffsDebuffs L%d: scr_CritAddCondition -> hook (Herbling "
                                               "counts the buff / minion)" % line_of(sbl, "dword ptr [rsp + 0x40]", s)))
    patch("SU-0218", "Photosynthesis: buffs and minions your Herbling receives at the start of battle count, like the "
                     "ones it receives later (code: only in-battle grants counted). Start-of-battle stat gains not "
                     "built", e, r, [h], group="heavy")
    n218 = len(mine)

    # ---- SU-0206 Misery (buff half)
    t, e, r, h = tramp("206", "hook_k_su0206_realm_prop")
    s, c = put("""
        cmp byte ptr [{flag:#x}], 0
        je normal
        mov byte ptr [{flag:#x}], 0
        jmp {l51:#x}
    normal:
        mov dword ptr [rsp + 0x60], 0x30
        jmp {nxt:#x}""".format(flag=K_MISERY, l51=0x14201664d, nxt=0x1420164be), "SU-0206 stub (L48)")
    e += chunks(s, c, "SU-0206 stub (scr_CritAddCondition L48): refusal armed -> the game's L51 refusal exit")
    r += [res(s, len(c), "SU-0206 stub (scr_CritAddCondition L48)"), res(K_MISERY, 8, "SU-0206 refusal flag (byte)")]
    e += [call_redirect(0x1420164a1, REALM_HAS_PROP, t, "scr_CritAddCondition L46 (your creature, a buff): "
                        "scr_RealmHasProperty(31) -> hook (true and arms the refusal under Misery)"),
          detour(0x1420164b6, 8, s, "scr_CritAddCondition L48 marker -> SU-0206 stub")]
    patch("SU-0206", "Misery (Nemesis): your creatures cannot gain buffs from direct adds either (start-of-battle, "
                     "'always has', in-battle direct grants), as from buff events (code: only the buff event refused). "
                     "Start-of-battle stat gains not built", e, r, [h])

    # ---- SU-0219 Sacrifice x artifact Health
    e = [raw(va, x, y, "bc_StartupStatGain L%d artifact Health: %s" % (ln, w)) for (va, x, y), ln, w in
         zip(s219, (1123, 1123, 1124, 1124), ("read hpmax -> hp", "write hpmax -> hp", "read hp -> hpmax", "write hp -> hpmax"))]
    patch("SU-0219", "Artifact Health %: current and Max Health gain the same amount (code: current Health gained a share "
                     "of the already raised Max Health, which nearly cancelled Sacrifice)", e, [], [])

    # ---- SU-0183 Hymn of Panic
    t, e, r, h = tramp("183", "hook_k_su0183_key")
    e += [call_redirect(0x14069aa59, INT_SET, t, "bc_CreateCreatureList L196 Hymn of Panic: key = 1 -> random key"),
          call_redirect(0x14069aabb, INT64_SET, t, "bc_CreateCreatureList L200 Hymn of Panic: key = 1999999999999098 -> "
                                                   "random key")]
    patch("SU-0183", "Hymn of Panic: the Timeline is shuffled into a uniformly random order (code: a coin flip into two "
                     "groups with a fixed order inside each)", e, r, [h])

    # ---- SU-0189 Lord Zantai
    t, e, r, h = tramp("189", "hook_k_su0189_boss_type")
    e.append(call_redirect(0x1410c9ad0, EQ_INT, t, "bc_ExecuteEvents L1053: battletype == 88 -> 88 or 37 (Lord Zantai)"))
    patch("SU-0189", "Lord Zantai's battle: forced 'move to the bottom of the Timeline' moves him down 1 place, like the "
                     "other bosses (code: the boss list missed battle type 37)", e, r, [h])

    # ---- SU-0310 Terminus / cannot be resurrected
    t, e, r, h = tramp("310", "hook_k_su0310_dead")
    e.append(call_redirect(0x1410da5f3, LE_INT, t, "bc_ExecuteEvents L1312 resurrect case: hp <= 0 -> also "
                                                   "can_resurrect (queue-time exemptions kept)"))
    patch("SU-0310", "'Cannot be resurrected' (Burn Their Corpses, Endwalker, Feast and Famine, End On a High Note, "
                     "Epigraphy, Disintegrating Arrow) also stops resurrections queued before the death (Terminus, Defy "
                     "the Gods, Reincarnation, Genesis) (code: checked only when queued)", e, r, [h])

    # ---- SU-0204 realm 'Next battle' boosts
    patch("SU-0204", "Realm 'Next battle' boosts work in the next battle of any kind (code: switched off in boss and "
                     "special battles but still used up there)",
          [raw(0x1466302c6, "750f", "eb0f", "scr_RealmBoostExists: scr_BattleType != 0 -> return false: jne -> jmp")], [], [])

    # ---- space and overlap
    for p in patches:
        assert p["id"] in OWN
        spans = [(int(x["start"], 16), int(x["end"], 16) + 1) for x in p["reserves"]] + \
                [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in p["edits"]]
        for x in p["reserves"]:
            lo, hi = int(x["start"], 16), int(x["end"], 16)
            assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), x
        for d in p["edits"]:
            va = int(d["va"], 16)
            if CODE_LO <= va <= CODE_HI:
                assert d["expect"] == "00" * (len(d["expect"]) // 2)
            else:
                assert S.pe.get_data(va - S.BASE, len(d["expect"]) // 2).hex() == d["expect"], d
        for x0, x1 in spans:
            for lo, hi, pid in taken:
                assert x1 <= lo or hi <= x0, "%s %#x overlaps %s" % (p["id"], x0, pid)
    allspans = sorted((int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2, p["id"]) for p in patches
                      for d in p["edits"] if not (CODE_LO <= int(d["va"], 16) <= CODE_HI))
    for (a, b_, i), (c_, d_, j) in zip(allspans, allspans[1:]):
        assert b_ <= c_, "self overlap %s / %s @%#x" % (i, j, c_)
    json.dump({"patches": patches}, open(os.path.join(HERE, "hooks_K.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_K.json: %d patches; code %#x-%#x (%d of %d bytes); data %#x-%#x; SU-0218 sites %d" % (
        len(patches), CODE_LO, at[0] - 1, at[0] - CODE_LO, CODE_HI - CODE_LO + 1, DATA_LO, K_MISERY + 7, n218))
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for lo, code, note in listing:
        print("  ;", note)
        for i in md.disasm(code, lo):
            print("  %#x  %-16s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))


if __name__ == "__main__":
    main()
