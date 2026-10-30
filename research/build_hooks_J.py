"""Build research/hooks_J.json: errata round 2, batch J (stats, stat getters, race counts). See loader/hooks_J.c.

  SU-0281 Jealousy            : crit_attack L577 / crit_defense L630 / crit_intelligence L673 / crit_speed L636, the two
                                "count == 1" compares -> per-getter cave stub (saves self / other / getter) -> hook
                                (bc_CountRace on the same ally list)
  SU-0261 Devotion            : bc_EventDamage L2777, the same two compares -> hook
  SU-0264 Draconic Arrogance  : the four scr_GetCritNthHighestStatAmt(ally, 1, false) calls -> hook (stored stats)
  SU-0234 Memento (sealed)    : the sealed flag of the four Memento gem lists false -> true (constant repoint)
  SU-0269 Fallen Star         : 35% -> 50% (constant repoint x3); the four holder tests -> hook (Feared holder does not
                                steal); bc_EventGainMaxHP L312 bc_GetEnemiesOf -> hook that runs the Fallen Star block
  SU-0202 Unstable Horror     : bc_OnDefend L510 / bc_OnProvoke L163 n = 2 -> 1 (constant repoint); `amount = 0`
                                (L512 / L165) -> hook (Health -> Maximum Health)
  SU-0275 Grandiose           : 14 raw buff / debuff list fetches -> pass-through hook (records the list's identity
                                and bc_CountBuffs / bc_CountDebuffs of the same creature); each site's single list[0]
                                read (array element helper) -> hook returning a fresh value equal to that counter

Verifies every expect byte, call target, constant, frame offset and data-flow assumption against the exe. Assigned
space only: code 0x14a343500-0x14a3438ff (xcave), data 0x149ed8950-0x149ed89cf (.data tail).
"""
import bisect, glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x14a343500, 0x14a3438ff, 0x149ed8950, 0x149ed89cf
OWN = ("SU-0281", "SU-0261", "SU-0264", "SU-0234", "SU-0269", "SU-0202", "SU-0275")
# data (must match loader/hooks_J.c)
J_SELF, J_OTHER, J_IDX = 0x149ed8950, 0x149ed8958, 0x149ed8960
SLOT = {"jeal": 0x149ed8968, "dev": 0x149ed8970, "drac": 0x149ed8978, "fsgate": 0x149ed8980, "fshp": 0x149ed8988,
        "uhdef": 0x149ed8990, "uhprov": 0x149ed8998, "buffs": 0x149ed89a0, "debuffs": 0x149ed89a8,
        "elem": 0x149ed89b0}
SYM = {"jeal": "hook_j_su0281_count", "dev": "hook_j_su0261_count", "drac": "hook_j_su0264_highest",
       "fsgate": "hook_j_su0269_holder", "fshp": "hook_j_su0269_maxhp", "uhdef": "hook_j_su0202_defend",
       "uhprov": "hook_j_su0202_provoke", "buffs": "hook_j_su0275_buffs", "debuffs": "hook_j_su0275_debuffs",
       "elem": "hook_j_su0275_elem"}

EQ_INT, EQ, ASSIGN, FREE1, FREE2, SET_INT, ELEM = 0x14028c8f0, 0x14028c8d0, 0x14028c410, 0x14028c140, 0x14028c220, \
    0x14028c530, 0x14028c820
VARGET, VARSET, COPY_K = 0x1478bbd70, 0x1478bc260, 0x14028c4a0
RV_FALSE, RV_TRUE = 0x1498e0f40, 0x1498e0f60
FN = {n: int(a, 16) for n, a in S.FM.items()}
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()
raw = lambda va, n: S.pe.get_data(va - S.BASE, n)

_fcache = {}


def fn(name):
    """(instructions, GML line per instruction) for a function."""
    if name not in _fcache:
        lo, hi = S.func_range(name)
        ins = S.disasm(lo, hi)
        slots = {}
        for i in ins:
            if i.mnemonic == "mov" and i.op_str.startswith("dword ptr [r") and re.search(r", 0x[0-9a-f]+$", i.op_str):
                k = i.op_str.rsplit(", ", 1)[0]; slots[k] = slots.get(k, 0) + 1
        slot = max(slots, key=slots.get)
        cur, lines = None, []
        for i in ins:
            if i.mnemonic == "mov" and i.op_str.startswith(slot + ",") and re.search(r", 0x[0-9a-f]+$", i.op_str):
                cur = int(i.op_str.rsplit(", ", 1)[1], 16)
            lines.append(cur)
        _fcache[name] = (ins, lines, {i.address: k for k, i in enumerate(ins)})
    return _fcache[name]


def host(va):
    k = bisect.bisect_right(S.FUNCS, va) - 1
    return S.NAMES[S.FUNCS[k]]


def at(name, va):
    ins, lines, idx = fn(name)
    assert va in idx, "%#x is not an instruction boundary of %s" % (va, name)
    return idx[va]


def rip(i):
    m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
    return i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1) if m else None


def calls(i, target):
    return i.mnemonic == "call" and i.op_str == hex(target)


def rv(va):
    b = raw(va, 16)
    return int.from_bytes(b[:8], "little"), int.from_bytes(b[12:16], "little") & 0xffffff


def real_const(va, x):
    import struct
    b = raw(va, 16)
    assert struct.unpack("<d", b[:8])[0] == x and int.from_bytes(b[12:16], "little") & 0xffffff == 0, (hex(va), x)


_strs = None


def gstr(g):
    """String value a static string global is initialised with (lea rdx,[str]; lea rcx,[g]; call 0x147897df0)."""
    global _strs
    if _strs is None:
        import struct
        t = [s for s in S.pe.sections if s.Name.startswith(b".text")][0]
        d = t.get_data(); tva = S.BASE + t.VirtualAddress; _strs = {}
        for m in re.finditer(rb"\x48\x8d\x15(....)\x48\x8d\x0d(....)\xe8(....)", d, re.S):
            va = tva + m.start()
            if va + 19 + struct.unpack("<i", m.group(3))[0] != 0x147897df0:
                continue
            sva = va + 7 + struct.unpack("<i", m.group(1))[0]; gg = va + 14 + struct.unpack("<i", m.group(2))[0]
            try:
                r = raw(sva, 64); _strs[gg] = r[:r.index(b"\0")].decode("utf-8", "replace")
            except Exception:
                pass
    return _strs.get(g)


def varname(slot):
    try:
        p = int.from_bytes(raw(slot - 8, 8), "little"); r = raw(p, 64)
        return r[:r.index(b"\0")].decode("ascii")
    except Exception:
        return None


def call_redirect(site, target, tramp, note):
    b = raw(site, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, hex(site)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def lea_repoint(va, old, new, note):
    i = S.disasm(va, va + 8)[0]
    assert i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip") and rip(i) == old, (hex(va), i.op_str)
    assert raw(va, 3).hex() == "488d15", hex(va)
    return {"va": hex(va + 3), "expect": le(old - (va + 7)), "write": le(new - (va + 7)), "note": note}


def args_before(name, k, n=24):
    """rip constants copied into script arguments (0x14028c4a0 copies) before instruction k, in order, and argc."""
    ins, lines, _ = fn(name)
    ks, argc = [], None
    for j in range(k - 1, max(0, k - 60), -1):
        i = ins[j]
        if i.mnemonic == "call" and j != k and not calls(i, COPY_K) and not calls(i, ASSIGN) and not calls(i, FREE1):
            break
        if i.mnemonic == "mov" and i.op_str.startswith("r9d, ") and argc is None:
            argc = int(i.op_str.split(", ")[1], 0)
        if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip"):
            ks.insert(0, rip(i))
    return ks, argc


def frame_rbp(name):
    """rbp - rsp after the prologue (lea rbp, [rsp - a]; mov eax, b; call __chkstk; sub rsp, rax)."""
    ins, _, _ = fn(name)
    a = b = None
    for i in ins[:30]:
        if i.mnemonic == "lea" and i.op_str.startswith("rbp, [rsp - "):
            a = int(i.op_str.split(" - ")[1].rstrip("]"), 16)
        if i.mnemonic == "mov" and i.op_str.startswith("eax, 0x") and a is not None and b is None:
            b = int(i.op_str.split(", ")[1], 16)
        if i.mnemonic == "sub" and i.op_str == "rsp, rax":
            return b - a
    raise SystemExit("no rbp frame in " + name)


def self_other_regs(name, upto):
    """The registers the prologue copies rcx / rdx into; nothing writes them again before `upto` (the function's
    closing return statement reuses one of them, after every site we patch)."""
    ins, _, _ = fn(name)
    regs = {}
    for i in ins[:40]:
        m = re.match(r"(r\w+), (rcx|rdx)$", i.op_str)
        if i.mnemonic == "mov" and m:
            regs[m.group(2)] = m.group(1)
    assert set(regs) == {"rcx", "rdx"}, (name, regs)
    for k, i in enumerate(ins):                     # nothing else writes them (callee-saved, set once in the prologue)
        if i.mnemonic == "int3" or i.address >= upto:
            break
        if k > 40 and i.mnemonic not in ("push", "pop") and re.match(r"(%s|%s)\b," % (regs["rcx"], regs["rdx"]), i.op_str) \
                and i.mnemonic not in ("cmp", "test"):
            raise SystemExit("%s writes %s at %#x" % (name, i.op_str, i.address))
    return regs["rcx"], regs["rdx"]


def mem(i):
    m = re.search(r"\[(r[bs]p) ([+-]) (0x[0-9a-f]+)\]", i.op_str)
    return (m.group(1), int(m.group(3), 16) * (1 if m.group(2) == "+" else -1)) if m else None


# ---------------------------------------------------------------------------------------------------------------------
P = []
at_code = [CODE_LO]


def put(src, note, patch, what):
    code = asm(src, at_code[0])
    lo = at_code[0]; at_code[0] += len(code)
    assert at_code[0] - 1 <= CODE_HI, "code range full at %s" % note
    patch["edits"] += chunks(lo, code, note)
    patch["reserves"].append({"start": hex(lo), "end": hex(lo + len(code) - 1), "what": what})
    return lo


def tramp(key, patch):
    t = put("jmp qword ptr [%#x]" % SLOT[key], "trampoline -> %s (loader/hooks_J.c)" % SYM[key], patch,
            "trampoline -> " + SYM[key])
    hook(key, patch)
    return t


def hook(key, patch):
    patch["runtime_hooks"].append({"slot_va": hex(SLOT[key]), "symbol": SYM[key]})
    patch["reserves"].append({"start": hex(SLOT[key]), "end": hex(SLOT[key] + 7), "what": "hook pointer " + SYM[key]})


def patch(pid, title, group=None):
    p = {"id": pid, "bug": pid, "default": 1, "title": title, "edits": [], "reserves": [], "runtime_hooks": []}
    if group:
        p["group"] = group
    P.append(p)
    return p


# ---- SU-0281 Jealousy ------------------------------------------------------------------------------------------------
# (getter, L of the tests, imler / imling / found offsets from rbp, Imler / Imling string globals) = loader/hooks_J.c
JEAL = [("crit_attack", 577, 0x510, 0x500, 0x4f0, 0x149d692a0, 0x149d69270),
        ("crit_defense", 630, 0x4b0, 0x4a0, 0x490, 0x149d69400, 0x149d69310),
        ("crit_intelligence", 673, 0x500, 0x4f0, 0x4e0, 0x149d69520, 0x149d694b0),
        ("crit_speed", 636, 0x4a0, 0x490, 0x480, 0x149d696a0, 0x149d695d0)]
GET_ALLIES, HAS_PASSIVE, COUNT_RACE = FN["bc_GetAlliesOf"], FN["scr_CritHasPassive"], FN["bc_CountRace"]
assert COUNT_RACE == 0x14068f7b0


def race_block(name, line, imler, imling, found, s_imler, s_imling, base_reg, allies_off, holder_id):
    """Checks one 'only one Imler and one Imling' block and returns the two count-compare call sites."""
    ins, lines, _ = fn(name)
    assert gstr(s_imler) == "Imler" and gstr(s_imling) == "Imling", name
    ks = [k for k, i in enumerate(ins) if lines[k] == line and calls(i, EQ_INT)]
    assert len(ks) >= 2, (name, line)
    sites = []
    for k, off in zip(ks[:2], (imler, imling)):
        assert mem(ins[k - 1]) == (base_reg, off) and ins[k - 1].op_str.startswith("rcx"), (name, ins[k - 1].op_str)
        sites.append(ins[k].address)
    # the holder flag is read by the third test of the same statement, or by the bool == that follows
    third = [k for k in range(ks[1] + 1, ks[1] + 40) if mem(ins[k]) == (base_reg, found)]
    assert third, (name, "found flag not tested")
    # walk back from the tests to the block start: allies fetch, two int sets 0, flag set, loop with the holder gate,
    # race compares against the string globals incrementing the count locals
    start = max(k for k in range(ks[0]) if calls(ins[k], GET_ALLIES))
    st = ins[start + 2]
    assert ins[start + 1].op_str == "rdx, rax" and calls(ins[start + 3], ASSIGN) and mem(st) == (base_reg, allies_off), \
        (name, st.op_str)
    seg = ins[start:ks[0]]
    sets = [mem(seg[j - 1]) for j in range(len(seg)) if calls(seg[j], SET_INT)]
    assert (base_reg, imler) in sets and (base_reg, imling) in sets, (name, sets)
    holder = [rip(i) for i in seg if i.mnemonic == "lea" and rip(i) and S.const_at(rip(i)) == float(holder_id)]
    assert holder, (name, "holder id")
    incs = {}
    last_str = None
    for j, i in enumerate(seg):
        if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip") and rip(i) in (s_imler, s_imling):
            last_str = rip(i)
        if calls(i, 0x1402f4230):
            incs[mem(seg[j - 1])] = last_str
    assert incs == {(base_reg, imler): s_imler, (base_reg, imling): s_imling}, (name, incs)
    # nothing jumps into the middle of a redirected call
    return sites


p = patch("SU-0281", "Jealousy: the 'only one Imler and one Imling' test uses the shared race count, so Odd One, "
                     "Shackler's Mastery and Forest Pact apply (code: its own count, which ignored them)")
for idx, (name, line, imler, imling, found, s1, s2) in enumerate(JEAL):
    assert frame_rbp(name) == 0x100, name
    sites = race_block(name, line, imler, imling, found, s1, s2, "rbp", -0x38, 455)
    sreg, oreg = self_other_regs(name, max(sites) + 5)
    ins, lines, _ = fn(name)
    assert all(lines[k] is not None and lines[k] > line for k, i in enumerate(ins) if i.address > max(sites) and
               re.match(r"(%s|%s)," % (sreg, oreg), i.op_str) and i.mnemonic == "mov"), name
    stub = put("""
        mov qword ptr [{s:#x}], {sr}
        mov qword ptr [{o:#x}], {orr}
        mov byte ptr [{i:#x}], {idx}
        jmp qword ptr [{slot:#x}]""".format(s=J_SELF, o=J_OTHER, i=J_IDX, slot=SLOT["jeal"], sr=sreg, orr=oreg, idx=idx),
        "SU-0281 %s stub: save self / other / getter, then hook_j_su0281_count" % name, p, "SU-0281 %s stub" % name)
    for s, what in zip(sites, ("Imler", "Imling")):
        p["edits"].append(call_redirect(s, EQ_INT, stub, "%s L%d: %s count == 1 -> bc_CountRace(allies, %s) == 1"
                                        % (name, line, what, what)))
hook("jeal", p)
p["reserves"] += [{"start": hex(J_SELF), "end": hex(J_SELF + 7), "what": "SU-0281 self of the running getter"},
                  {"start": hex(J_OTHER), "end": hex(J_OTHER + 7), "what": "SU-0281 other of the running getter"},
                  {"start": hex(J_IDX), "end": hex(J_IDX + 7), "what": "SU-0281 getter index (byte)"}]

# ---- SU-0261 Devotion ------------------------------------------------------------------------------------------------
p = patch("SU-0261", "Devotion: the 'only one Imler and one Imling' test uses the shared race count, so Odd One, "
                     "Shackler's Mastery and Forest Pact apply (code: its own count, which ignored them)")
ins, _, _ = fn("bc_EventDamage")
assert [i.op_str for i in ins[2:5]] == ["qword ptr [rsp + 0x10], rdx", "qword ptr [rsp + 8], rcx", "eax, 0x30488"] \
    and ins[6].op_str == "rsp, rax" and not any(i.mnemonic == "push" for i in ins[:7]), "bc_EventDamage prologue"
# self / other stay in their home slots [rsp + 0x30490 / 0x30498]: nothing in the body writes them
assert not [i for i in ins[7:] if re.search(r"qword ptr \[rsp \+ 0x3049[08]\], ", i.op_str)], "homes rewritten"
sites = race_block("bc_EventDamage", 2777, 0x22948, 0x22958, 0x22968, 0x149d610a0, 0x149d60f00, "rsp", 0x22178, 449)
t = tramp("dev", p)
for s, what in zip(sites, ("Imler", "Imling")):
    p["edits"].append(call_redirect(s, EQ_INT, t, "bc_EventDamage L2777: %s count == 1 -> bc_CountRace(allies, %s) == 1"
                                    % (what, what)))

# ---- SU-0264 Draconic Arrogance --------------------------------------------------------------------------------------
NTH_AMT = FN["scr_GetCritNthHighestStatAmt"]
assert NTH_AMT == 0x14612aad0
p = patch("SU-0264", "Draconic Arrogance: reads the other creatures' stored stats, so it no longer crashes the game "
                     "with From Death to Destiny or Lifeblood (code: computed them, and the two traits recursed)")
t = tramp("drac", p)
for site in (0x1417aedca, 0x1417c1fe4, 0x1417e20a6, 0x1417e7efb):
    name = host(site); ins, lines, _ = fn(name); k = at(name, site)
    ks, argc = args_before(name, k)
    assert argc == 3 and ks[-1] == RV_FALSE and S.const_at(ks[-2]) == 1.0, \
        (hex(site), [hex(x) for x in ks], argc)
    gate = [rip(i) for i in ins[k - 400:k] if i.mnemonic == "lea" and rip(i) and S.const_at(rip(i)) == 1885.0]
    assert gate, hex(site)
    p["edits"].append(call_redirect(site, NTH_AMT, t, "%s L%d Draconic Arrogance: scr_GetCritNthHighestStatAmt(ally, 1, "
                                    "false) -> the ally's stored stats" % (name, lines[k])))
for slot, nm in ((0x149930148, "recent_attack"), (0x1499304a8, "recent_defense"), (0x149930138, "recent_intelligence"),
                 (0x1499302b8, "recent_speed"), (0x1499e0b68, "hpmax"), (0x1499e0aa8, "slot"), (0x1499e3228, "creature"),
                 (0x1499e09f8, "creatureList")):
    assert varname(slot) == nm, (hex(slot), varname(slot), nm)
# the mode-false branch of scr_GetCritNthHighestStatAmt is the one that calls the four getters + hpmax
ins, _, _ = fn("scr_GetCritNthHighestStatAmt")
called = [S.NAMES.get(int(i.op_str, 16)) for i in ins if i.mnemonic == "call" and i.op_str.startswith("0x")]
assert all(g in called for g in ("crit_attack", "crit_defense", "crit_intelligence", "crit_speed")), "NthHighest getters"

# ---- SU-0234 Memento of Attack / Intelligence / Defense / Speed while sealed -----------------------------------------
GEMS = FN["bc_GetSpellGems"]
p = patch("SU-0234", "Memento of Attack / Intelligence / Defense / Speed: also counts while the gem is Sealed (code: "
                     "a sealed Memento gave nothing)")
for site, spell in ((0x1417b202b, 540), (0x1417c486f, 542), (0x1417d7f2f, 541), (0x1417eaf73, 543)):
    name = host(site); ins, lines, _ = fn(name); k = at(name, site)
    assert calls(ins[k], GEMS)
    leas = [i for i in ins[k - 24:k] if i.mnemonic == "lea" and i.op_str.startswith("rdx, [rip")]
    assert [rip(i) for i in leas[-3:]] == [RV_FALSE, RV_FALSE, RV_TRUE] and \
        [i.op_str for i in ins[k - 24:k] if i.op_str.startswith("r9d")] == ["r9d, 4"], hex(site)
    assert rv(RV_FALSE) == (0, 13) and rv(RV_TRUE) == (0x3ff0000000000000, 13)
    sealed = leas[-2]
    lst = ins[k + 2]; X = mem(lst)
    assert ins[k + 1].op_str == "rdx, rax" and calls(ins[k + 3], ASSIGN), hex(site)
    # the list feeds only the Memento loop of the next statements: it is compared with the spell id and nothing else
    # reads it before the next bc_GetSpellGems result is assigned to the same local
    ids = []
    for j in range(k + 4, len(ins)):
        if mem(ins[j]) == X:
            if calls(ins[j + 1], ASSIGN) and ins[j - 1].op_str == "rdx, rax" and calls(ins[j - 2], GEMS):
                break
            assert calls(ins[j + 1], ELEM) or calls(ins[j + 1], FREE1) or calls(ins[j + 1], FREE2), \
                (hex(site), hex(ins[j].address))
        if calls(ins[j], EQ_INT) and ins[j - 2].op_str.startswith("edx, 0x") and lines[j] < lines[k] + 4:
            ids.append(int(ins[j - 2].op_str.split(", ")[1], 16))
    assert ids == [spell], (hex(site), ids)
    p["edits"].append(lea_repoint(sealed.address, RV_FALSE, RV_TRUE, "%s L%d Memento gem list: bc_GetSpellGems sealed "
                                  "argument false -> true" % (name, lines[k])))

# ---- SU-0269 Fallen Star ---------------------------------------------------------------------------------------------
p = patch("SU-0269", "Fallen Star: 50% for every stat (code: 35% for Defense / Intelligence / Speed), a Feared holder "
                     "does not steal, and Max Health gains can be stolen too")
R50 = 0x1498ec470
real_const(R50, 50.0)
t = tramp("fsgate", p)
for name, gate, roll, r35 in (("bc_EventGainAttack", 0x140ff2ad4, 0x140ff2cee, None),
                              ("bc_EventGainDefense", 0x141001f54, 0x14100216e, 0x1498ecb00),
                              ("bc_EventGainIntelligence", 0x141011b65, 0x141011d7f, 0x1498ecba0),
                              ("bc_EventGainSpeed", 0x14103054c, 0x141030766, 0x1498ed6d0)):
    ins, lines, _ = fn(name); k = at(name, gate)
    ks, argc = args_before(name, k)
    assert argc == 2 and S.const_at(ks[-1]) == 268.0, (name, argc)
    assert len([i for i in ins if i.mnemonic == "lea" and rip(i) and S.const_at(rip(i)) == 268.0]) == 1, name
    p["edits"].append(call_redirect(gate, HAS_PASSIVE, t, "%s L%d Fallen Star holder test -> also not Feared"
                                    % (name, lines[k])))
    kr = at(name, roll)
    nxt = [ins[j] for j in range(kr, kr + 20) if ins[j].mnemonic == "call" and ins[j].op_str != hex(COPY_K)][0]
    assert S.NAMES.get(int(nxt.op_str, 16)) == "scr_Roll", (name, nxt.op_str)
    if r35 is None:
        assert rip(ins[kr]) == R50
    else:
        real_const(r35, 35.0)
        p["edits"].append(lea_repoint(roll, r35, R50, "%s L%d Fallen Star roll 35 -> 50" % (name, lines[kr])))
# the receiver switch writes event.creature on [rsp + 0x50] (bc_EventGainAttack L312)
ins, lines, _ = fn("bc_EventGainAttack")
sw = [k for k, i in enumerate(ins) if lines[k] == 312 and calls(i, VARSET)]
assert sw and ins[sw[0] - 1].op_str == "rcx, [rsp + 0x50]" and rip(ins[sw[0] - 2]) == 0x1499e3228, "GainAttack L312"
# Max Health: no Fallen Star block; L312 (Currents) fetches bc_GetEnemiesOf(event.creature, true)
ENEMIES = FN["bc_GetEnemiesOf"]
ins, lines, _ = fn("bc_EventGainMaxHP")
assert not [i for i in ins if i.mnemonic == "lea" and rip(i) and S.const_at(rip(i)) == 268.0], "MaxHP already has 268"
k = [k for k, i in enumerate(ins) if lines[k] == 312 and calls(i, ENEMIES)]
assert len(k) == 1; k = k[0]
vg = [j for j in range(k - 30, k) if calls(ins[j], VARGET)]
assert vg and ins[vg[-1] - 1].op_str == "rcx, [rsp + 0x50]" and rip(ins[vg[-1] - 2]) == 0x1499e3228, "MaxHP L312 arg"
ks, argc = args_before("bc_EventGainMaxHP", k)
assert argc == 2 and ks[-1] == RV_TRUE, (argc, ks)
assert [lines[j] for j in range(k) if lines[j] is not None and 300 <= lines[j] <= 311] and \
    any(S.const_at(rip(i) or 0) == 837.0 for i in ins[k:k + 80] if i.mnemonic == "lea"), "MaxHP L312 = Currents"
t = tramp("fshp", p)
p["edits"].append(call_redirect(ins[k].address, ENEMIES, t, "bc_EventGainMaxHP L312 (Currents) bc_GetEnemiesOf -> run "
                                "the Fallen Star block first"))
for g, s in ((0x149d615e0, "L_B_STAT_GAIN_STOLEN"), (0x149d61500, "L_TRAIT_NAME_FALLENSTAR"), (0x149d61660, "\n"),
             (0x149d614f0, "("), (0x149d61400, ")")):
    assert gstr(g) == s, (hex(g), gstr(g))
# the floater as bc_EventGainAttack L311 builds it: lcz x2, bc_EventFloating argc 4, scr_AddEventToStack argc 2
ins, lines, _ = fn("bc_EventGainAttack")
l311 = [i for k, i in enumerate(ins) if lines[k] == 311]
named = [S.NAMES.get(int(i.op_str, 16)) for i in l311 if i.mnemonic == "call" and i.op_str.startswith("0x")]
assert named.count("lcz") == 2 and "bc_EventFloating" in named and "scr_AddEventToStack" in named, named
assert any(S.const_at(rip(i) or 0) == 16776960.0 for i in l311 if i.mnemonic == "lea"), "floater color"
assert FN["lcz"] == 0x141dc5060 and FN["bc_EventFloating"] == 0x140fe96c0 and FN["scr_AddEventToStack"] == 0x141ef3830
assert FN["scr_CritHasCondition"] == 0x14202b010 and FN["scr_Roll"] == 0x146666e40 and ENEMIES == 0x141161660
# Feared = condition 32: the gain events' own Fear block (bc_EventGainAttack L50)
k = [k for k, i in enumerate(ins) if lines[k] == 50 and calls(i, FN["scr_CritHasCondition"])][0]
assert S.const_at(args_before("bc_EventGainAttack", k)[0][-1]) == 32.0, "Fear id"

# ---- SU-0202 Unstable Horror ------------------------------------------------------------------------------------------
NTH = FN["scr_GetCritNthHighestStat"]
p = patch("SU-0202", "Unstable Horror: the damage uses the master's highest stat, Health included (Maximum Health) "
                     "(code: the second-highest when Health was highest)")
for name, l1, l2, lset, stat_off, health, key in (("bc_OnDefend", 506, 510, 512, 0x2e0, 0x149d67500, "uhdef"),
                                                 ("bc_OnProvoke", 159, 163, 165, 0x290, 0x149d67bb0, "uhprov")):
    assert frame_rbp(name) == 0x100, name
    ins, lines, _ = fn(name)
    c1 = [k for k, i in enumerate(ins) if lines[k] == l1 and calls(i, NTH)]
    c2 = [k for k, i in enumerate(ins) if lines[k] == l2 and calls(i, NTH)]
    assert len(c1) == 1 and len(c2) == 1, name
    a1, n1 = args_before(name, c1[0]); a2, n2 = args_before(name, c2[0])
    assert n1 == n2 == 3 and S.const_at(a1[-2]) == 1.0 and S.const_at(a2[-2]) == 2.0 and a1[-1] == a2[-1] == RV_FALSE
    real_const(a1[-2], 1.0)
    for c in (c1[0], c2[0]):        # master at [rbp - 0x78] is args[0]; the result goes to the stat local
        assert mem(ins[c + 2]) == ("rbp", stat_off) and calls(ins[c + 3], ASSIGN), (name, ins[c + 2].op_str)
    arg0 = [ins[j] for j in range(c1[0] - 30, c1[0]) if ins[j].mnemonic == "lea" and ins[j].op_str == "rax, [rbp - 0x78]"]
    assert arg0, name
    # the health test between the two picks compares the stat local with the 'health' string
    assert gstr(health) == "health"
    hs = [ins[j] for j in range(c1[0], c2[0]) if ins[j].mnemonic == "lea" and rip(ins[j]) == health]
    assert hs, name
    two = [ins[j] for j in range(c2[0] - 20, c2[0]) if ins[j].mnemonic == "lea" and rip(ins[j]) == a2[-2]][0]
    p["edits"].append(lea_repoint(two.address, a2[-2], a1[-2], "%s L%d Unstable Horror: Health highest -> keep the "
                                  "highest (n = 2 -> 1)" % (name, l2)))
    ks = [k for k, i in enumerate(ins) if lines[k] == lset and calls(i, SET_INT)]
    assert len(ks) == 1 and ins[ks[0] - 2].op_str == "edx, edx" and ins[ks[0] - 1].mnemonic == "lea", name
    amount = mem(ins[ks[0] - 1])
    # the stat switch right after reads the master's attack / defense / intelligence / realspeed into amount
    sw = [rip(i) for i in ins[ks[0]:ks[0] + 200] if i.mnemonic == "mov" and i.op_str.startswith("edx, dword ptr [rip")]
    assert [varname(x) for x in sw[:4]] == ["attack", "defense", "intelligence", "realspeed"], (name, sw[:4])
    assert sum(1 for i in ins[ks[0]:ks[0] + 200] if i.mnemonic == "lea" and i.op_str == "rcx, [rbp - 0x78]") >= 4, name
    t = tramp(key, p)
    p["edits"].append(call_redirect(ins[ks[0]].address, SET_INT, t, "%s L%d Unstable Horror: amount = 0 -> the master's "
                                    "Maximum Health when the stat is Health" % (name, lset)))

# ---- SU-0275 Grandiose -----------------------------------------------------------------------------------------------
# Never writes into a game array or a game-owned value (2026-10-26 crash: the first version overwrote list[0] of the
# fetched array, which can be the creature's own stored list). The fetch hook is a pure pass-through that records, in
# the DLL, (array identity, its list[0], the counter for the same creature). Each site's single list[0] read (ELEM, the
# array element read helper: returns a pointer the caller only reads) goes to a hook that runs the original read and,
# when the array and its list[0] match the record, returns a pointer to a fresh real holding the counter instead.
# Anything unexpected returns the original pointer.
GB, GD, CB, CD = FN["bc_GetCreatureBuffs"], FN["bc_GetCreatureDebuffs"], FN["bc_CountBuffs"], FN["bc_CountDebuffs"]
assert (GB, GD, CB, CD) == (0x1411422e0, 0x141142ab0, 0x140689e20, 0x14068d0c0)
# The counters take a creature list ([0] = count), not a creature (2026-10-28 crash: the hook passed the creature and
# bc_CountBuffs L9 indexed a non-array). argument0 is indexed directly: the runtime's "not an array" error call comes
# before the first variable read. hooks_J.c builds [1, creature] for them.
for _c in (CB, CD):
    _ci = [i for i in S.disasm(_c, _c + 0x600) if i.mnemonic == "call"]
    _t = [int(i.op_str, 16) for i in _ci if i.op_str.startswith("0x")]
    assert 0x147897fe0 in _t and 0x1478bbd70 in _t and _t.index(0x147897fe0) < _t.index(0x1478bbd70), hex(_c)
_e = S.disasm(ELEM, ELEM + 0x50)                       # ELEM(arr, idx) -> &data[idx]
assert [i.mnemonic for i in _e[:6]] == ["push", "sub", "mov", "mov", "and", "cmp"] and _e[5].op_str == "eax, 2", "ELEM"
# helpers that consume the element pointer as a read-only source (out = rcx, a stack temp; element in rdx or r8)
READERS = {ASSIGN: "copy", 0x14028c630: "dst += src", 0x140290cc0: "out = a * b", 0x1402e06c0: "out = n * a",
           0x1402e0680: "out = a * f", 0x1402bd5a0: "a <= b", 0x1402908a0: "out = a + b"}
p = patch("SU-0275", "Grandiose (and Redefined): effects that count buffs / debuffs see the +3 (Lenience, Holy Might, "
                     "Reckoning, Pandemonium Exploit, Under Stress, Swell, Nighttaker, Ruin, Daybreaker, Heresy and two "
                     "spells) (code: they counted the raw list)", "heavy")
tb = tramp("buffs", p); td = tramp("debuffs", p); te = tramp("elem", p)
SITES = [(0x140e1a071, "B", "Lenience"), (0x140eadf77, "B", "Holy Might"), (0x140dc5bd5, "B", "Reckoning"),
         (0x140e72f7d, "B", "Pandemonium Exploit"), (0x1408931b4, "B", "spell: +10% per buff"),
         (0x1406df0f1, "D", "Under Stress"), (0x140ecf85e, "D", "Under Stress"), (0x14138231a, "D", "Swell"),
         (0x140dfa2b9, "D", "Nighttaker"), (0x140e28fd3, "D", "Ruin"), (0x140ec0a4b, "D", "Ruin"),
         (0x140e7559c, "D", "Daybreaker"), (0x140eb24c9, "D", "Heresy"), (0x1408b2eca, "D", "spell: chance per debuff")]
_jumps = {}
for site, kind, what in SITES:
    name = host(site); ins, lines, _ = fn(name); k = at(name, site)
    target = GB if kind == "B" else GD
    assert calls(ins[k], target), hex(site)
    _, argc = args_before(name, k)
    assert argc == 1, (hex(site), argc)
    assert ins[k + 1].op_str == "rdx, rax" and calls(ins[k + 3], ASSIGN), hex(site)
    st = ins[k + 2]
    if st.mnemonic == "mov":                          # Reckoning: stored into the instance variable count2, read [0]
        assert st.op_str == "rcx, qword ptr [rsp + 0x123a0]", st.op_str
        rd = [j for j in range(k, k + 40) if ins[j].mnemonic == "mov" and rip(ins[j]) == 0x149934128]
        assert len(rd) == 1 and varname(0x149934128) == "count2" and ins[rd[0] + 4].op_str == "edx, edx" and \
            calls(ins[rd[0] + 6], ELEM), hex(site)
        # the count2 slot pointer goes straight into the element read
        assert calls(ins[rd[0] + 2], 0x140297c10) and ins[rd[0] + 3].op_str == "qword ptr [rsp + 0x123a8], rax" and \
            ins[rd[0] + 5].op_str == "rcx, qword ptr [rsp + 0x123a8]", hex(site)
        refs = [i for i in S.disasm(*S.func_range("bc_EventDamage")) if i.mnemonic == "mov" and rip(i) == 0x149934128]
        assert len(refs) == 2, "count2 is read elsewhere"
        rk = rd[0] + 6; end = rk + 1
    else:
        X = mem(st); reads = []; end = len(ins)
        for j in range(k + 4, len(ins)):
            if mem(ins[j]) != X:
                continue
            nx, pv = ins[j + 1], ins[j - 1]
            if ins[j].op_str.startswith("rcx") and ((calls(nx, ASSIGN) and pv.op_str == "rdx, rax") or
                                                     calls(nx, SET_INT)):
                end = j; break                        # reassigned: a different value from here on
            if calls(nx, ELEM) and pv.op_str == "edx, edx":
                assert ins[j].mnemonic == "lea" and ins[j].op_str == "rcx, [%s + %#x]" % X, ins[j].op_str
                reads.append(j + 1); continue         # list[0], the count
            if ins[j].op_str.startswith("rcx") and (calls(nx, FREE1) or calls(nx, FREE2)) and (pv.mnemonic == "nop" or calls(pv, FREE2)):
                continue                              # function-exit release
            raise SystemExit("%s %#x: list used at %#x (%s)" % (what, site, ins[j].address, ins[j].op_str))
        assert len(reads) == 1, (hex(site), reads)
        rk = reads[0]
    # the element pointer is only read: moved into rdx / r8 of the next helper call, whose out (rcx) is a stack temp
    assert ins[rk + 1].op_str in ("rdx, rax", "r8, rax"), (hex(site), ins[rk + 1].op_str)
    cj = next(j for j in range(rk + 2, rk + 6) if ins[j].mnemonic == "call")
    assert int(ins[cj].op_str, 16) in READERS, (hex(site), ins[cj].op_str)
    assert ins[cj - 1].mnemonic == "lea" and re.match(r"rcx, \[rsp \+ 0x[0-9a-f]+\]$", ins[cj - 1].op_str), hex(site)
    assert not any("rax" in i.op_str or "r8" in i.op_str and ins[rk + 1].op_str == "r8, rax" for i in ins[rk + 2:cj]), \
        hex(site)
    # the read always follows its own fetch: nothing jumps into (fetch, read] from outside, except a loop back-edge
    # (Swell: `i <= list[0]` is a loop condition) from before the local's reassignment to after the store of the list,
    # so the local still holds the fetched list. The record is therefore not consumed by a read.
    if name not in _jumps:
        _jumps[name] = [(i.address, int(i.op_str, 16)) for i in ins
                        if i.mnemonic.startswith("j") and i.op_str.startswith("0x")]
    lo_w, hi_w, stored = site, ins[rk].address, ins[k + 3].address
    hi_s = ins[end].address if end < len(ins) else 1 << 64
    bad = [(a, t) for a, t in _jumps[name] if lo_w < t <= hi_w and not (lo_w <= a <= hi_w)
           and not (hi_w < a < hi_s and t > stored)]
    assert not bad, (hex(site), [(hex(a), hex(t)) for a, t in bad])
    p["edits"].append(call_redirect(site, target, tb if kind == "B" else td, "%s L%d %s: list fetch -> pass-through, "
        "records the %s value" % (name, lines[k], what, "bc_CountBuffs" if kind == "B" else "bc_CountDebuffs")))
    p["edits"].append(call_redirect(ins[rk].address, ELEM, te, "%s L%d %s: list[0] read -> the recorded %s count "
        "(fresh value)" % (name, lines[rk], what, "buff" if kind == "B" else "debuff")))

# ---- space and overlap -----------------------------------------------------------------------------------------------
taken = []
for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
    if f.endswith("hooks_J.json"):
        continue
    for q in json.load(open(f, encoding="utf-8"))["patches"]:
        if q["id"] in OWN:
            continue
        for e in q["edits"]:
            taken.append((int(e["va"], 16), int(e["va"], 16) + len(e["expect"]) // 2, q["id"]))
        for r in q.get("reserves", []):
            taken.append((int(r["start"], 16), int(r["end"], 16) + 1, q["id"]))
        for h in q.get("runtime_hooks", []):
            taken.append((int(h["slot_va"], 16), int(h["slot_va"], 16) + 8, q["id"]))
b = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["build"]
assert any(int(x["start"], 16) <= CODE_LO and CODE_HI < int(x["end"], 16) for x in b["xcaves"]), "code range not in an xcave"
assert int(b["data_cave_start"], 16) <= DATA_LO and DATA_HI < int(b["data_cave_end"], 16), "data range not in the data cave"
mine = []
for q in P:
    for r in q["reserves"]:
        lo, hi = int(r["start"], 16), int(r["end"], 16)
        assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), r
    for e in q["edits"]:
        a = int(e["va"], 16); n = len(e["expect"]) // 2
        if not (CODE_LO <= a <= CODE_HI):
            assert raw(a, n).hex() == e["expect"], "expect mismatch @%s" % e["va"]
        mine.append((a, a + n, q["id"]))
    for x0, x1 in [(int(r["start"], 16), int(r["end"], 16) + 1) for r in q["reserves"]] + \
                  [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in q["edits"]]:
        for lo, hi, pid in taken:
            assert x1 <= lo or hi <= x0, "%s %#x overlaps %s" % (q["id"], x0, pid)
mine.sort()
for (a, b_, i), (c, d, j) in zip(mine, mine[1:]):
    assert b_ <= c, "self overlap %s / %s @%#x" % (i, j, c)
# no edit lands inside another instruction's bytes that something jumps to (call redirects keep the E8 opcode)
json.dump({"patches": P}, open(os.path.join(HERE, "hooks_J.json"), "w", encoding="utf-8", newline="\n"), indent=2,
          ensure_ascii=False)
print("hooks_J.json: %d patches, %d edits; code %#x-%#x (%d of %d bytes); data %#x-%#x" % (
    len(P), sum(len(q["edits"]) for q in P), CODE_LO, at_code[0] - 1, at_code[0] - CODE_LO, CODE_HI - CODE_LO + 1,
    DATA_LO, max(SLOT.values()) + 7))
