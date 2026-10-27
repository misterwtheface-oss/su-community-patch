"""Build research/hooks_L.json: hook batch L (errata round 2: spells, sealing, cards, luck). See loader/hooks_L.c.
Records: SU-0212, SU-0289 (cannot be Sealed: read-side), SU-0271 (Gemcutter side), SU-0226 (Chaos Rift tag),
SU-0228 / SU-0229 (Velox / Lagopus stat spells), SU-0233 (Ice Bolt), SU-0235 (Shellbust), SU-0242 (Smith p2),
SU-0272 (Giftwrapped Army), SU-0222 (Spin the Wheel, enemy holder).
Verifies every expected byte, call target and assumption against the exe. Assigned space only:
code 0x14a343d00-0x14a343fff (_RDATA slack, xcave), data 0x149ed8a50-0x149ed8acf (.data BSS)."""
import glob, json, os, re, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x14a343d00, 0x14a343fff, 0x149ed8a50, 0x149ed8acf
OWN = ("SU-0212", "SU-0289", "SU-0271", "SU-0226", "SU-0228", "SU-0229", "SU-0233", "SU-0235", "SU-0242", "SU-0272",
       "SU-0222")
# data (must match loader/hooks_L.c)
SLOT = dict(r0289=0x149ed8a50, s0289=0x149ed8a58, f0212=0x149ed8a60, a0271=0x149ed8a68, e0271=0x149ed8a70,
            v0228=0x149ed8a78, l0228=0x149ed8a80, f0229=0x149ed8a88, g0272=0x149ed8a90, w0222=0x149ed8a98,
            d0235=0x149ed8aa0, m0235=0x149ed8aa8)

VARGET, GT_INT, CALL_LEGACY = 0x1478bbd70, 0x14028ca10, 0x147898420
ANY_ALLY, ANY_ENEMY = 0x141f0a8a0, 0x141f0b2d0
V_SEALED = 0x1499e3348
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def rd(va, n):
    return S.pe.get_data(va - S.BASE, n)


def ins_at(va):
    return S.disasm(va, va + 16)[0]


def rip_target(i):
    m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
    assert m, (hex(i.address), i.op_str)
    return i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)


def host(va):
    import bisect
    k = bisect.bisect_right(S.FUNCS, va) - 1
    return S.NAMES.get(S.FUNCS[k])


def call_target(site):
    b = rd(site, 5)
    assert b[0] == 0xE8, hex(site)
    return site + 5 + int.from_bytes(b[1:], "little", signed=True)


def call_redirect(site, target, tramp, note):
    assert call_target(site) == target, "%#x calls %#x, not %#x" % (site, call_target(site), target)
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def before(site, n=0x60):
    """Instructions in the ~n bytes before site: decoded from the farthest start that lands exactly on site (x86 decoding
    resynchronises within a few instructions, so the far start gives the true instruction boundaries near site)."""
    for back in range(n + 64, n - 1, -1):
        ins = S.disasm(site - back, site + 16)
        if ins and any(i.address == site for i in ins):
            return [i for i in ins if i.address < site and i.address >= site - n]
    raise SystemExit("cannot decode before %#x" % site)


def loads_const(site, value, n=0xa0):
    """A rip-relative load of the double `value` shortly before site (the argument the call passes)."""
    for i in before(site, n):
        if "rip" in i.op_str and i.mnemonic in ("lea", "movups", "movsd", "movaps"):
            t = rip_target(i)
            try:
                if struct.unpack("<d", rd(t, 8))[0] == value:
                    return True
            except Exception:
                pass
    return False


def gname(slot):
    p = struct.unpack("<Q", rd(slot - 8, 8))[0]
    return rd(p, 64).split(b"\0")[0].decode()


def init_string(g):
    """The C string a static string global is initialised with (lea rdx,[str]; lea rcx,[g] in the init stubs)."""
    lo, hi = 0x140001000, 0x140290000
    data = rd(lo, hi - lo)
    for k in range(len(data) - 14):
        if data[k:k + 3] == b"\x48\x8d\x0d" and lo + k + 7 + int.from_bytes(data[k + 3:k + 7], "little", signed=True) == g:
            i = S.disasm(lo + k - 7, lo + k)
            if i and i[0].mnemonic == "lea" and i[0].op_str.startswith("rdx"):
                return rd(rip_target(i[0]), 64).split(b"\0")[0].decode()
    return None


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def main():
    assert gname(V_SEALED) == "sealed" and gname(0x1499e0b28) == "spellid" and gname(0x1499354c8) == "is_ultimate"
    assert gname(0x1499e0aa8) == "slot" and gname(0x1499e0668) == "crits" and gname(0x1499e3228) == "creature"
    assert gname(0x1499c91b8) == "amount" and gname(0x1499e1f18) == "creatureturn"
    for a, n in [(0x141f0a8a0, "scr_AnyAllyHasPassive"), (0x141f0b2d0, "scr_AnyEnemyHasPassive"),
                 (0x1464eb110, "scr_PerkLevel"), (0x140601da0, "bc_AllRace"), (0x141dbb120, "inv_SpellIsBooze"),
                 (0x141644100, "bc_SpellGemGetOwner"), (0x141168b80, "bc_GetRandomBuff"), (0x14104ff60, "bc_EventLoseDefense"),
                 (0x1417a2e70, "big_mult"), (0x141cf6e10, "inv_CardSetPowerUnlocked")]:
        assert S.NAMES.get(a) == n, (hex(a), S.NAMES.get(a), n)

    taken = []
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_L.json"):
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
    assert int(b["data_cave_start"], 16) <= DATA_LO and DATA_HI < int(b["data_cave_end"], 16)

    at = [CODE_LO]

    def tramp(slot, sym):
        code = asm("jmp qword ptr [%#x]" % slot, at[0])
        lo = at[0]; at[0] += len(code)
        assert at[0] - 1 <= CODE_HI
        return lo, chunks(lo, code, "trampoline -> " + sym), res(lo, len(code), "trampoline -> " + sym)

    patches = []

    # ---------------- SU-0289 Master of Spellmanes (+ the shared read hooks SU-0212 uses)
    READS = [0x140871b47, 0x1408f4db5, 0x140b427ae, 0x140bb699e, 0x140df34b2, 0x140e10689, 0x140e5ac84, 0x140e948ba,
             0x140eb228e, 0x140eb5f3e, 0x141186428, 0x141186b8f, 0x1413840ed, 0x1414d427e, 0x1417ad154, 0x1417bf823,
             0x1417d3123, 0x1417e5d4a]
    for s in READS:
        prev = [i for i in before(s, 0x30) if i.mnemonic == "mov" and i.op_str.startswith("edx, dword ptr [rip")]
        assert prev and rip_target(prev[-1]) == V_SEALED, "%#x: not a sealed read" % s
        assert call_target(s) == VARGET
    assert sorted(set(host(s) for s in READS)) == ["bc_CreatureCast", "bc_CreatureStartOfTurn", "bc_EventDamage",
                                                   "bc_GetSpellGems", "bc_OnAttack", "bc_OnDeath", "crit_attack",
                                                   "crit_defense", "crit_intelligence", "crit_speed"]
    # every sealed read in battle code is covered (bc_CritCanCastSpell's is SU-0137's)
    STEP_LO, STEP_HI = 0x1476442e0, 0x147647800                      # gml_Object_obj_spellgem_manager_Step_0
    STEP_SITE = 0x147646471                                          # L77 scr_AnyEnemyHasPassive(1815)
    assert call_target(STEP_SITE) == ANY_ENEMY and loads_const(STEP_SITE, 1815.0)
    p = before(STEP_SITE, 0x10)                                      # self = the with-loop gem, other = the manager
    assert p[-1].op_str == "rcx, qword ptr [rbp + 0x460]" and p[-2].op_str == "rdx, qword ptr [rbp + 0x468]"
    assert ins_at(0x1476463bc).op_str == "dword ptr [rbp - 0x80], 0x4d"                 # L77, top level of the gem loop
    assert call_target(0x14764665e) == ANY_ALLY and call_target(0x1476465a1) == 0x140601da0
    assert init_string(0x149e25bb0) == "Spellmane"
    assert struct.unpack("<d", rd(0x14992a870, 8))[0] == 1.0 and rd(0x14992a870, 16)[12:16] == b"\0\0\0\0"
    # the Step's other unseal rules, copied into hooks_L.c: 288, ultimate && perk 313, booze && perk 608, 431-435 && 292
    assert [struct.unpack("<d", rd(a, 8))[0] for a in range(0x148d59620, 0x148d59648, 8)] == [431, 432, 433, 434, 435]
    for a, v in [(0x148d591a0, 288), (0x14992a880, 313), (0x14992a860, 608), (0x14992a890, 292), (0x14992a8b0, 1988),
                 (0x14992a850, 1815)]:
        assert struct.unpack("<d", rd(a, 8))[0] == v, hex(a)
    e, rv = [], []
    t_read, c, r = tramp(SLOT["r0289"], "hook_l_su0289_sealed"); e += c; rv.append(r)
    t_step, c, r = tramp(SLOT["s0289"], "hook_l_su0289_step"); e += c; rv.append(r)
    for s in READS:
        e.append(call_redirect(s, VARGET, t_read, "%s gem.sealed read -> hook: a gem that cannot be Sealed reads as not sealed" % host(s)))
    e.append(call_redirect(STEP_SITE, ANY_ENEMY, t_step, "spell-gem manager Step L77 AnyEnemyHasPassive(1815) -> hook: same answer, refreshes the unseal rules"))
    rv += [res(SLOT["r0289"], 8, "hook pointer hook_l_su0289_sealed"), res(SLOT["s0289"], 8, "hook pointer hook_l_su0289_step")]
    patches.append({"id": "SU-0289", "bug": "SU-0289", "default": 1, "group": "heavy",
                    "title": "Master of Spellmanes: gems that can't be sealed read as unsealed at once (code: sealed until "
                             "the gem manager's next pass); also the read side of SU-0212",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["r0289"]), "symbol": "hook_l_su0289_sealed"},
                                      {"slot_va": hex(SLOT["s0289"]), "symbol": "hook_l_su0289_step"}]})

    # ---------------- SU-0212 Diabolism / Straight Up / Unstoppable Force (flag; rules live in the SU-0289 / SU-0137 hooks)
    patches.append({"id": "SU-0212", "bug": "SU-0212", "default": 1,
                    "title": "Diabolism / Straight Up / Unstoppable Force: their gems read as unsealed at once (code: sealed "
                             "until the gem manager's next pass). Needs SU-0289 (shared sealed-read hooks) and SU-0137 (cast check)",
                    "edits": [], "reserves": [res(SLOT["f0212"], 8, "SU-0212 on-flag (hook pointer slot)")],
                    "runtime_hooks": [{"slot_va": hex(SLOT["f0212"]), "symbol": "hook_l_su0212_flag"}]})

    # ---------------- SU-0271 Gemcutter: the unseal counts only for the holder's side
    GA, GE = 0x147646ce1, 0x147646da4
    assert STEP_LO <= GA < STEP_HI and STEP_LO <= GE < STEP_HI
    assert loads_const(GA, 1988.0) and loads_const(GE, 1988.0)
    assert call_target(0x147646e80) == 0x141dbd080 and S.NAMES.get(0x141dbd080) == "inv_SpellIsUltimate"
    for s in (GA, GE):                                               # self = the with-loop gem ([rbp+0x460])
        p = before(s, 0x10)
        assert p[-1].op_str == "rcx, qword ptr [rbp + 0x460]" and p[-2].op_str == "rdx, qword ptr [rbp + 0x468]", hex(s)
    e, rv = [], []
    ta, c, r = tramp(SLOT["a0271"], "hook_l_su0271_ally"); e += c; rv.append(r)
    te, c, r = tramp(SLOT["e0271"], "hook_l_su0271_enemy"); e += c; rv.append(r)
    e += [call_redirect(GA, ANY_ALLY, ta, "spell-gem manager Step L87 AnyAllyHasPassive(1988) -> hook: your gems only"),
          call_redirect(GE, ANY_ENEMY, te, "spell-gem manager Step L87 AnyEnemyHasPassive(1988) -> hook: enemy gems only")]
    rv += [res(SLOT["a0271"], 8, "hook pointer hook_l_su0271_ally"), res(SLOT["e0271"], 8, "hook pointer hook_l_su0271_enemy")]
    patches.append({"id": "SU-0271", "bug": "SU-0271", "default": 1,
                    "title": "Gemcutter unseals only its own side's Ultimate gems (code: every Ultimate gem on the field "
                             "when either side has it)",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["a0271"]), "symbol": "hook_l_su0271_ally"},
                                      {"slot_va": hex(SLOT["e0271"]), "symbol": "hook_l_su0271_enemy"}]})

    # ---------------- SU-0226 Chaos Rift: category tag BOOST -> UTILITY
    LEA = 0x1459d9e17
    assert host(LEA) == "scr_DatabaseSpellGems2"
    i = ins_at(LEA)
    assert i.mnemonic == "lea" and i.op_str.startswith("rdx") and rip_target(i) == 0x149dd4940
    assert init_string(0x149dd4940) == "BOOST" and init_string(0x149dd43e0) == "UTILITY"
    # the spell block: line 1879 is Chaos Rift's tag (its name / description globals are stored at lines 1859 / 1860)
    assert init_string(0x149dd4780) == "L_SN_CHAOSRIFT" and init_string(0x149dd4a00) == "L_SD_CHAOSRIFT"
    m = ins_at(LEA - 11)
    assert m.op_str == "dword ptr [rsp + 0x36570], 0x757", m.op_str
    for va, g in [(0x1459d7e97, 0x149dd4780), (0x1459d8169, 0x149dd4a00)]:
        assert rip_target(ins_at(va)) == g
    assert ins_at(0x1459d7dab).op_str.endswith("0x743") and ins_at(0x1459d807d).op_str.endswith("0x744")   # L1859 / L1860
    assert ins_at(0x1459db9b8).op_str.endswith("0x76b")                                                    # next spell L1899
    patches.append({"id": "SU-0226", "bug": "SU-0226", "default": 1,
                    "title": "Chaos Rift is filed as a utility spell (code: a stat-boosting spell), so Velox / Lagopus / "
                             "Temptation rank 100 no longer pick it",
                    "edits": [{"va": hex(LEA + 3), "expect": le(0x149dd4940 - (LEA + 7)), "write": le(0x149dd43e0 - (LEA + 7)),
                               "note": "scr_DatabaseSpellGems2 L1879 Chaos Rift category: \"BOOST\" -> \"UTILITY\" string"}],
                    "reserves": [], "runtime_hooks": []})

    # ---------------- SU-0228 / SU-0229 Velox / Lagopus: Dark Ritual and Death Siphon count as stat spells
    VEL, LAG = 0x1416c64a3, 0x1416c90b3                               # bc_StartupCasting L153 / L293 first tag test
    pro = S.disasm(0x1416c2950, 0x1416c2970)
    assert [x.mnemonic for x in pro[:8]] == ["mov", "push", "push", "push", "push", "push", "push", "push"]
    assert pro[8].op_str == "rbp, [rsp - 0xe60]" and pro[9].op_str == "rsp, 0xf60"   # rbp = rsp + 0x100
    for s, sp_off, line in [(VEL, 0x460, 0x99), (LAG, 0x410, 0x125)]:
        p = before(s, 0x120)
        assert p[-1].op_str == "edx, edx" and p[-2].op_str == "rcx, rax" and call_target(p[-3].address) == CALL_LEGACY, hex(s)
        lea = [x for x in p if x.mnemonic == "lea" and "rip" in x.op_str]
        assert lea and rip_target(lea[0]) == 0x149d687a0 and init_string(0x149d687a0) == "DEBOOST", hex(s)
        v = [x for x in p if x.mnemonic == "mov" and x.op_str.startswith("edx, dword ptr [rip")]
        assert rip_target(v[0]) == 0x1499e0b28                        # spellid read into [rbp+sp_off]
        r9 = [x for x in p if x.op_str == "r9, [rbp + %#x]" % sp_off]
        assert r9 and r9[0].address < v[0].address, hex(s)
        nxt = S.disasm(s + 5, s + 13)
        assert nxt[0].op_str == "al, al" and nxt[1].mnemonic == "jne", hex(s)
        mk = [x for x in before(s, 0x200) if x.op_str == "dword ptr [rsp + 0x60], %#x" % line]
        assert mk, "line marker %#x before %#x" % (line, s)
    e, rv = [], []
    tv, c, r = tramp(SLOT["v0228"], "hook_l_su0228_velox"); e += c; rv.append(r)
    tl, c, r = tramp(SLOT["l0228"], "hook_l_su0228_lagopus"); e += c; rv.append(r)
    e += [call_redirect(VEL, GT_INT, tv, "bc_StartupCasting L153 (Velox) DEBOOST tag test -> hook: also Dark Ritual (35) / Death Siphon (37)"),
          call_redirect(LAG, GT_INT, tl, "bc_StartupCasting L293 (Lagopus) DEBOOST tag test -> hook: also Dark Ritual (35) / Death Siphon (37)")]
    rv += [res(SLOT["v0228"], 8, "hook pointer hook_l_su0228_velox"), res(SLOT["l0228"], 8, "hook pointer hook_l_su0228_lagopus")]
    patches.append({"id": "SU-0228", "bug": "SU-0228", "default": 1,
                    "title": "Velox / Lagopus also cast Dark Ritual, a stat-changing spell (code: only BOOST / DEBOOST-tagged gems)",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["v0228"]), "symbol": "hook_l_su0228_velox"},
                                      {"slot_va": hex(SLOT["l0228"]), "symbol": "hook_l_su0228_lagopus"}]})
    patches.append({"id": "SU-0229", "bug": "SU-0229", "default": 1,
                    "title": "Velox / Lagopus also cast Death Siphon, a stat-changing spell (code: only BOOST / DEBOOST-tagged "
                             "gems). Needs SU-0228 (shared tag-test hook)",
                    "edits": [], "reserves": [res(SLOT["f0229"], 8, "SU-0229 on-flag (hook pointer slot)")],
                    "runtime_hooks": [{"slot_va": hex(SLOT["f0229"]), "symbol": "hook_l_su0229_flag"}]})

    # ---------------- SU-0233 Ice Bolt: Frozen regardless of the damage
    JE = 0x1409be087
    assert host(JE) == "bc_CreatureCast" and rd(JE, 6).hex() == "0f8489050000"
    assert call_target(0x1409be07d) == GT_INT
    assert ins_at(0x1409be051).op_str.endswith("0x3cbc") and ins_at(0x1409be08d).op_str.endswith("0x3cbd")   # L15548 / L15549
    assert rip_target(ins_at(0x1409be2dc)) == 0x1498e52d0 and struct.unpack("<d", rd(0x1498e52d0, 8))[0] == 21.0
    assert call_target(0x1409be582) == 0x140fdb040 and S.NAMES.get(0x140fdb040) == "bc_EventDebuff"
    assert ins_at(0x1409be61b).op_str.endswith("0x3cc1")             # the je target region ends the statement (L15553)
    patches.append({"id": "SU-0233", "bug": "SU-0233", "default": 1,
                    "title": "Ice Bolt always afflicts Frozen (code: only when its damage on the target is above 0)",
                    "edits": [{"va": hex(JE), "expect": "0f8489050000", "write": "660f1f440000",
                               "note": "bc_CreatureCast L15548: the damage > 0 jump is removed, L15549-L15550 (Frozen) always run"}],
                    "reserves": [], "runtime_hooks": []})

    # ---------------- SU-0235 Shellbust: damage from the amount actually reduced
    LOSE, MULT = 0x1408ae52f, 0x1408aeb58
    assert host(LOSE) == host(MULT) == "bc_CreatureCast"
    assert call_target(LOSE) == 0x14104ff60 and call_target(MULT) == 0x1417a2e70
    assert ins_at(0x1408ae18c).op_str.endswith("0x24cc") and ins_at(0x1408ae764).op_str.endswith("0x24d8")   # L9420 / L9432
    assert rip_target(ins_at(0x1408aea50)) == 0x1498e5fc0 and struct.unpack("<d", rd(0x1498e5fc0, 8))[0] == 1.5
    for s in (LOSE, MULT):                                            # k = [rsp+0x2fd80] indexes this target's entries
        assert any(x.op_str == "rcx, [rsp + 0x2fd80]" for x in before(s, 0x200)), hex(s)
        p = before(s, 0x20)
        assert p[-1].op_str == "rcx, qword ptr [rsp + 0x42990]" and p[-2].op_str == "rdx, qword ptr [rsp + 0x42998]", hex(s)
    assert ins_at(0x1408ae9cd).op_str == "rcx, [rsp + 0x2fd80]"        # big_mult's amount[k]
    e, rv = [], []
    tdl, c, r = tramp(SLOT["d0235"], "hook_l_su0235_lose"); e += c; rv.append(r)
    tml, c, r = tramp(SLOT["m0235"], "hook_l_su0235_mult"); e += c; rv.append(r)
    e += [call_redirect(LOSE, 0x14104ff60, tdl, "bc_CreatureCast L9420 Shellbust bc_EventLoseDefense -> hook: record the loss that really happens"),
          call_redirect(MULT, 0x1417a2e70, tml, "bc_CreatureCast L9432 Shellbust big_mult(amount, 1.5) -> hook: 150% of the recorded loss")]
    rv += [res(SLOT["d0235"], 8, "hook pointer hook_l_su0235_lose"), res(SLOT["m0235"], 8, "hook pointer hook_l_su0235_mult")]
    patches.append({"id": "SU-0235", "bug": "SU-0235", "default": 1,
                    "title": "Shellbust deals 150% of the Defense actually lost (code: of the planned loss, even when it is "
                             "blocked, reflected or turned into a gain)",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["d0235"]), "symbol": "hook_l_su0235_lose"},
                                      {"slot_va": hex(SLOT["m0235"]), "symbol": "hook_l_su0235_mult"}]})

    # ---------------- SU-0242 Smith cards power 2: only the trick slots that activate
    SMITH_NAME = None
    e = []
    for grp, je in [(2, 0x141ce2859), (3, 0x141ce2d8e), (5, 0x141ce323b), (6, 0x141ce3505), (7, 0x141ce37d3),
                    (8, 0x141ce3aa1), (9, 0x141ce3d69)]:
        call = je - 0x0f
        assert call_target(call) == 0x141cf6e10 and rd(je, 2)[0] == 0x74, hex(je)
        assert S.disasm(call + 5, je)[-1].op_str == "al, al"
        p = before(call, 0x60)
        nm = [x for x in p if x.mnemonic == "lea" and x.op_str.startswith("rdx, [rip")]
        g = rip_target(nm[0])
        SMITH_NAME = SMITH_NAME or g
        assert g == SMITH_NAME, hex(je)
        assert loads_const(call, 2.0, 0x40), hex(je)
        blk = S.disasm(je + 2, je + 2 + rd(je, 2)[1])
        assert [x.mnemonic for x in blk if x.mnemonic == "call"] == ["call"] * 3       # mul temp, add, release (only)
        assert call_target(blk[-1].address) == 0x14028c220 and "[rsp + 0x58]" in blk[-2].op_str
        if grp >= 5:
            e.append({"va": hex(je), "expect": "74", "write": "eb",
                      "note": "inv_ArtifactGetStat trick group %d: Smith power 2 bonus skipped (not an activation chance)" % grp})
    assert init_string(SMITH_NAME) == "Smith", init_string(SMITH_NAME)
    patches.append({"id": "SU-0242", "bug": "SU-0242", "default": 1,
                    "title": "Smith cards power 2 raise only the buff / debuff trick slots' activation chance (code: every "
                             "trick slot's value by 10%)",
                    "edits": e, "reserves": [], "runtime_hooks": []})

    # ---------------- SU-0272 Giftwrapped Army: the Mimic is passed to bc_GetRandomBuff
    GRB = 0x1416a5f08
    assert host(GRB) == "bc_StartupBuffsDebuffs" and call_target(GRB) == 0x141168b80
    assert rip_target(ins_at(0x1416a5e97)) == 0x1498f7290 and struct.unpack("<d", rd(0x1498f7290, 8))[0] == -1.0
    assert ins_at(0x1416a5db1).op_str.endswith("0x3ed") and ins_at(0x1416a5f1d).op_str.endswith("0x3ee")   # L1005 / L1006
    assert loads_const(0x1416a593a, 1298.0, 0x80) and call_target(0x1416a593a) == ANY_ALLY             # L1000 gate
    assert ins_at(0x1416a597c).op_str == "rcx, [rsp + 0x48]" and call_target(0x1416a5981) == 0x14028c530   # i = 1
    assert ins_at(0x1416a59c4).op_str == "rcx, [rsp + 0x48]" and ins_at(0x1416a59bf).op_str == "edx, 6"   # i <= 6
    assert ins_at(0x1416a6001).op_str == "rcx, [rsp + 0x48]" and call_target(0x1416a6006) == 0x14028c580   # L1006 crits[i]
    assert rip_target(ins_at(0x1416a6020)) == 0x1499e0668 and call_target(0x1416a602e) == VARGET
    e, rv = [], []
    tg, c, r = tramp(SLOT["g0272"], "hook_l_su0272_randbuff"); e += c; rv.append(r)
    e.append(call_redirect(GRB, 0x141168b80, tg, "bc_StartupBuffsDebuffs L1005 bc_GetRandomBuff(-1) -> hook: pass the Mimic"))
    rv.append(res(SLOT["g0272"], 8, "hook pointer hook_l_su0272_randbuff"))
    patches.append({"id": "SU-0272", "bug": "SU-0272", "default": 1,
                    "title": "Giftwrapped Army gives each Mimic buffs it doesn't already have (code: repeats possible)",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["g0272"]), "symbol": "hook_l_su0272_randbuff"}]})

    # ---------------- SU-0222 Spin the Wheel: the enemy holder's half
    JSLOT, CALL = 0x1466679b6, 0x146667a1a
    assert host(JSLOT) == "scr_Roll" and rd(JSLOT, 6).hex() == "0f84e7000000"
    assert S.disasm(0x146667993, 0x1466679b6)[1].op_str == "dil" and ins_at(0x1466679b3).op_str == "dil, dil"
    assert call_target(0x14666796a) == VARGET and rip_target(ins_at(0x146667961)) == 0x1499e0aa8   # creatureturn.slot
    assert JSLOT + 6 + 0xe7 == 0x146667aa3 and ins_at(0x146667aa3).op_str.endswith("0x2b")           # skip -> L43
    assert rip_target(ins_at(0x1466679e7)) == 0x14990a950 and struct.unpack("<d", rd(0x14990a950, 8))[0] == 1765.0
    assert ins_at(0x146667a1f).op_str == "rcx, rax" and call_target(0x146667a22) == 0x147871cf0
    # SU-0001 (loader/patches.json) makes this block reachable in battle
    s1 = [p for p in json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["patches"]
          if p["id"] == "SU-0001"]
    assert s1 and s1[0]["edits"][0]["va"] == "0x1466674d8"
    e, rv = [], []
    tw, c, r = tramp(SLOT["w0222"], "hook_l_su0222_luck"); e += c; rv.append(r)
    e += [{"va": hex(JSLOT), "expect": "0f84e7000000", "write": "660f1f440000",
           "note": "scr_Roll L36: the 'enemy's turn' (slot == 0) jump is removed; the hook below picks the side"},
          call_redirect(CALL, ANY_ALLY, tw, "scr_Roll L36 AnyAllyHasPassive(1765) -> hook: your side on an enemy's turn, the enemy side on yours")]
    rv.append(res(SLOT["w0222"], 8, "hook pointer hook_l_su0222_luck"))
    patches.append({"id": "SU-0222", "bug": "SU-0222", "default": 1,
                    "title": "Spin the Wheel also works for an enemy holder, on your creatures' turns (code: only your "
                             "holder on enemy turns). Needs SU-0001",
                    "edits": e, "reserves": rv,
                    "runtime_hooks": [{"slot_va": hex(SLOT["w0222"]), "symbol": "hook_l_su0222_luck"}]})

    # ---------------- space and overlap
    mine = []
    for p in patches:
        for r in p["reserves"]:
            lo, hi = int(r["start"], 16), int(r["end"], 16)
            assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), r
        for x in [(int(r["start"], 16), int(r["end"], 16) + 1) for r in p["reserves"]] + \
                 [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in p["edits"]]:
            for lo, hi, pid in taken:
                assert x[1] <= lo or hi <= x[0], "%s %#x overlaps %s" % (p["id"], x[0], pid)
            for lo, hi, pid in mine:
                assert x[1] <= lo or hi <= x[0] or pid == p["id"], "%s %#x overlaps %s" % (p["id"], x[0], pid)
        for r in p["reserves"]:
            mine.append((int(r["start"], 16), int(r["end"], 16) + 1, p["id"]))
        for d in p["edits"]:
            mine.append((int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2, p["id"]))
        for d in p["edits"]:                                          # cave chunks expect zeros; game edits match the exe
            va = int(d["va"], 16)
            if not (CODE_LO <= va <= CODE_HI):
                assert rd(va, len(d["expect"]) // 2).hex() == d["expect"], (p["id"], d["va"])
    assert sorted(p["id"] for p in patches) == sorted(OWN)
    json.dump({"patches": patches}, open(os.path.join(HERE, "hooks_L.json"), "w", encoding="utf-8", newline="\n"),
              indent=2, ensure_ascii=False)
    print("hooks_L.json: %d patches; code %#x-%#x (%d of %d bytes); data %#x-%#x" % (
        len(patches), CODE_LO, at[0] - 1, at[0] - CODE_LO, CODE_HI - CODE_LO + 1, DATA_LO, max(SLOT.values()) + 7))


if __name__ == "__main__":
    main()
