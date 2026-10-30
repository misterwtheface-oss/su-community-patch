"""Build research/hooks_M.json: errata round-2 batch M (attacks, Avatar traits, overworld). See loader/hooks_M.c.
SU-0301 Roulette (cave stub, heavy), SU-0286 Master of Hounds, SU-0243 Teleportation Shrine, SU-0268 Forbearance + Master of
Wights, SU-0200 Disarmed (heavy), SU-0280 Improbable Catapult (heavy, partial). SU-0249 (battle music) is not built:
its gate already lets the realm-music swap run in battle when the option is off (see the SU-0249 record).
Verifies every expect byte, call target, frame offset and jump-safety assumption against the exe. Assigned space only:
code 0x149856700-0x149856bff (.rdata slack, loader-made executable), data 0x149ed8258-0x149ed82ff (.data BSS)."""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
from build_h01b import asm, chunks

CODE_LO, CODE_HI, DATA_LO, DATA_HI = 0x149856700, 0x149856bff, 0x149ed8258, 0x149ed82ff
MY_IDS = ("SU-0301", "SU-0286", "SU-0243", "SU-0268", "SU-0200", "SU-0280", "SU-0249")
# data (must match loader/hooks_M.c)
SLOT_AVATAR, SLOT_HOUND_E, SLOT_HOUND_A, SLOT_SHRINE = 0x149ed8258, 0x149ed8260, 0x149ed8268, 0x149ed8270
SLOT_WDIM, SLOT_WEQ, SLOT_DTRAIT, SLOT_DNETHER = 0x149ed8278, 0x149ed8280, 0x149ed8288, 0x149ed8290
WIGHT_FLAG, BLACK_PASS, BLACK_MORE = 0x149ed8298, 0x149ed829c, 0x149ed829d

# runtime / scripts
VARGET, EQ, SUB_INT = 0x1478bbd70, 0x14028c8d0, 0x1402c47f0
ANY_ALLY, ANY_ENEMY = 0x141f0a8a0, 0x141f0b2d0
GT_INT, EQ_INT, TO_BOOL, TO_BOOL2, CMP_VAL = 0x14028ca10, 0x14028c8f0, 0x147871cf0, 0x1402be230, 0x1478a6470
SLOT_VAR = 0x1499e0aa8
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()

FLAG_READ = re.compile(r"^(j(?!mp)|set|cmov|adc|sbb|pushf|lahf)")
FLAG_WRITE = {"cmp", "test", "add", "sub", "and", "or", "xor", "inc", "dec", "neg", "shl", "shr", "sar", "imul", "popf", "sahf"}


def ins_at(va):
    return S.disasm(va, va + 16)[0]


def rip_target(i):
    m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
    return i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1) if m else None


def flags_dead(va):
    for i in S.disasm(va, va + 160):
        if FLAG_READ.match(i.mnemonic):
            raise SystemExit("flags live at %#x (%s %s)" % (va, i.mnemonic, i.op_str))
        if i.mnemonic in FLAG_WRITE or i.mnemonic in ("call", "ret") or i.mnemonic == "jmp":
            return


def call_redirect(site, target, tramp, note):
    b = S.pe.get_data(site - S.BASE, 5)
    assert b[0] == 0xE8 and site + 5 + int.from_bytes(b[1:], "little", signed=True) == target, (hex(site), hex(target))
    return {"va": hex(site + 1), "expect": le(target - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def nop_jcc(va, target, note):
    """NOP a `je target` (2 or 6 bytes): the game then always takes the path it takes for the tested side."""
    i = ins_at(va)
    assert i.mnemonic == "je" and int(i.op_str, 16) == target, (hex(va), i.mnemonic, i.op_str)
    n = i.size
    assert n in (2, 6)
    return {"va": hex(va), "expect": bytes(i.bytes).hex(), "write": "6690" if n == 2 else "660f1f440000", "note": note}


def res(lo, n, what):
    return {"start": hex(lo), "end": hex(lo + n - 1), "what": what}


def fn_of(va):
    import bisect
    k = bisect.bisect_right(S.FUNCS, va) - 1
    return S.FUNCS[k], S.FUNCS[k + 1]


_FN_CACHE = {}


def window(site, before, after=0):
    """Instructions around site, decoded from its function start (no misaligned decode)."""
    lo, hi = fn_of(site)
    if lo not in _FN_CACHE:
        _FN_CACHE[lo] = S.disasm(lo, hi)
    ins = _FN_CACHE[lo]
    k = [n for n, x in enumerate(ins) if x.address == site][0]
    return ins[max(0, k - before):k + after + 1]


def calls_to(lo, hi, target):
    return [i.address for i in S.disasm(lo, hi) if i.mnemonic == "call" and i.op_str == hex(target)]


# ------------------------------------------------------------------------------------------------- SU-0301 Roulette
# bc_CreatureAttack hit loop L1076-L1892 (continue block 0x1406d0568, back edge 0x1406f6748, exit 0x1406f674d).
# Roulette L1742-L1776 sits in it. Its heal branch: L1746-L1773 queue one bc_EventHeal per creature, L1775 dmg = 0,
# L1776 `return`. The return's tail (0x1406f09a2: store the return value, 0x1406f09b2: jmp epilogue) is SHARED with the
# pre-loop L176 exit (Stomp, jmp from 0x1406a7ef9 to 0x1406f09a2): the first build retargeted 0x1406f09b2 and so sent
# Stomp-failed attacks into the hit loop before `i` was ever set (in-game: 'STRING argument is unset' at L1076 = the
# ++ of an unset i). Now the detour is the L1776 line marker 0x1406f098a, reached only from the heal branch; the shared
# tail is untouched. The stub runs L1789 (attacker.first_attack_done = true, which every hit runs) and joins the path a
# dodged hit takes after its dodge branch: L1871 (0x1406f4cb3, the L1834 `not dodged or still hits` false target), so
# the heal hit skips the dodge branch and the damage event, then runs the per-hit end (L1871-L1892) and the next hit.
RL_SITE, RL_TAIL, RL_TAILJMP, RL_EPILOGUE = 0x1406f098a, 0x1406f09a2, 0x1406f09b2, 0x1406f957d
RL_L1775, RL_HEAL_LO = 0x1406f0973, 0x1406efbc5                  # L1775 dmg = 0; L1742 Roulette gate
RL_L1789, RL_L1789_END, RL_L1871 = 0x1406f1472, 0x1406f14e2, 0x1406f4cb3
RL_CONTINUE, RL_BACKEDGE, RL_LOOP_EXIT = 0x1406d0568, 0x1406f6748, 0x1406f674d
RL_STOMP_JMP = 0x1406a7ef9
RL_TEMPS = {0x48, 0x58, 0xa8, 0x1b8}            # YYC temps: each use is `release, reset kind`, then the call writes it
RL_ARGS = (0xc0, 0x350)                         # argument pointer array + argument RValue array (assigned by helpers)
RL_WRITERS = {0x14028c530, 0x14028c410, 0x14028c4a0, 0x14028c3b0, 0x14028c360, 0x14028c3d0}   # helpers: rcx = dest
RL_VARGET = 0x1478bbd70


def check_su0301():
    lo, hi = S.func_range("bc_CreatureAttack")
    ins = S.disasm(lo, hi)
    at = {x.address: n for n, x in enumerate(ins)}
    # the site: L1776 marker (8 bytes), after L1775 dmg = 0; then the shared return tail
    s = ins[at[RL_SITE]]
    assert s.op_str == "dword ptr [rsp + 0x40], 0x6f0" and s.size == 8
    assert ins[at[RL_L1775]].op_str == "dword ptr [rsp + 0x40], 0x6ef"
    assert ins[at[RL_TAILJMP]].mnemonic == "jmp" and int(ins[at[RL_TAILJMP]].op_str, 16) == RL_EPILOGUE
    assert RL_TAIL in at and RL_SITE + 8 < RL_TAIL
    jumps = [(x.address, int(x.op_str, 16)) for x in ins if x.mnemonic.startswith("j") and x.op_str.startswith("0x")]
    # every jump into [L1775, tail) comes from the Roulette block; the only foreign entry is Stomp's into the tail
    for src, t in jumps:
        if RL_L1775 <= t < RL_TAIL:
            assert RL_HEAL_LO <= src < RL_L1775, "jump into the heal-branch end from %#x" % src
            assert t == RL_L1775, "jump into L1776 itself from %#x" % src
    assert (RL_STOMP_JMP, RL_TAIL) in jumps                                  # the shared tail (left untouched)
    # the Roulette block is only entered from inside the hit loop
    for src, t in jumps:
        if RL_HEAL_LO <= t < RL_TAIL:
            assert RL_CONTINUE <= src < RL_LOOP_EXIT, hex(src)
    # loop shape: back edge -> continue block; the dodged path joins at L1871 (L1834 false target)
    assert (RL_BACKEDGE, RL_CONTINUE) in jumps
    assert ins[at[RL_L1871]].op_str == "dword ptr [rsp + 0x40], 0x74f"
    j1834 = [src for src, t in jumps if t == RL_L1871]
    assert j1834 and all(0x1406f3848 <= src < RL_L1871 for src in j1834), [hex(x) for x in j1834]
    assert ins[at[0x1406f3848]].op_str == "dword ptr [rsp + 0x40], 0x72a"   # L1834 (if !dodged || still_hits)
    flags_dead(RL_L1871)
    # no non-volatile register is written anywhere in the loop (so no register state rides across the skipped code)
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    canon = lambda n: {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi", "al": "rax",
                       "bl": "rbx", "cl": "rcx", "dl": "rdx", "sil": "rsi", "dil": "rdi"}.get(n, re.sub(r"^(r\d+)[dwb]$", r"\1", n))
    nv = {"rbx", "rsi", "rdi", "r12", "r13", "r14", "r15", "rbp"} | {"xmm%d" % k for k in range(6, 16)}
    for x in md.disasm(S.pe.get_data(RL_CONTINUE - S.BASE, RL_LOOP_EXIT - RL_CONTINUE), RL_CONTINUE):
        for r in x.regs_access()[1]:
            assert canon(x.reg_name(r)) not in nv, hex(x.address)
    # at the landing every register is written before it is read (up to the first call, after which volatiles are dead)
    seen = set()
    for x in md.disasm(S.pe.get_data(RL_L1871 - S.BASE, 0x200), RL_L1871):
        r, w = x.regs_access()
        r = {canon(x.reg_name(y)) for y in r} - {"rsp", "rip", "rflags"}
        if x.mnemonic == "call":
            break
        assert r <= seen, ("register read before set at L1871", hex(x.address), r - seen)
        seen |= {canon(x.reg_name(y)) for y in w}

    # ---- stack-slot audit (both directions), regions in address order:
    HEAL, R1 = (RL_HEAL_LO, RL_SITE), (RL_L1789_END, RL_L1871)            # heal branch; code the heal hit now skips
    LATER = [(RL_L1871, RL_LOOP_EXIT), (RL_LOOP_EXIT, RL_EPILOGUE), (RL_CONTINUE, RL_HEAL_LO)]  # per-hit end, post, next hit

    def refs(a, b):
        out = {}
        for n, x in enumerate(ins):
            if a <= x.address < b:
                for m in re.finditer(r"\[rsp \+ (0x[0-9a-f]+)\]", x.op_str):
                    out.setdefault(int(m.group(1), 16), []).append(n)
        return out

    def writes(n):
        x = ins[n]
        if x.mnemonic == "mov" and re.match(r"(byte|word|dword|qword) ptr \[rsp", x.op_str):
            return True
        if x.mnemonic == "lea":
            reg = x.op_str.split(",")[0]
            for y in ins[n + 1:n + 12]:
                if y.mnemonic == "call":
                    t = int(y.op_str, 16) if y.op_str.startswith("0x") else None
                    return (reg == "rcx" and t in RL_WRITERS) or (reg == "r9" and t == RL_VARGET) or reg == "r8"
                if y.op_str.split(",")[0] == reg:
                    return False              # pointer kept for an argument array / release block: checked below
        return False

    def is_temp_release(n):                   # lea rax, [rsp+T]; mov [rsp+X], rax; ... (release, reset kind to 5)
        x, y = ins[n], ins[n + 1]
        return x.op_str.startswith("rax, [rsp + ") and y.mnemonic == "mov" and y.op_str.endswith(", rax")

    for name, (a, b) in (("heal branch", HEAL), ("skipped L1791-L1870", R1)):
        for slot, ns in refs(a, b).items():
            if not any(writes(n) for n in ns):
                continue                      # only read there: the heal path leaves it as it was
            if RL_ARGS[0] <= slot < RL_ARGS[1]:
                continue                      # argument arrays: every call assigns its own entries first
            for la, lb in LATER:
                r = refs(la, lb).get(slot)
                if not r:
                    continue
                if slot in RL_TEMPS:
                    assert is_temp_release(r[0]), (name, hex(slot), hex(ins[r[0]].address))
                else:
                    assert writes(r[0]), ("%s writes %#x, read first at %#x" % (name, slot, ins[r[0]].address))
    return ins, at


def su0301_stub(ins, at, base):
    """L1789 replayed instruction by instruction (calls and rip operands re-encoded for the cave), then jmp L1871."""
    src = []
    for x in ins[at[RL_L1789]:at[RL_L1789_END]]:
        if x.mnemonic == "call":
            src.append("call %s" % x.op_str)
        elif "rip" in x.op_str:
            src.append("%s %s" % (x.mnemonic, re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", "[%#x]" % rip_target(x), x.op_str)))
        else:
            src.append("%s %s" % (x.mnemonic, x.op_str))
    src.append("jmp %#x" % RL_L1871)
    code = asm("\n".join(src), base)
    # the replica decodes to the same instructions and targets as the original
    got = S.md.disasm(code, base)
    want = ins[at[RL_L1789]:at[RL_L1789_END]]
    got = list(got)
    for g, w in zip(got, want):
        assert g.mnemonic == w.mnemonic, (hex(g.address), g.mnemonic, w.mnemonic)
        if w.mnemonic == "call":
            assert g.op_str == w.op_str
        elif "rip" in w.op_str:
            assert rip_target(g) == rip_target(w) and re.sub(r"\[rip.*\]", "", g.op_str) == re.sub(r"\[rip.*\]", "", w.op_str)
        else:
            assert g.op_str == w.op_str, (g.op_str, w.op_str)
    assert len(got) == len(want) + 1 and got[-1].mnemonic == "jmp" and int(got[-1].op_str, 16) == RL_L1871
    assert any(rip_target(w) == 0x1499e1878 for w in want)                 # first_attack_done
    return code


# --------------------------------------------------------------------------------------- SU-0286 Master of Hounds
HD_ENEMY, HD_ALLY = 0x1413271b7, 0x14132738c          # bc_OnAttack L1067 side gates (1447)
HD_OWNER = 0x168f0                                    # attacker = the Dire Wolves' owner


def check_su0286():
    lo, hi = S.func_range("bc_OnAttack")
    for site in (HD_ENEMY, HD_ALLY):
        ins = window(site, 140)
        assert any(x.op_str == "rcx, [rsp + %#x]" % HD_OWNER for x in ins if x.mnemonic == "lea"), hex(site)
        assert any(rip_target(x) == 0x1498f1ae0 for x in ins if x.mnemonic == "lea"), hex(site)    # 1447.0
    # L1066 base = crit_speed of the same creature, L1065 loop over its Dire Wolves (condition 48)
    assert S.disasm(0x141326eb6, 0x141326ec1)[0].op_str == "dword ptr [rsp + 0x20150], 0x42a"


# --------------------------------------------------------------------------------- SU-0243 Teleportation Shrine
SH_FN, SH_SITE, SH_FINISHED = 0x1474478e0, 0x147448938, 0x149940b08


def check_su0243():
    p = S.disasm(SH_FN, SH_FN + 0x25)
    assert [x.op_str for x in p[:2]] == ["qword ptr [rsp + 0x10], rdx", "qword ptr [rsp + 8], rcx"]
    assert [x.mnemonic for x in p[2:10]] == ["push"] * 8
    assert p[10].op_str == "rbp, [rsp - 0x348]" and p[11].op_str == "rsp, 0x448"      # self home = [rsp + 0x490]
    s = S.disasm(SH_SITE - 13, SH_SITE + 0x1e)
    assert s[0].op_str == "r8d, 0x3e8" and s[1].op_str == "rdx, rsi"                      # ppower - 1000
    assert any(x.mnemonic == "call" and x.op_str == hex(0x140290d30) for x in s)          # < 0
    f = S.disasm(0x147448c49, 0x147448c5b)
    assert rip_target(f[0]) == SH_FINISHED and f[1].op_str == "rcx, qword ptr [rbp + 0x390]"


# ----------------------------------------------------------------------------- SU-0268 Forbearance + Master of Wights
WD_DIM, WD_DIMFN, WD_EQ = 0x141083cd1, 0x1460713c0, 0x141083f0e


def check_su0268():
    lo, hi = S.func_range("bc_EventResurrect")
    p = S.disasm(lo, lo + 0x20)
    assert [x.mnemonic for x in p[1:8]] == ["push"] * 7 and p[8].op_str == "rbp, [rsp - 0x2c0]" and p[9].op_str == "rsp, 0x3c0"
    d = S.disasm(0x141083c77, WD_DIM)
    assert d[3].op_str == "rcx, [rsp + 0x50]" and rip_target(d[2]) == 0x1499c91b8                # amount of the event
    assert any(x.op_str == "rax, [rbp + 0x170]" for x in d)                                     # the bonus pool
    e = S.disasm(0x141083ef3, WD_EQ)
    assert rip_target(e[0]) == 0x149d63110                                                       # "Wight"
    assert S.disasm(0x141083e9f, 0x141083ea7)[0].op_str == "dword ptr [rsp + 0x70], 0x97"         # L151
    assert S.disasm(0x141083f27, 0x141083f2f)[0].op_str == "dword ptr [rsp + 0x70], 0x98"         # L152 amount = hpmax
    assert ins_at(WD_EQ + 0x13).mnemonic == "je" and int(ins_at(WD_EQ + 0x13).op_str, 16) == 0x141083fbc


# --------------------------------------------------------------------------------------------- SU-0200 Disarmed
DS_TRAIT = 0x14202ce41          # scr_CritHasPassive L60: creature.artifact
DS_NETHER, DS_NETHERFN = 0x141ceffa3, 0x141d97fd0   # inv_ArtifactStatTotal L41: inv_NetherStoneGetStat(stone, prop)


def check_su0200():
    t = S.disasm(0x14202ce2c, DS_TRAIT)
    assert rip_target(t[2]) == 0x1499e2058 and t[3].op_str == "rcx, [rsp + 0x58]"
    after = S.disasm(DS_TRAIT + 5, DS_TRAIT + 0x70)
    j = [x for x in after if x.mnemonic == "je" and x.op_str == "0x14202d1ac"]
    assert j, "L60 -1 test must skip to L75"
    lo, hi = S.func_range("inv_ArtifactStatTotal")
    p = S.disasm(lo, lo + 0x30)
    assert p[12].op_str == "rbp, [rax - 0xf8]" and p[13].op_str == "rsp, 0x1b8"
    n = S.disasm(0x141cefce1, 0x141cefcec)
    assert rip_target(n[0]) == 0x149930258 and n[1].op_str == "rcx, [rsp + 0x70]"           # item.nether, item at rsp+0x70
    c = S.disasm(DS_NETHER - 0x2d, DS_NETHER)
    assert c[0].op_str == "rax, [rbp + 0x70]" and c[2].op_str == "rax, [rbp - 0x70]"          # (stone, prop)


# ------------------------------------------------------------------------------------ SU-0280 Improbable Catapult
# (call site, subject, ptr, mode, slot-test call or None, slot-test kind) ; mode 0 = holder on the subject's side,
# 1 = opposite side, 2 = The Black gate, 3 = The Black holder. subject: frame offset (rsp-relative at the call)
AV_SITES = [
    ("Firelord", 0x1406e7766, 0x68, 0, 0, 0x1406e7601),
    ("Prayer Position (damage)", 0x140e1cca2, 0x21fd8, 0, 0, 0x140e1ca81),
    ("Prayer Position (end of turn)", 0x140b07d59, 0x48, 1, 0, 0x140b07bf4),
    ("Avenged Sevenfold", 0x140e969e1, 0x21fd8, 0, 0, 0x140e96876),
    ("Expanded Power", 0x1415aff0c, 0xb728, 0, 0, 0x1415afda1),
    ("The End (gate)", 0x140b06b36, 0x48, 1, 1, 0x140b069d1),
    ("The End (attacker)", 0x140b0710b, 0x48, 1, 1, None),
    ("The End (highest stat)", 0x140b0729f, 0x48, 1, 1, None),
    ("Perfect Imperfection (taken)", 0x140e19b0a, 0x21fd8, 0, 0, 0x140e1999f),
    ("Perfect Imperfection (dealt)", 0x140ea4fec, 0x21fc8, 0, 0, 0x140ea4e81),
    ("The Truth (cast)", 0x14145c615, 0x88, 0, 0, 0x14145c5a7),
    ("The Truth (defend)", 0x141536bb8, 0x88, 0, 0, 0x141536b4b),
    ("The Truth (provoke)", 0x14156b960, 0x88, 0, 0, 0x14156b8f4),
    ("The Truth (start of turn)", 0x140c5ddd9, 0xba58, 1, 0, 0x140c5dc6e),
    ("The Truth (attack)", 0x1413b100e, 0x168f0, 0, 0, 0x1413b0ea3),
    ("The Truth (Nether Stone stats)", 0x141d9a829, 0x120, 0, 0, 0x141d9a79d),
    ("The Black (gate)", 0x1412b8c50, 0, 0, 2, None),
    ("The Black (holder)", 0x1412b8cf5, 0, 0, 3, None),
]
TRAIT_IDS = {"Firelord": 612, "Prayer": 598, "Avenged": 611, "Expanded": 607, "The End": 604, "Perfect": 609,
             "The Truth": 605, "I HATE": 610, "The Black": 600}
BLACK_END, BLACK_L564 = 0x1412b95e7, 0x1412b8c65


def frame_shift(fn_lo):
    """rsp-relative offset of rbp in the function (0 for rsp-only frames)."""
    for x in S.disasm(fn_lo, fn_lo + 0x40):
        m = re.match(r"rbp, \[r(sp|ax) - (0x[0-9a-f]+)\]", x.op_str)
        if x.mnemonic == "lea" and m:
            lea = x
            break
    else:
        return None
    pro = S.disasm(fn_lo, fn_lo + 0x60)
    pushes = sum(1 for x in pro[:12] if x.mnemonic == "push")
    sub = None
    for x in pro:
        if x.mnemonic == "sub" and x.op_str.startswith("rsp, 0x"):
            sub = int(x.op_str.split(", ")[1], 16)
        if x.mnemonic == "sub" and x.op_str == "rsp, rax":
            sub = [int(y.op_str.split(", ")[1], 16) for y in pro if y.mnemonic == "mov" and y.op_str.startswith("eax, 0x")][0]
        if sub is not None:
            break
    disp = int(re.search(r"- (0x[0-9a-f]+)\]", lea.op_str).group(1), 16)
    if "rax" in lea.op_str:            # rax = entry rsp; rsp = entry - 8*pushes - sub
        return 8 * pushes + sub - disp
    return sub - disp                  # lea after the pushes


def check_av_site(name, site, off, ptr, mode, test):
    """Returns the NOP edit for the slot test (or None) and asserts the subject location."""
    fn_lo, fn_hi = fn_of(site)
    ins = S.disasm(fn_lo, fn_hi)
    k = [n for n, x in enumerate(ins) if x.address == site][0]
    assert ins[k].op_str == hex(ANY_ALLY), name
    # the trait id fed to this call (or, for the The End holder lookups, the gate's id)
    tid = [v for key, v in TRAIT_IDS.items() if name.startswith(key)][0]
    window = ins[max(0, k - 60):k]
    ids = [S.const_at(rip_target(x)) for x in window if x.mnemonic == "lea" and rip_target(x)]
    if name != "The End (highest stat)":
        assert float(tid) in ids, (name, ids)
    if test is None:
        return None
    t = [n for n, x in enumerate(ins) if x.address == test][0]
    assert ins[t].mnemonic == "call" and int(ins[t].op_str, 16) in (GT_INT, EQ_INT, CMP_VAL), name
    want = EQ_INT if mode == 1 else (GT_INT if int(ins[t].op_str, 16) != CMP_VAL else CMP_VAL)
    assert int(ins[t].op_str, 16) == want, name
    # the varget of the slot right before: rcx = the subject
    vg = [n for n in range(t - 1, t - 12, -1) if ins[n].mnemonic == "call" and ins[n].op_str == hex(VARGET)][0]
    pre = ins[vg - 6:vg]
    assert any(rip_target(x) == SLOT_VAR for x in pre if x.mnemonic == "mov"), name
    rcx = [x for x in pre if x.op_str.startswith("rcx, ")][-1]
    shift = frame_shift(fn_lo) or 0
    if ptr:
        assert rcx.mnemonic == "mov" and rcx.op_str == "rcx, qword ptr [rsp + %#x]" % off, (name, rcx.op_str)
    else:
        m = re.match(r"rcx, \[(rsp|rbp) ([+-]) (0x[0-9a-f]+)\]", rcx.op_str)
        assert rcx.mnemonic == "lea" and m, (name, rcx.op_str)
        o = int(m.group(3), 16) * (1 if m.group(2) == "+" else -1) + (shift if m.group(1) == "rbp" else 0)
        assert o == off, (name, hex(o), hex(off))
    # nothing between the slot read and the call rewrites the subject (EventDamage refetches the same field)
    slotpat = ("[rsp + %#x]" % off) if not ptr else None
    first_var = None
    for n in range(vg - 30, k):
        x = ins[n]
        if slotpat and x.mnemonic == "lea" and x.op_str == "r9, " + slotpat:
            v = [rip_target(y) for y in ins[n:n + 6] if y.mnemonic == "mov" and rip_target(y)][0]
            if n < vg:
                first_var = v
            else:
                assert v == first_var, (name, hex(x.address))
        if ptr and x.op_str.startswith("qword ptr [rsp + %#x], " % off):
            raise SystemExit("subject pointer rewritten in %s" % name)
    # the jcc right after the test, and its target = the gate's false path
    nx = ins[t + 1:t + 7]
    if int(ins[t].op_str, 16) == CMP_VAL:
        j = [x for x in nx if x.mnemonic == "je"]
        j = [x for x in S.disasm(ins[t].address, ins[t].address + 0x40) if x.mnemonic == "je" and x.size == 6][0]
    else:
        assert nx[0].op_str in ("eax, al",) or nx[0].op_str == "al, al", (name, nx[0].op_str)
        j = [x for x in nx[:3] if x.mnemonic == "je"][0]
    tgt = int(j.op_str, 16)
    # false path of the trait call: the je after its ToBool, or the byte the ToBool result is stored in
    after = S.disasm(site + 5, site + 0x30)
    if after[1].mnemonic == "call" and int(after[1].op_str, 16) in (TO_BOOL, TO_BOOL2):
        a2 = after[2:6]
        if a2[0].mnemonic == "mov" and a2[0].op_str.endswith(", al"):          # stored, then tested at tgt
            assert tgt == a2[1].address, (name, hex(tgt), hex(a2[1].address))
        else:
            jj = [x for x in a2 if x.mnemonic == "je"][0]
            assert int(jj.op_str, 16) == tgt, (name, hex(tgt), jj.op_str)
    else:
        raise SystemExit("no bool test after %s" % name)
    return nop_jcc(j.address, tgt, "%s: the side test no longer restricts the trait to one side (holder side "
                                    "decided by the hook)" % name)


def check_black():
    lo, hi = S.func_range("bc_MaintainPermanentEffects")
    ins = S.disasm(lo, hi)
    m = ins_at(BLACK_END)
    assert m.op_str == "dword ptr [rsp + 0x70], 0x24c" and m.size == 8
    assert ins_at(BLACK_L564).op_str == "dword ptr [rsp + 0x70], 0x234"
    assert ins_at(0x1412b8be8).op_str == "dword ptr [rsp + 0x70], 0x232"
    flags_dead(BLACK_END + 8); flags_dead(BLACK_L564)
    g = ins_at(0x1412b8c5f)
    assert g.mnemonic == "je" and int(g.op_str, 16) == BLACK_END                   # gate false -> block end
    assert calls_to(0x1412b8cf5, 0x1412b8d48, 0x141161660)                          # bc_GetEnemiesOf(holder)
    # every jump into (L564, END] comes from inside the block; the block's loop exits only to END
    for x in ins:
        if x.mnemonic.startswith("j") and x.op_str.startswith("0x"):
            t = int(x.op_str, 16)
            inside = BLACK_L564 <= x.address < BLACK_END
            if BLACK_L564 < t < BLACK_END:
                assert inside, "jump into the The Black block %#x" % x.address
            if inside and not (BLACK_L564 <= t <= BLACK_END):
                raise SystemExit("jump out of the The Black block %#x -> %#x" % (x.address, t))
            assert not (BLACK_END < t < BLACK_END + 8), hex(x.address)
    # re-running L564..END: no register read there before being written may be written inside the block
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    canon = lambda n: {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi", "al": "rax",
                       "bl": "rbx", "cl": "rcx", "dl": "rdx", "sil": "rsi", "dil": "rdi"}.get(n, re.sub(r"^(r\d+)[dwb]$", r"\1", n))
    blk = list(md.disasm(S.pe.get_data(BLACK_L564 - S.BASE, BLACK_END - BLACK_L564), BLACK_L564))
    written, read_first = set(), set()
    for x in blk:
        r, w = x.regs_access()
        r = {canon(x.reg_name(y)) for y in r}; w = {canon(x.reg_name(y)) for y in w}
        if x.mnemonic in ("xor", "xorps", "pxor") and x.op_str.split(", ")[0] == x.op_str.split(", ")[-1]:
            r = set()
        if x.mnemonic == "call":
            w |= {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
            r = {y for y in r if y not in ("rax", "r10", "r11")}
        read_first |= {y for y in r if y not in written}
        written |= w
    bad = (read_first & written) - {"rsp", "rip", "rflags", "rbp"}
    assert not bad, ("registers carried between The Black passes", bad)


def main():
    rl_ins, rl_at = check_su0301()
    check_su0286(); check_su0243(); check_su0268(); check_su0200(); check_black()

    taken = []
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_M.json"):
            continue
        for p in json.load(open(f, encoding="utf-8"))["patches"]:
            if p["id"] in MY_IDS:
                continue
            for e in p["edits"]:
                taken.append((int(e["va"], 16), int(e["va"], 16) + len(e["expect"]) // 2, p["id"]))
            for r in p.get("reserves", []):
                taken.append((int(r["start"], 16), int(r["end"], 16) + 1, p["id"]))
    b = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))["build"]
    assert any(int(x["start"], 16) <= CODE_LO and CODE_HI < int(x["end"], 16) for x in b["xcaves"]), "code range not in an xcave"
    assert int(b["data_cave_start"], 16) <= DATA_LO and DATA_HI < int(b["data_cave_end"], 16)
    try:
        raw = S.pe.get_data(CODE_LO - S.BASE, CODE_HI - CODE_LO + 1)
        assert not any(raw), "xcave not zero in the file"
    except Exception as ex:            # past the raw data: zero-filled by the loader's own check (expect 00)
        if isinstance(ex, AssertionError):
            raise

    at = [CODE_LO]

    def put(src, note):
        code = asm(src, at[0])
        lo = at[0]; at[0] += len(code)
        assert at[0] - 1 <= CODE_HI, "code range full at %s" % note
        return lo, code

    def tramp(slot, sym):
        lo, c = put("jmp qword ptr [%#x]" % slot, sym)
        return lo, chunks(lo, c, "trampoline -> " + sym), res(lo, len(c), "trampoline -> " + sym)

    patches = []

    # ---- SU-0301 (cave stub placed after the other patches' code so their bytes do not move; see below)
    rl_patch = {"id": "SU-0301", "bug": "SU-0301", "default": 1, "group": "heavy",
                "title": "Roulette: a heal roll ends only that hit (no damage, like a hit that dealt none), so the "
                         "remaining extra attacks and the after-attack effects still happen (code: the heal roll "
                         "ended the whole attack)",
                "edits": [], "runtime_hooks": [], "reserves": []}
    patches.append(rl_patch)

    # ---- SU-0286
    tE, eE, rE = tramp(SLOT_HOUND_E, "hook_m_su0286_enemy")
    tA, eA, rA = tramp(SLOT_HOUND_A, "hook_m_su0286_ally")
    patches.append({"id": "SU-0286", "bug": "SU-0286", "default": 1,
                    "title": "Master of Hounds: only Hounds' Dire Wolves use the highest stat (code: every Dire Wolf "
                             "owner on the holder's side)",
                    "edits": eE + eA + [
                        call_redirect(HD_ENEMY, ANY_ENEMY, tE, "bc_OnAttack L1067 enemy-side gate (1447) -> hook: the owner must be a Hound"),
                        call_redirect(HD_ALLY, ANY_ALLY, tA, "bc_OnAttack L1067 your-side gate (1447) -> hook: the owner must be a Hound")],
                    "runtime_hooks": [{"slot_va": hex(SLOT_HOUND_E), "symbol": "hook_m_su0286_enemy"},
                                      {"slot_va": hex(SLOT_HOUND_A), "symbol": "hook_m_su0286_ally"}],
                    "reserves": [rE, rA, res(SLOT_HOUND_E, 8, "hook pointer hook_m_su0286_enemy"),
                                 res(SLOT_HOUND_A, 8, "hook pointer hook_m_su0286_ally")]})

    # ---- SU-0243
    tS, eS, rS = tramp(SLOT_SHRINE, "hook_m_su0243_cost")
    patches.append({"id": "SU-0243", "bug": "SU-0243", "default": 1,
                    "title": "Teleportation Shrine: after paying 1,000 Power the Realm Type choice travels (code: the "
                             "cost was checked again after paying and failed below 2,000)",
                    "edits": eS + [call_redirect(SH_SITE, SUB_INT, tS, "obj_realmselector KeyPress_69 L52 ppower - 1000 -> hook: "
                                                                        "no second affordability check once paid")],
                    "runtime_hooks": [{"slot_va": hex(SLOT_SHRINE), "symbol": "hook_m_su0243_cost"}],
                    "reserves": [rS, res(SLOT_SHRINE, 8, "hook pointer hook_m_su0243_cost")]})

    # ---- SU-0268
    tD, eD, rD = tramp(SLOT_WDIM, "hook_m_su0268_diminish")
    tQ, eQ, rQ = tramp(SLOT_WEQ, "hook_m_su0268_race")
    patches.append({"id": "SU-0268", "bug": "SU-0268", "default": 1,
                    "title": "Master of Wights + Forbearance: the Wight's 100% Health is the base the resurrection bonuses "
                             "add to (code: Master of Wights overwrote the bonus with 100%)",
                    "edits": eD + eQ + [
                        call_redirect(WD_DIM, WD_DIMFN, tD, "bc_EventResurrect L147 scr_Diminish(amount, bonus) -> hook: Wight base = Max Health"),
                        call_redirect(WD_EQ, EQ, tQ, "bc_EventResurrect L151 race == Wight -> hook: false once L147 used the Wight base")],
                    "runtime_hooks": [{"slot_va": hex(SLOT_WDIM), "symbol": "hook_m_su0268_diminish"},
                                      {"slot_va": hex(SLOT_WEQ), "symbol": "hook_m_su0268_race"}],
                    "reserves": [rD, rQ, res(SLOT_WDIM, 8, "hook pointer hook_m_su0268_diminish"),
                                 res(SLOT_WEQ, 8, "hook pointer hook_m_su0268_race"),
                                 res(WIGHT_FLAG, 4, "SU-0268 Wight base used")]})

    # ---- SU-0200
    tT, eT, rT = tramp(SLOT_DTRAIT, "hook_m_su0200_artifact")
    tN, eN, rN = tramp(SLOT_DNETHER, "hook_m_su0200_nether")
    patches.append({"id": "SU-0200", "bug": "SU-0200", "default": 1, "group": "heavy",
                    "title": "Disarmed: the Artifact's trait, its Nether Stone's traits and the Nether Stone's trick "
                             "properties are lost too (code: only stats, trick slots and spells were)",
                    "edits": eT + eN + [
                        call_redirect(DS_TRAIT, VARGET, tT, "scr_CritHasPassive L60 creature.artifact -> hook: none while Disarmed"),
                        call_redirect(DS_NETHER, DS_NETHERFN, tN, "inv_ArtifactStatTotal L41 Nether Stone property -> hook: 0 for non-stat properties while Disarmed")],
                    "runtime_hooks": [{"slot_va": hex(SLOT_DTRAIT), "symbol": "hook_m_su0200_artifact"},
                                      {"slot_va": hex(SLOT_DNETHER), "symbol": "hook_m_su0200_nether"}],
                    "reserves": [rT, rN, res(SLOT_DTRAIT, 8, "hook pointer hook_m_su0200_artifact"),
                                 res(SLOT_DNETHER, 8, "hook pointer hook_m_su0200_nether")]})

    # ---- SU-0280
    tV, eV, rV = tramp(SLOT_AVATAR, "hook_m_su0280_any_ally")
    e, rv = list(eV), [rV]
    for name, site, off, ptr, mode, test in AV_SITES:
        nop = check_av_site(name, site, off, ptr, mode, test) if mode in (0, 1) else None
        if nop:
            e.append(nop)
        e.append(call_redirect(site, ANY_ALLY, tV, "%s: scr_AnyAllyHasPassive -> hook (holder side from the subject)" % name))
    bs, c = put("""
        cmp byte ptr [{more:#x}], 0
        je orig
        mov byte ptr [{more:#x}], 0
        mov byte ptr [{pas:#x}], 1
        jmp {l564:#x}
    orig:
        mov dword ptr [rsp + 0x70], 0x24c
        jmp {nxt:#x}""".format(more=BLACK_MORE, pas=BLACK_PASS, l564=BLACK_L564, nxt=BLACK_END + 8), "black")
    e += chunks(bs, c, "SU-0280 The Black: after your side's pass, run the block again for the enemy holder")
    rv.append(res(bs, len(c), "SU-0280 The Black second-pass stub"))
    ob = S.pe.get_data(BLACK_END - S.BASE, 8)
    e.append({"va": hex(BLACK_END), "expect": ob.hex(), "write": "e9" + le(bs - (BLACK_END + 5)) + "909090",
              "note": "bc_MaintainPermanentEffects L588 (end of the The Black block) -> second-pass stub"})
    rv += [res(SLOT_AVATAR, 8, "hook pointer hook_m_su0280_any_ally"), res(BLACK_PASS, 1, "SU-0280 The Black: holder side"),
           res(BLACK_MORE, 1, "SU-0280 The Black: enemy pass pending")]
    patches.append({"id": "SU-0280", "bug": "SU-0280", "default": 1, "group": "heavy",
                    "title": "Improbable Catapult: Avatar traits copied to enemies work for the enemy side (Prayer "
                             "Position, Avenged Sevenfold, Firelord, Expanded Power, The End, Perfect Imperfection's "
                             "damage parts, The Truth, The Black, I HATE YOU); code: your side only",
                    "edits": e, "runtime_hooks": [{"slot_va": hex(SLOT_AVATAR), "symbol": "hook_m_su0280_any_ally"}],
                    "reserves": rv})

    # ---- SU-0301 stub (after every other M cave byte, 16-aligned)
    at[0] = (at[0] + 15) // 16 * 16
    rl_code = su0301_stub(rl_ins, rl_at, at[0])
    rs = at[0]
    at[0] += len(rl_code)
    assert at[0] - 1 <= CODE_HI
    site = asm("jmp %#x" % rs, RL_SITE) + b"\x90\x90\x90"
    assert len(site) == 8
    rl_patch["edits"] = chunks(rs, rl_code, "SU-0301 Roulette heal: L1789 (first_attack_done = true), then join the "
                                            "per-hit end at L1871 like a hit that dealt no damage") + [
        {"va": hex(RL_SITE), "expect": S.pe.get_data(RL_SITE - S.BASE, 8).hex(), "write": site.hex(),
         "note": "bc_CreatureAttack L1776 (Roulette heal `return`, its line marker; the shared return tail at "
                 "0x1406f09a2 stays untouched) -> SU-0301 stub"}]
    rl_patch["reserves"] = [res(rs, len(rl_code), "SU-0301 Roulette heal continuation stub")]
    # no other patch branches into the heal-branch end (L1775-L1776) or edits it
    import capstone as _cs
    _md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
    for f in [os.path.join(HERE, "..", "loader", "patches.json")] + glob.glob(os.path.join(HERE, "hooks_*.json")):
        if f.endswith("hooks_M.json"):
            continue
        for p in json.load(open(f, encoding="utf-8"))["patches"]:
            if p["id"] in MY_IDS:
                continue
            for d in p["edits"]:
                va = int(d["va"], 16)
                assert not (RL_L1775 <= va < RL_TAIL + 21), (p["id"], d["va"])
                for x in _md.disasm(bytes.fromhex(d["write"]), va):
                    if x.mnemonic.startswith("j") or x.mnemonic == "call":
                        if x.op_str.startswith("0x"):
                            assert not (RL_L1775 < int(x.op_str, 16) < RL_TAIL), (p["id"], hex(x.address))
    # the other M patches are live and tested: their bytes must not change
    old = os.path.join(HERE, "hooks_M.json")
    if os.path.exists(old):
        prev = {p["id"]: p for p in json.load(open(old, encoding="utf-8"))["patches"]}
        for p in patches:
            if p["id"] != "SU-0301" and p["id"] in prev:
                assert p["edits"] == prev[p["id"]]["edits"] and p["reserves"] == prev[p["id"]]["reserves"], \
                    "%s changed" % p["id"]

    for p in patches:
        for r in p["reserves"]:
            lo, hi = int(r["start"], 16), int(r["end"], 16)
            assert (CODE_LO <= lo and hi <= CODE_HI) or (DATA_LO <= lo and hi <= DATA_HI), r
        spans = [(int(r["start"], 16), int(r["end"], 16) + 1) for r in p["reserves"]] + \
                [(int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for d in p["edits"]]
        for x in spans:
            for lo, hi, pid in taken:
                assert x[1] <= lo or hi <= x[0], "%s %#x overlaps %s" % (p["id"], x[0], pid)
        for d in p["edits"]:                                            # every expect matches the file (cave = zero)
            va = int(d["va"], 16)
            if CODE_LO <= va <= CODE_HI:
                continue
            assert S.pe.get_data(va - S.BASE, len(d["expect"]) // 2).hex() == d["expect"], d
    allspans = sorted((int(d["va"], 16), int(d["va"], 16) + len(d["expect"]) // 2) for p in patches for d in p["edits"])
    for a, b2 in zip(allspans, allspans[1:]):
        assert a[1] <= b2[0], "own edits overlap at %#x" % b2[0]
    out = json.dumps({"patches": patches}, indent=2, ensure_ascii=False)
    open(os.path.join(HERE, "hooks_M.json"), "w", encoding="utf-8", newline="\n").write(out)
    print("hooks_M.json: %d patches; code %#x-%#x (%d of %d bytes)" % (len(patches), CODE_LO, at[0] - 1, at[0] - CODE_LO,
                                                                        CODE_HI - CODE_LO + 1))
    print("  The Black stub", hex(bs))
    for p in patches:
        for t in p["runtime_hooks"]:
            print("  ", p["id"], t["symbol"], t["slot_va"])


if __name__ == "__main__":
    main()
