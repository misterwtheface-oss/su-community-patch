"""Audit every patch that makes game code jump over a range (jmp / jcc -> jmp, directly or through a cave stub) for
stack locals that are first set inside the skipped range and then used after the landing point. YYC code releases an
RValue temp before reusing it, and runs destructors on its locals at the exit; a slot the skipped code would have
initialised holds stack garbage instead, which gets freed. The same goes for registers: the compiler keeps a zero
register (r15) and cached constants (xmm9, xmm12, ...) that it first sets inside a block and relies on afterwards
(SU-0027 crash, 2026-10-26: r15 garbage became the spell-switch index).

python tools/skip_audit.py

Heuristic (address order, rbp/rsp displacement match): it over-reports. Saved-register restores in the epilogue and
slots whose first use after the landing is a plain write are dropped; anything left must be checked by hand and either
fixed (initialise the slot in the stub) or added to KNOWN with the reason.
"""
import bisect, collections, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.argv = sys.argv[:1]
import capstone
import gmlsite as S

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CAVE_LO, CAVE_HI = 0x1488bf5e0, 0x1488c0000
XCAVES = ((0x149856700, 0x149857000), (0x14a343100, 0x14a344000))
in_cave = lambda a: CAVE_LO <= a < CAVE_HI or any(lo <= a < hi for lo, hi in XCAVES)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
REG_ALIAS = {"eax": "rax", "ax": "rax", "al": "rax", "ah": "rax", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "ecx": "rcx",
             "cx": "rcx", "cl": "rcx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "esi": "rsi", "si": "rsi", "sil": "rsi",
             "edi": "rdi", "di": "rdi", "dil": "rdi"}


def reg(n):
    n = REG_ALIAS.get(n, n)
    m = re.match(r"(r\d+)[dwb]?$", n)
    return m.group(1) if m else n


VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"}


def reg_access(i):
    r, w = i.regs_access()
    r, w = {reg(i.reg_name(x)) for x in r}, {reg(i.reg_name(x)) for x in w}
    if i.mnemonic == "call":                                            # Win64: the callee sets the volatile registers
        w |= VOLATILE
    ops = [o.strip() for o in i.op_str.split(",")]
    if i.mnemonic in ("xor", "pxor", "xorps", "sub") and len(ops) == 2 and ops[0] == ops[1]:
        r -= w                                                          # zeroing idiom: a write, not a read
    return r, w
WRITE = re.compile(r"^(byte|word|dword|qword|xmmword) ptr \[")
# (patch, site, slot) checked by hand: not a real read-before-set
KNOWN = {
    ("SU-0108", 0x141463ea6, "rsp+0x14ec0"): "args array: the first use after the landing writes element 0",
    ("SU-0108", 0x141463ea6, "rsp+0x15058"): "prologue home of the 'other' argument (written before sub rsp)",
    ("SU-0136", 0x140b22374, "rsp+0x25d70"): "args array: the first use after the landing writes element 0",
    ("SU-0136", 0x140b22374, "rsp+0x26058"): "prologue home of the 'other' argument (written before sub rsp)",
    ("SU-0136", 0x140b22374, "rsp+0x25d28"): "iterator: the S1 stub clears +0x10, the only field its destructor reads",
    ("SU-0136", 0x140b22374, "rsp+0x25d48"): "iterator: the S1 stub clears +0x10, the only field its destructor reads",
    ("SU-0204", 0x1466302c6, "r15"): "jne -> jmp over the same range the original jne skips; r15d is zeroed before the branch",
}


def main():
    spec = json.load(open(os.path.join(ROOT, "loader", "patches.json"), encoding="utf-8"))
    cave = {}                                                           # address -> byte, every cave edit
    for p in spec["patches"]:
        for e in p["edits"]:
            va = int(e["va"], 16)
            if in_cave(va):
                for k, x in enumerate(bytes.fromhex(e["write"])):
                    cave[va + k] = x

    def cave_bytes(a):
        out = bytearray()
        while a in cave and len(out) < 4096:
            out.append(cave[a]); a += 1
        return bytes(out)

    def landings(stub, seen, stub_ins):
        out = set()
        if stub in seen:
            return out
        seen.add(stub)
        for i in md.disasm(cave_bytes(stub), stub):
            stub_ins.append(i)
            if i.mnemonic.startswith("j") and i.op_str.startswith("0x"):
                t = int(i.op_str, 16)
                out |= landings(t, seen, stub_ins) if in_cave(t) else {t}
                if i.mnemonic == "jmp":
                    break
            if i.mnemonic in ("ret", "int3") or (i.mnemonic == "jmp" and not i.op_str.startswith("0x")):
                break
        return out

    funcs, cache, bad = S.FUNCS, {}, 0

    def slots(ins, a, b):
        out = collections.defaultdict(list)
        for i in ins:
            if a <= i.address < b:
                for m in re.finditer(r"\[(rbp|rsp) ([+-]) (0x[0-9a-f]+)\]", i.op_str):
                    out["%s%s%s" % (m.group(1), m.group(2), m.group(3))].append(i)
        return out

    for p in spec["patches"]:
        for e in p["edits"]:
            va = int(e["va"], 16)
            if in_cave(va) or va >= 0x149000000:
                continue
            new = list(md.disasm(bytes.fromhex(e["write"]), va))
            old = list(md.disasm(bytes.fromhex(e["expect"]), va))
            if not new or new[0].mnemonic != "jmp" or not new[0].op_str.startswith("0x"):
                continue
            o = old[0] if old else None
            if o is not None and o.mnemonic == "jmp":
                continue
            skip_lo = o.address + o.size if (o is not None and o.mnemonic.startswith("j") and o.op_str == new[0].op_str) \
                else va + new[0].size
            t = int(new[0].op_str, 16)
            stub_ins = []
            lands = landings(t, set(), stub_ins) if in_cave(t) else {t}
            k = bisect.bisect_right(funcs, va) - 1
            flo, fhi = funcs[k], funcs[k + 1]
            if flo not in cache:
                cache[flo] = list(md.disasm(S.pe.get_data(flo - S.BASE, fhi - flo), flo))
            ins = cache[flo]
            for land in sorted(lands):
                if not (flo <= land < fhi) or land <= skip_lo:
                    continue
                sk, bef, aft = slots(ins, skip_lo, land), slots(ins, flo, skip_lo), slots(ins, land, fhi)
                for s, xs in slots(stub_ins, 0, 1 << 64).items():               # slots the stub itself writes
                    if any(x.mnemonic == "mov" and WRITE.match(x.op_str) for x in xs):
                        bef[s] += xs
                # registers set in the skipped range and read (before any write) after the landing, in address order
                wsk = set()
                for i in ins:
                    if skip_lo <= i.address < land:
                        wsk |= reg_access(i)[1]
                for i in stub_ins:
                    wsk -= reg_access(i)[1]
                firsts = {}
                for i in ins:
                    if i.address < land:
                        continue
                    r, w = reg_access(i)
                    if i.mnemonic == "call":
                        r = {x for x in r if x not in VOLATILE or x in ("rcx", "rdx", "r8", "r9")}
                    for x in r:
                        firsts.setdefault(x, ("R", i))
                    for x in w:
                        firsts.setdefault(x, ("W", i))
                for x, (k, i) in sorted(firsts.items()):
                    if k == "R" and x in wsk and x not in ("rsp", "rbp", "rflags", "rip") and (p["id"], va, x) not in KNOWN:
                        bad += 1
                        print("CHECK %s site %#x -> %#x: register %s set in the skipped range, read at %#x (%s %s)" % (
                            p["id"], va, land, x, i.address, i.mnemonic, i.op_str))
                for s in sk:
                    if s in bef or s not in aft or (p["id"], va, s) in KNOWN:
                        continue
                    first = aft[s][0]
                    if first.mnemonic == "mov" and WRITE.match(first.op_str):
                        continue                                         # written first: fine
                    if first.mnemonic == "mov" and first.op_str.split(",")[0] in ("rbx", "rbp", "rsi", "rdi", "r12",
                                                                                  "r13", "r14", "r15") \
                            and any(x.mnemonic == "ret" for x in S.disasm(first.address, first.address + 0x40)):
                        continue                                         # epilogue register restore
                    bad += 1
                    print("CHECK %s site %#x -> %#x: %s first set in the skipped range, used at %#x (%s %s)" % (
                        p["id"], va, land, s, first.address, first.mnemonic, first.op_str))
    print("skip audit: %d slot(s) to check" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
