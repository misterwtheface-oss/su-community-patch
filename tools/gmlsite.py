"""Locate a GML line inside a YYC function and print its asm with constant values.

python tools/gmlsite.py <function name> <first GML line> [last GML line]
The YYC build stores the current GML line in a stack slot (`mov dword ptr [rsp/rbp+X], line`) before each statement;
this finds that slot automatically (the most common immediate-store target) and lists the code between the markers.
Reads the baseline exe; prints rip-relative doubles/RValues. Our own tool: reads offsets, ships no game code.
"""
import sys, os, re, json, struct, collections
import pefile, capstone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
EXE = os.path.join(ROOT, "_baseline", "su_2x_steambuild_20548371", "game", "SiralimUltimate.exe")
FMAP = os.path.join(ROOT, "_su_extract", "code", "func_map.json")
pe = pefile.PE(EXE, fast_load=True); BASE = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
FM = json.load(open(FMAP)); NAMES = {int(v, 16): k for k, v in FM.items()}
FUNCS = sorted(int(v, 16) for v in FM.values())
CALLN = {0x14028c9e0: ">", 0x14028c9b0: "<", 0x140297c30: ">=", 0x140297c60: ">=int", 0x14028c8f0: "==int",
         0x14028ca10: ">int", 0x14028c950: "!=int", 0x140290d30: "<int", 0x1402bd5a0: "<=", 0x1402bd5d0: "<=int",
         0x14028c8d0: "==", 0x1478b83e0: "irandom_range", 0x1478bbd70: "varget", 0x1478bc260: "varset",
         0x14028c220: "mul", 0x14028c630: "add", 0x140290b30: "mul2"}


def func_range(name):
    a = int(FM[name], 16)
    import bisect
    i = bisect.bisect_right(FUNCS, a)
    return a, (FUNCS[i] if i < len(FUNCS) else a + 0x400000)


def disasm(lo, hi):
    return list(md.disasm(pe.get_data(lo - BASE, hi - lo), lo))


def const_at(t):
    if 0x1488c0000 <= t < 0x149857000 + 0x6811ac:
        try:
            raw = pe.get_data(t - BASE, 16)
        except Exception:
            return None
        if len(raw) < 16:
            return None
        d = struct.unpack("<d", raw[:8])[0]
        kind = struct.unpack("<I", raw[12:16])[0]
        if kind == 0 and abs(d) < 1e9:   # RValue real (kind 0) or a plain double
            return d
        return d if 1e-9 < abs(d) < 1e9 else None


def main():
    name, l1 = sys.argv[1], int(sys.argv[2]); l2 = int(sys.argv[3]) if len(sys.argv) > 3 else l1
    lo, hi = func_range(name)
    ins = disasm(lo, hi)
    slots = collections.Counter(re.sub(r", 0x[0-9a-f]+$", "", i.op_str) for i in ins
                                if i.mnemonic == "mov" and i.op_str.startswith("dword ptr [r") and re.search(r", 0x[0-9a-f]+$", i.op_str))
    slot = slots.most_common(1)[0][0]
    marks = [(int(i.op_str.rsplit(", ", 1)[1], 16), k) for k, i in enumerate(ins)
             if i.mnemonic == "mov" and i.op_str.startswith(slot + ",") and re.search(r", 0x[0-9a-f]+$", i.op_str)]
    ks = [k for ln, k in marks if l1 <= ln <= l2]
    if not ks:
        print("no marker for lines", l1, l2, "slot", slot); return
    nxt = [k for ln, k in marks if k > ks[-1]]
    a, b = ks[0], (nxt[0] if nxt else ks[-1] + 200)
    print("%s @%#x  line slot %s  lines %d-%d" % (name, lo, slot, l1, l2))
    for i in ins[a:b + 1]:
        s = "%#x %-24s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
        m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", i.op_str)
        if m:
            t = i.address + i.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
            c = const_at(t)
            s += "   ; %#x%s" % (t, "" if c is None else " = %r" % c)
        if i.mnemonic == "call":
            try:
                t = int(i.op_str, 16); s += "   ; " + (CALLN.get(t) or NAMES.get(t) or "")
            except ValueError:
                pass
        if i.mnemonic == "mov" and i.op_str.startswith(slot + ",") and re.search(r", 0x[0-9a-f]+$", i.op_str):
            s += "   <<< GML line %d" % int(i.op_str.rsplit(", ", 1)[1], 16)
        print(s)


if __name__ == "__main__":
    main()
