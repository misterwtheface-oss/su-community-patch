"""Give every edit in loader/patches.json a build-independent fingerprint, so a new game build can be checked.

For each edit it records, from the build the edit was written against:
  - "anchor": a fingerprint of the instructions around the edit, with every address-dependent field masked
    (rip-relative displacements, call/jmp/jcc targets): a short seed (at most 16 game bytes), the mask, and a SHA-256 of
    the masked window, so the repo holds no real run of game code. Plus the offset of the edit inside the window, the
    containing function's name (YYC keeps gml_Script names, so it survives rebuilds) and the GML line of the statement;
  - "kind": what the edit changes, with the meaning of old and new values where they are addresses:
      raw        opcode / immediate bytes (ported as is once the pattern is found)
      rip_disp   a rip-relative operand now points somewhere else: "old"/"new" describe both targets
                 (a constant value, a function name or a variable-id slot)
      call_rel   a call now goes to another function: "old"/"new" are function names
      cave       our own bytes in the free space at the end of .text (no anchor; re-placed in the new cave)

Run after adding edits:  python tools/anchor.py          (rewrites loader/patches.json in place)
"""
import json, os, re, struct, sys, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.argv = sys.argv[:1]
import gmlsite as S
import capstone
import port_check as PC
TEXT = PC.load_text(PC.BASELINE)[1]

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.join(HERE, "..", "loader", "patches.json")
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); MD.detail = True
CTX = 24                                        # bytes of context each side of the edit


def decode_around(va, length, ctx=CTX):
    """Instructions covering [va-ctx, va+length+ctx), decoded from a boundary that resyncs before the edit."""
    for back in range(ctx + 64, ctx + 16, -1):
        lo = va - back
        buf = S.pe.get_data(lo - S.BASE, back + length + ctx + 16)
        ins = list(MD.disasm(buf, lo))
        if any(i.address == va or i.address < va < i.address + i.size for i in ins):
            return [i for i in ins if i.address + i.size > va - ctx and i.address < va + length + ctx]
    raise RuntimeError("cannot decode around %#x" % va)


def masked(i):
    """Mask (True = wildcard) for each byte of one instruction: rip displacements and relative branch targets."""
    m = [False] * i.size
    if i.disp_offset and any(op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP
                             for op in i.operands):
        for k in range(i.disp_offset, i.disp_offset + i.disp_size):
            m[k] = True
    if (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)) and i.imm_offset and i.imm_size == 4:
        for k in range(i.imm_offset, i.imm_offset + 4):
            m[k] = True
    return m


# Variable-id slots read through `mov edx, [rip+slot]` before a var get. Names from the extract's decoding
# (bug_report_*.md, EFFECT_FORMULAS.md); on a new build they are re-found by name.
SLOTS = {0x1499e3228: "creature", 0x1499e0c38: "source", 0x1499e0aa8: "slot",
         0x1499e1fe8: "damage_taken", 0x1499e17e8: "battleturns"}
HELPERS = {0x14069c1a0: "real >= (setns)", 0x14069c140: "real > (setg)"}


CAVES = ((0x1488bf5e0, 0x1488c0000, "code cave"), (0x149ed81b0, 0x149ed8b00, "data cave"),
         (0x149856700, 0x149857000, "code cave (.rdata slack)"), (0x14a343100, 0x14a344000, "code cave (_RDATA slack)"))


def describe(target):
    """Meaning of an address: function name, constant value or variable slot."""
    for lo, hi, what in CAVES:
        if lo <= target < hi:
            return {"ours": what, "addr": hex(target)}
    if target in S.NAMES:
        return {"func": S.NAMES[target]}
    if target in HELPERS:
        return {"helper": HELPERS[target], "addr": hex(target)}
    if target in SLOTS:
        return {"var": SLOTS[target], "slot": hex(target)}
    raw = S.pe.get_data(target - S.BASE, 16)
    if len(raw) < 16:
        return {"slot": hex(target)}
    if raw[8:16] == bytes(8):
        d = struct.unpack("<d", raw[:8])[0]
        if d == d and abs(d) < 1e9 and (d == 0 or abs(d) > 1e-9):
            return {"rvalue": d}                 # static RValue real (value, flags 0, kind 0)
    d = struct.unpack("<d", raw[:8])[0]
    if d == d and 1e-9 < abs(d) < 1e9:
        return {"double": d}
    return {"slot": hex(target)}                 # a variable-id slot or other global; resolved by hand on a new build


_FN_CACHE = {}


def gml_line(va):
    """Function name and the GML line of the statement containing va (last line marker before it)."""
    fn = S.FUNCS[bisect.bisect_right(S.FUNCS, va) - 1]
    if fn not in _FN_CACHE:
        lo, hi = S.func_range(S.NAMES[fn])
        ins = S.disasm(lo, hi)
        import collections
        slots = collections.Counter(re.sub(r", 0x[0-9a-f]+$", "", i.op_str) for i in ins
                                    if i.mnemonic == "mov" and i.op_str.startswith("dword ptr [r")
                                    and re.search(r", 0x[0-9a-f]+$", i.op_str))
        slot = slots.most_common(1)[0][0] if slots else None
        _FN_CACHE[fn] = [(i.address, int(i.op_str.rsplit(", ", 1)[1], 16)) for i in ins
                         if slot and i.mnemonic == "mov" and i.op_str.startswith(slot + ",")
                         and re.search(r", 0x[0-9a-f]+$", i.op_str)]
    marks = _FN_CACHE[fn]
    k = bisect.bisect_right([a for a, _ in marks], va) - 1
    return S.NAMES.get(fn), (marks[k][1] if k >= 0 else None)


def main():
    spec = json.load(open(PATCHES, encoding="utf-8"))
    b = spec["build"]
    cave = (int(b["cave_start"], 16), int(b["cave_end"], 16))
    for p in spec["patches"]:
        for e in p["edits"]:
            va = int(e["va"], 16); n = len(bytes.fromhex(e["expect"]))
            if cave[0] <= va < cave[1] or any(lo <= va < hi for lo, hi, _ in CAVES[2:]):
                e["kind"] = {"type": "cave"}; e.pop("anchor", None); continue
            for ctx in (CTX, 48, 96, 160, 256, 400, 640):   # widen until the fingerprint is unique in this build
                ins = decode_around(va, n, ctx)
                lo = ins[0].address
                pat, mask = bytearray(), []
                for i in ins:
                    pat += i.bytes; mask += masked(i)
                hits = PC.find_all(TEXT, bytes(pat), "".join("?" if m else "x" for m in mask))
                if len(hits) == 1:
                    break
            else:
                print("note: %s edit at %#x matches %d identical places; recording which one" % (p["id"], va, len(hits)))
            # what the edit touches
            first = next(i for i in ins if i.address <= va < i.address + i.size)
            mk = masked(first)
            rel = range(va - first.address, va - first.address + n)
            kind = {"type": "raw"}
            if all(mk[k] for k in rel):
                newbuf = bytearray(first.bytes); w = bytes.fromhex(e["write"])
                newbuf[va - first.address: va - first.address + n] = w
                new = next(MD.disasm(bytes(newbuf), first.address))
                def tgt(x):
                    if x.group(capstone.CS_GRP_CALL) or x.group(capstone.CS_GRP_JUMP):
                        return int(x.op_str, 16)
                    return x.address + x.size + x.disp
                if first.group(capstone.CS_GRP_CALL):
                    kind = {"type": "call_rel", "old": describe(tgt(first)), "new": describe(tgt(new))}
                else:
                    kind = {"type": "rip_disp", "old": describe(tgt(first)), "new": describe(tgt(new))}
            fn, line = gml_line(va)
            e["kind"] = kind
            mstr = "".join("?" if m else "x" for m in mask)
            e["anchor"] = dict(PC.fingerprint(bytes(pat), mstr), function=fn, gml_line=line, offset=va - lo)
            if len(hits) > 1:                        # identical copies of the code: keep the occurrence index
                e["anchor"]["occurrence"] = sorted(hits).index(lo - PC.load_text(PC.BASELINE)[2])
                e["anchor"]["occurrences"] = len(hits)
    json.dump(spec, open(PATCHES, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
    open(PATCHES, "a").write("\n")
    print("anchored", sum(len(p["edits"]) for p in spec["patches"]), "edits")


if __name__ == "__main__":
    main()
