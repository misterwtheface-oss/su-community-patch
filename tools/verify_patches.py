"""Apply loader/patches.json to the baseline bytes in memory and print each patched instruction (sanity check)."""
import json, os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.argv = sys.argv[:1]
import gmlsite as S

spec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loader", "patches.json"), encoding="utf-8"))
for p in spec["patches"]:
    print("==", p["id"], p["title"])
    for e in p["edits"]:
        va = int(e["va"], 16)
        if e.get("kind", {}).get("type") == "cave":     # our own code/data: checked by its builder (e.g. build_h01b)
            continue
        w = bytes.fromhex(e["write"])
        for back in range(96, 0, -1):             # decode from before the edit; x86 resyncs within a few bytes
            lo = va - back
            buf = bytearray(S.pe.get_data(lo - S.BASE, back + 64)); buf[back: back + len(w)] = w
            ins = list(S.md.disasm(bytes(buf), lo))
            k = next((i for i, x in enumerate(ins) if x.address <= va < x.address + x.size), None)
            if k is not None:
                break
        for i in ins[k:]:
            s = "  %#x %-16s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
            if "rip + " in i.op_str:
                d = int(i.op_str.split("rip + ")[1].split("]")[0], 16); t = i.address + i.size + d
                try:
                    v = S.pe.get_data(t - S.BASE, 8)
                except Exception:
                    v = bytes(8)
                v = (v + bytes(8))[:8]
                s += "  -> %#x%s" % (t, " = %r" % struct.unpack("<d", v)[0] if 1e-9 < abs(struct.unpack("<d", v)[0]) < 1e9 else "")
            if i.mnemonic in ("call", "jmp"):
                try: s += "  -> " + (S.NAMES.get(int(i.op_str, 16)) or "")
                except ValueError: pass
            print(s)
            if i.address + i.size >= va + len(w): break
