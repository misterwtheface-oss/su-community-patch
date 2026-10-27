"""Check every patch edit against a game build: is the bug still there, and where does each edit go now?

python tools/port_check.py [path\\to\\SiralimUltimate.exe] [--json out.json]

Uses only the fingerprints in loader/patches.json (tools/anchor.py), so it works on a build we have never decoded.
For each edit it searches the build's code section for the masked byte pattern and reports:
  PRESENT      pattern found once and the original bytes are there: the bug is still in this build;
               for raw edits the new address is final; rip/call edits list the target to re-resolve
  PATCHED?     pattern found and the bytes already equal our fix (the developer may have fixed it the same way)
  CHANGED      pattern found but the edited bytes differ: code was touched, review by hand
  MISSING      pattern not found: the code around the bug changed (possibly fixed upstream), review by hand
  AMBIGUOUS    pattern found more than once
On the build the patches were written for, every edit must come out PRESENT at its recorded address (self-test).
"""
import json, os, sys, struct
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHES = os.path.join(HERE, "..", "loader", "patches.json")
BASELINE = os.path.join(HERE, "..", "..", "_baseline", "su_2x_steambuild_20548371", "game", "SiralimUltimate.exe")


def load_text(path):
    pe = pefile.PE(path, fast_load=True)
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    return pe, t.get_data(), pe.OPTIONAL_HEADER.ImageBase + t.VirtualAddress


SEED_MAX = 16


def _masked_hash(buf, mask):
    import hashlib
    return hashlib.sha256(bytes(b if m == "x" else 0 for b, m in zip(buf, mask))).hexdigest()


def fingerprint(pat, mask):
    """Public-safe fingerprint: the longest fixed run (capped at SEED_MAX bytes) as a seed + mask + masked SHA-256."""
    best, cur = (0, 0), None
    for k, m in enumerate(mask):
        if m == "x":
            cur = (cur[0], k + 1) if cur and cur[1] == k else (k, k + 1)
            if cur[1] - cur[0] > best[1] - best[0]:
                best = cur
    s = best[0]; e = min(best[1], s + SEED_MAX)
    return {"seed": pat[s:e].hex(), "seed_offset": s, "length": len(pat), "mask": mask,
            "sha256": _masked_hash(pat, mask)}


def find_fp(text, a):
    """Positions in text whose masked window matches fingerprint a."""
    seed, so, n, mask = bytes.fromhex(a["seed"]), a["seed_offset"], a["length"], a["mask"]
    out, i = [], text.find(seed)
    while i != -1:
        st = i - so
        if st >= 0 and st + n <= len(text) and _masked_hash(text[st:st + n], mask) == a["sha256"]:
            out.append(st)
        i = text.find(seed, i + 1)
    return out


def find_all(text, pat, mask):
    """Masked search. Seeds on the longest fixed run of the pattern, then checks the rest."""
    runs, cur = [], None
    for k, m in enumerate(mask):
        if m == "x":
            cur = (cur[0], k + 1) if cur and cur[1] == k else (k, k + 1)
            if not runs or runs[-1][0] != cur[0]:
                runs.append(cur)
            else:
                runs[-1] = cur
    s, e = max(runs, key=lambda r: r[1] - r[0])
    seed = pat[s:e]
    out, i = [], text.find(seed)
    while i != -1:
        st = i - s
        if st >= 0 and st + len(pat) <= len(text) and all(
                mask[k] == "?" or text[st + k] == pat[k] for k in range(len(pat))):
            out.append(st)
        i = text.find(seed, i + 1)
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    exe = args[0] if args else BASELINE
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    spec = json.load(open(PATCHES, encoding="utf-8"))
    pe, text, tva = load_text(exe)
    same_build = (pe.FILE_HEADER.TimeDateStamp == int(spec["build"]["timestamp"], 16))
    print("build", hex(pe.FILE_HEADER.TimeDateStamp), "(patch build)" if same_build else "(NEW build)")
    rows, worst = [], 0
    for p in spec["patches"]:
        for k, e in enumerate(p["edits"]):
            kind = e.get("kind", {}).get("type")
            if kind == "cave":
                rows.append((p["id"], k, "CAVE", "re-place in the new build's free space", None)); continue
            a = e.get("anchor")
            if not a:
                rows.append((p["id"], k, "NO-ANCHOR", "run tools/anchor.py", None)); worst = max(worst, 2); continue
            hits = find_fp(text, a)
            exp, wr = bytes.fromhex(e["expect"]), bytes.fromhex(e["write"])
            if not hits:
                st, info, va = "MISSING", "%s L%s: code changed, review" % (a["function"], a["gml_line"]), None
            elif len(hits) > 1 and a.get("occurrences") != len(hits):
                st, info, va = "AMBIGUOUS", "%d matches" % len(hits), None
            if hits and (len(hits) == 1 or a.get("occurrences") == len(hits)):
                h = sorted(hits)[a.get("occurrence", 0)]
                va = tva + h + a["offset"]
                cur = text[h + a["offset"]: h + a["offset"] + len(exp)]
                if kind == "raw":
                    st = "PRESENT" if cur == exp else ("PATCHED?" if cur == wr else "CHANGED")
                    info = "%s L%s" % (a["function"], a["gml_line"])
                else:                               # address fields are masked: the pattern match itself is the test
                    st = "PRESENT"
                    info = "%s L%s; re-resolve %s -> %s" % (a["function"], a["gml_line"],
                                                           e["kind"].get("old"), e["kind"].get("new"))
                if same_build and va != int(e["va"], 16):
                    st, info = "SELFTEST-FAIL", "found at %#x, recorded %s" % (va, e["va"])
            worst = max(worst, {"PRESENT": 0, "CAVE": 0, "PATCHED?": 1}.get(st, 2))
            rows.append((p["id"], k, st, info, va))
    for pid, k, st, info, va in rows:
        print("%-5s #%d %-13s %-14s %s" % (pid, k, st, hex(va) if va else "", info))
    import collections
    print(dict(collections.Counter(r[2] for r in rows)))
    if "--record" in sys.argv:                  # write the result into each patched bug's `builds` map
        label = sys.argv[sys.argv.index("--record") + 1]
        sys.path.insert(0, HERE)
        import registry as R
        recs = R.load()
        pmap = {p["id"]: p.get("bug") for p in spec["patches"]}
        per = {}
        for pid, k, st, info, va in rows:
            per.setdefault(pmap.get(pid), []).append(st)
        for bid, sts in per.items():
            if bid not in recs:
                continue
            present = all(s in ("PRESENT", "CAVE") for s in sts)
            recs[bid].setdefault("builds", {})[label] = {
                "present": True if present else None,
                "port": "ok" if present else "review: " + ", ".join(sorted(set(sts) - {"PRESENT", "CAVE"})),
                "verified_in_game": None}
            R.save(recs[bid])
        print("recorded build %r into %d bug records" % (label, len(per)))
    if out_json:
        json.dump([dict(zip(("patch", "edit", "status", "info", "va"), (r[0], r[1], r[2], r[3], hex(r[4]) if r[4] else None)))
                   for r in rows], open(out_json, "w"), indent=1)
    sys.exit(worst)


if __name__ == "__main__":
    main()
