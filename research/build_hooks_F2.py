"""Build research/hooks_F2.json (round-3 batch F2). Checks every expected byte against the baseline exe, every
redirected call's current target, that no jump lands inside bytes a detour replaces, and that nothing overlaps
loader/patches.json. python research/build_hooks_F2.py"""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools")); sys.argv = sys.argv[:1]
import gmlsite as S
import keystone, capstone

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
CODE = ((0x1488bf980, 0x1488bfa00), (0x1488bfb40, 0x1488bfc00))
DATA = ((0x149ed8520, 0x149ed8600), (0x149ed8390, 0x149ed8400))
le = lambda v: (v & 0xffffffff).to_bytes(4, "little").hex()


def inside(a, n, ranges):
    return any(lo <= a and a + n <= hi for lo, hi in ranges)


def asm(src, addr):
    enc, _ = ks.asm(src, addr)
    code = bytes(enc)
    for i in md.disasm(code, addr):
        if i.mnemonic == "movabs" or re.search(r"\[0x[0-9a-f]{6,}\]", i.op_str):
            raise SystemExit("absolute address @%#x: %s %s" % (i.address, i.mnemonic, i.op_str))
    return code


def exe(va, n):
    return S.pe.get_data(va - S.BASE, n)


def code_edits(addr, data, note):
    assert inside(addr, len(data), CODE), hex(addr)
    return [{"va": hex(addr + k), "expect": "00" * len(data[k:k + 32]), "write": data[k:k + 32].hex(),
             "note": note + " (cave code)"} for k in range(0, len(data), 32)]


def redirect(site, callee, tramp, note):
    b = exe(site, 5)
    assert b[0] == 0xE8, hex(site)
    assert int.from_bytes(b[1:], "little", signed=True) + site + 5 == callee, "%#x does not call %#x" % (site, callee)
    return {"va": hex(site + 1), "expect": le(callee - (site + 5)), "write": le(tramp - (site + 5)), "note": note}


def no_jumps_into(fn, lo, hi):
    a, b = S.func_range(fn)
    for i in S.disasm(a, b):
        if (i.mnemonic.startswith("j") or i.mnemonic == "call") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            assert not (lo < t < hi), "%s: jump %#x -> %#x lands inside %#x-%#x" % (fn, i.address, t, lo, hi)


def tramp(addr, slot):
    assert inside(slot, 8, DATA)
    return asm("jmp qword ptr [%#x]" % slot, addr)


def detour(fn, at, orig_hex, flag, normal_next, te_target, cave):
    """Frameless: if [flag] != 0 jump to te_target, else run the replaced statement-marker store and continue."""
    orig = exe(at, len(bytes.fromhex(orig_hex)))
    assert orig.hex() == orig_hex, (fn, hex(at), orig.hex())
    no_jumps_into(fn, at, at + len(orig))
    i = next(md.disasm(orig, at))
    assert i.mnemonic == "mov" and i.size == len(orig), (i.mnemonic, i.op_str)
    stub = asm("cmp byte ptr [%#x], 0\n jne te\n %s %s\n jmp %#x\nte:\n jmp %#x"
               % (flag, i.mnemonic, i.op_str, normal_next, te_target), cave)
    j = asm("jmp %#x" % cave, at)
    return stub, {"va": hex(at), "expect": orig_hex, "write": (j + b"\x90" * (len(orig) - len(j))).hex(),
                  "note": "%s: detour at %#x" % (fn, at)}


P = []
REL = 0x14028c220; VCMP = 0x1478a6470
ISBUFF, ISMINION, ALLRACE, ONDEATH = 0x141fa4c50, 0x141fa5610, 0x140601da0, 0x141462dc0

# ---- SU-0108 True Ending
TE = 0x149ed8560
T1, S1 = 0x1488bf980, 0x149ed8520
e = code_edits(T1, tramp(T1, S1), "trampoline -> hook_su0108_l14")
e.append(redirect(0x141463ea1, REL, T1, "bc_OnDeath L14: temp release -> True Ending decision (hook)"))
for fn, at, orig, nxt, tgt, cave, what in (
        ("bc_OnDeath", 0x141463ea6, "c78424904e010010000000", 0x141463eb1, 0x141467ca0, 0x1488bf990, "L16 -> L80"),
        ("bc_OnDeath", 0x141467e80, "c78424904e010054000000", 0x141467e8b, 0x141468853, 0x1488bf9c0, "L84 -> L90 Born Again"),
        ("bc_OnDeath", 0x141469260, "c78424904e01005f000000", 0x14146926b, 0x1414703a7, 0x1488bfb40, "L95 -> L162 exit")):
    stub, ed = detour(fn, at, orig, TE, nxt, tgt, cave)
    e += code_edits(cave, stub, "True Ending skip " + what)
    ed["note"] += " (True Ending: " + what + ")"
    e.append(ed)
P.append({"id": "SU-0108", "bug": "SU-0108", "default": 1,
          "title": "True Ending: all on-death effects are ignored except Born Again (code still ran everything above its exit at L163)",
          "edits": e, "runtime_hooks": [{"slot_va": hex(S1), "symbol": "hook_su0108_l14"}]})

# ---- SU-0024 Demonologist vs anointed Undying Loyalty / Eternal Guardian
T2, S2, SELF, OTHER = 0x1488bfb70, 0x149ed8528, 0x149ed8570, 0x149ed8578
t2 = asm("mov qword ptr [%#x], r13\n mov qword ptr [%#x], r15\n jmp qword ptr [%#x]" % (SELF, OTHER, S2), T2)
T3, S3, T4, S4 = 0x1488bfb90, 0x149ed8530, 0x1488bfb98, 0x149ed8538
e = code_edits(T2, t2, "trampoline (saves self=r13 / other=r15) -> hook_su0024_demon")
e += code_edits(T3, tramp(T3, S3), "trampoline -> hook_su0024_isbuff")
e += code_edits(T4, tramp(T4, S4), "trampoline -> hook_su0024_isminion")
e += [redirect(0x1412a445e, VCMP, T2, "bc_HandleDeath L91: playertype == 35 compare -> Demonologist step only without UL / EG"),
      redirect(0x1412a4f6d, ISBUFF, T3, "bc_HandleDeath L110 (Undying Loyalty step): IsBuff -> false when Eternal Guardian also applies"),
      redirect(0x1412a53c4, ISMINION, T4, "bc_HandleDeath L120 (Eternal Guardian step): IsMinion -> false for demon minions 56-62 for a Demonologist")]
P.append({"id": "SU-0024", "bug": "SU-0024", "default": 1,
          "title": "Demonologist with anointed Undying Loyalty / Eternal Guardian: minions (UL) and buffs (EG) persist through death as their texts say, demon minions stay; UL + EG together keep both",
          "edits": e, "runtime_hooks": [{"slot_va": hex(S2), "symbol": "hook_su0024_demon"},
                                        {"slot_va": hex(S3), "symbol": "hook_su0024_isbuff"},
                                        {"slot_va": hex(S4), "symbol": "hook_su0024_isminion"}]})

# ---- SU-0046 Master of Rift Dancers on deaths (needs Dark Dance on the master's side)
T5, S5, T6, S6 = 0x1488bfba0, 0x149ed8540, 0x1488bfba8, 0x149ed8548
e = code_edits(T5, tramp(T5, S5), "trampoline -> hook_su0046_enemy")
e += code_edits(T6, tramp(T6, S6), "trampoline -> hook_su0046_ally")
e += [redirect(0x1410a6931, ALLRACE, T5, "bc_ExecuteEvents L448 (death repeats): enemy side all Rift Dancers -> and holds Dark Dance"),
      redirect(0x1410a6c8b, ALLRACE, T6, "bc_ExecuteEvents L448 (death repeats): your side all Rift Dancers -> and holds Dark Dance")]
P.append({"id": "SU-0046", "bug": "SU-0046", "default": 1,
          "title": "Master of Rift Dancers on deaths: the extra on-death pass is Dark Dance activating 1 additional time, so it needs Dark Dance on the master's side (code: any all-Rift-Dancer side with the Master)",
          "edits": e, "runtime_hooks": [{"slot_va": hex(S5), "symbol": "hook_su0046_enemy"},
                                        {"slot_va": hex(S6), "symbol": "hook_su0046_ally"}]})

# ---- SU-0025 instant kills get the Fable 80 and Master of Rift Dancers passes
T7, S7 = 0x1488bfbb0, 0x149ed8550
e = code_edits(T7, tramp(T7, S7), "trampoline -> hook_su0025_ohko")
e.append(redirect(0x1410c78e4, ONDEATH, T7, "bc_ExecuteEvents L986 (instant kill, base on-death pass) -> + Fable 80 / Master of Rift Dancers passes"))
P.append({"id": "SU-0025", "bug": "SU-0025", "default": 1,
          "title": "Instant kills: on-death effects also repeat for a Fable rank 80 bearer and Master of Rift Dancers, as damage deaths do",
          "edits": e, "runtime_hooks": [{"slot_va": hex(S7), "symbol": "hook_su0025_ohko"}]})

# ---- overlap check against loader/patches.json (bytes and hook slots)
spec = json.load(open(os.path.join(HERE, "..", "loader", "patches.json"), encoding="utf-8"))
used = set()
for p in spec["patches"]:
    for x in p["edits"]:
        a = int(x["va"], 16); used.update(range(a, a + len(bytes.fromhex(x["expect"]))))
    for h in p.get("runtime_hooks", []):
        a = int(h["slot_va"], 16); used.update(range(a, a + 8))
mine = set()
for p in P:
    for x in p["edits"]:
        a = int(x["va"], 16); n = len(bytes.fromhex(x["expect"]))
        r = set(range(a, a + n)); assert not (r & used), (p["id"], x["va"]); assert not (r & mine), (p["id"], x["va"]); mine |= r
    for h in p["runtime_hooks"]:
        a = int(h["slot_va"], 16); r = set(range(a, a + 8)); assert not (r & used) and not (r & mine), h; mine |= r
for a in (0x149ed8560, 0x149ed8570, 0x149ed8578, 0x149ed8580):
    assert a not in used
json.dump({"patches": P}, open(os.path.join(HERE, "hooks_F2.json"), "w", encoding="utf-8", newline="\n"), indent=2)
print("ok: %d patches, %d edits" % (len(P), sum(len(p["edits"]) for p in P)))
for p in P:
    for x in p["edits"]:
        if x["note"].endswith("(cave code)") and x["va"] in (hex(0x1488bf990), hex(0x1488bf9c0), hex(0x1488bfb40), hex(0x1488bfb70)):
            for i in md.disasm(bytes.fromhex(x["write"]), int(x["va"], 16)):
                print("   %#x %s %s" % (i.address, i.mnemonic, i.op_str))
