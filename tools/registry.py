"""Bug registry: validate, cross-check against patches / text overrides / the build calculator, and render STATUS.md.

python tools/registry.py            validate + write STATUS.md + write the app-note handoff
python tools/registry.py --check    validate only (exit 1 on problems)

Library use (migration, port_check --record): load(), save(rec), resolve(name, kind=None), next_id().
"""
import json, os, re, sys, glob, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BUGS = os.path.join(ROOT, "bugs")
PATCHES = os.path.join(ROOT, "loader", "patches.json")
OVERRIDES = os.path.join(ROOT, "text", "overrides.json")
STATUS = os.path.join(ROOT, "STATUS.md")
MODEL = os.path.normpath(os.path.join(ROOT, "..", "_su_extract", "data", "model"))
HANDOFF = os.path.normpath(os.path.join(ROOT, "..", "_su_extract", "code", "HANDOFF_patch_app_notes.md"))
# Internal records (hidden rules, and non-bugs our own analysis raised) live in the PRIVATE extract repo, never here:
# this repo may be published, and they must not appear in it or in patch notes. They still feed the app-note handoff.
PRIVATE_BUGS = os.path.normpath(os.path.join(ROOT, "..", "_su_extract", "patch_internal", "bugs"))
NEXT_ID = os.path.join(BUGS, ".next_id")

STATUSES = ("patched", "planned", "needs-hook", "test-first", "open", "wontfix")
CATEGORIES = ("bug", "hidden-rule", "not-a-bug")
DECISIONS = ("fix-code", "fix-text", "test-first", "leave", None)


def load(include_private=False):
    recs = {}
    dirs = [BUGS] + ([PRIVATE_BUGS] if include_private and os.path.isdir(PRIVATE_BUGS) else [])
    for f in sorted(f for d in dirs for f in glob.glob(os.path.join(d, "SU-*.json"))):
        r = json.load(open(f, encoding="utf-8"))
        r["_path"] = f
        recs[r["id"]] = r
    return recs


def save(r):
    path = r.pop("_path", None) or os.path.join(BUGS, r["id"] + ".json")
    json.dump(r, open(path, "w", encoding="utf-8", newline="\n"), indent=2, ensure_ascii=False)
    open(path, "a", encoding="utf-8").write("\n")


def next_id(recs):
    """Ids are never reused, including ids of internal (private) records: .next_id keeps the counter."""
    n = max([int(k[3:]) for k in recs] or [0]) + 1
    try:
        n = max(n, int(open(NEXT_ID).read().strip()))
    except (OSError, ValueError):
        pass
    if os.path.isdir(PRIVATE_BUGS):
        n = max([n] + [int(f[-9:-5]) + 1 for f in glob.glob(os.path.join(PRIVATE_BUGS, "SU-*.json"))])
    open(NEXT_ID, "w").write("%d\n" % (n + 1))
    return "SU-%04d" % n


# ---------- game-id resolution (from the extract's id tables) ----------
_IDX = None


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _vals(x):
    return x.values() if isinstance(x, dict) else x


def _index():
    global _IDX
    if _IDX is not None:
        return _IDX
    idx = collections.defaultdict(list)
    def j(name):
        return json.load(open(os.path.join(MODEL, name), encoding="utf-8"))
    for r in j("passive_ids_true.json")["records"].values():
        if not r.get("name"):
            continue
        idx[_norm(r["name"])].append({"kind": "trait", "name": r["name"], "runtime_id": r["id"],
                                      "text_key": ("L_TRAIT_DESC_" + r["desc_key"]) if r.get("desc_key") else None})
    for r in _vals(j("perk_ids_true.json")["records"]):
        idx[_norm(r["name"])].append({"kind": "perk", "name": r["name"], "runtime_id": r["id"], "key": r["key"],
                                      "text_key": "L_P_%s_DESC" % r["key"]})
    for r in _vals(j("spell_ids_true.json")["records"]):
        idx[_norm(r["name"])].append({"kind": "spell", "name": r["name"], "runtime_id": r["id"], "key": r["key"],
                                      "text_key": "L_SD_" + r["key"]})
    seen = set()
    for r in j("relic_signatures.json")["records"]:
        nm = r.get("app_relic_name") or r["relic"]
        if (nm, r["rank"]) in seen:
            continue
        seen.add((nm, r["rank"]))
        for alias in {nm, r["relic"]}:
            idx[_norm(alias)].append({"kind": "relic", "name": nm, "relic_code_id": r["relic_code_id"], "rank": r["rank"]})
    _IDX = idx
    return idx


def resolve(name, kind=None, rank=None):
    """Candidates for an effect name. Relics need a rank to be unique."""
    c = [x for x in _index().get(_norm(name), []) if (kind is None or x["kind"] == kind)]
    if rank is not None:
        c = [x for x in c if x.get("rank") in (rank, None)]
    return c


# ---------- build-calculator notes ----------
def app_notes():
    e = json.load(open(os.path.join(MODEL, "effect_clarifications.json"), encoding="utf-8"))["entries"]
    have = collections.defaultdict(list)
    for x in e:
        k = x["kind"]
        if k == "trait":
            have[("trait", x.get("trait_runtime_id"))].append(x)
        elif k == "perk":
            have[("perk", x.get("perk_key"))].append(x)
        elif k == "relic":
            have[("relic", _norm(x.get("relic_name")), x.get("rank"))].append(x)
        elif k == "spell":
            have[("spell", x.get("spell_id"))].append(x)
        else:
            have[(k, _norm(x.get("name")))].append(x)
    return have


def note_key(s):
    k = s.get("kind")
    if k == "trait":
        return ("trait", s.get("runtime_id"))
    if k == "perk":
        return ("perk", s.get("key"))
    if k == "relic":
        return ("relic", _norm(s.get("name")), s.get("rank"))
    if k == "spell":
        return ("spell", s.get("runtime_id"))
    return (k, _norm(s.get("name")))


# ---------- validation ----------
def validate(recs):
    errs = []
    spec = json.load(open(PATCHES, encoding="utf-8"))
    pids = {p["id"]: p for p in spec["patches"]}
    ovs = json.load(open(OVERRIDES, encoding="utf-8"))["overrides"] if os.path.exists(OVERRIDES) else []
    okeys = {o["key"] for o in ovs}
    for r in recs.values():
        for f in ("id", "title", "category", "status", "subjects", "sources"):
            if f not in r:
                errs.append("%s: missing %s" % (r.get("id"), f))
        if r.get("status") not in STATUSES:
            errs.append("%s: bad status %r" % (r["id"], r.get("status")))
        if r.get("category") not in CATEGORIES:
            errs.append("%s: bad category %r" % (r["id"], r.get("category")))
        if r.get("status") == "patched" and r.get("patch") not in pids and not r.get("text_fix"):
            errs.append("%s: patched but neither a patch in patches.json nor a text_fix" % r["id"])
        if r.get("patch") and r["patch"] not in pids:
            errs.append("%s: patch %r not found" % (r["id"], r["patch"]))
        for k in r.get("text_overrides", []):
            if k not in okeys:
                errs.append("%s: text override %s not in text/overrides.json" % (r["id"], k))
        if not os.path.normpath(os.path.dirname(r.get("_path", BUGS))) == os.path.normpath(PRIVATE_BUGS):
            errata = any(x.startswith("community:") for x in r.get("sources", []))
            if r.get("category") == "hidden-rule" or (r.get("category") == "not-a-bug" and not errata):
                errs.append("%s: internal record (hidden rule, or a non-bug our own analysis raised) must live in "
                            "_su_extract/patch_internal/bugs, not in this repo" % r["id"])
        if r.get("decision") == "leave" and not r.get("reason"):
            errs.append("%s: decision leave needs a reason" % r["id"])
    for pid, p in pids.items():
        if p.get("bug") not in recs:
            errs.append("patch %s: bug %r not in registry" % (pid, p.get("bug")))
    for o in ovs:
        if o.get("bug") not in recs:
            errs.append("override %s: bug %r not in registry" % (o["key"], o.get("bug")))
    return errs


# ---------- outputs ----------
def app_note_gaps(recs):
    have = app_notes()
    gaps = []
    for r in recs.values():
        if r["category"] == "not-a-bug" or r.get("app_note", {}).get("status") in ("shipped", "not-needed"):
            continue
        missing = [s for s in r["subjects"] if s.get("kind") != "system" and not have.get(note_key(s))]
        anynote = [s for s in r["subjects"] if have.get(note_key(s))]
        gaps.append((r, missing, anynote))
    return gaps


def write_handoff(recs):
    gaps = app_note_gaps(recs)
    lines = ["# Handoff: app notes for community-patch findings (generated; do not edit by hand)", "",
             "**From:** `su-community-patch` (`python tools/registry.py`). **For:** the extract session.",
             "**Ask (user, 2026-10-26):** every bug or hidden rule found while building the patch or vetting the community",
             "errata needs a note in the build calculator. The app describes the **unpatched** game, so notes say what the",
             "unpatched game does. When a note ships, set the bug's `app_note` to `{\"status\": \"shipped\", \"ref\": …}` in",
             "`su-community-patch/bugs/<id>.json` and re-run the tool; the row disappears.", "",
             "Columns: an existing note on the subject may already cover the finding (check it; mark shipped if so).", "",
             "| Bug | Subjects | Finding | Confidence | Existing note on subject? | Source |", "|---|---|---|---|---|---|"]
    for r, missing, anynote in sorted(gaps, key=lambda g: g[0]["id"]):
        subj = "; ".join("%s %s%s" % (s.get("kind"), s.get("name"), (" r%s" % s["rank"]) if s.get("rank") else "")
                         for s in r["subjects"]) or "—"
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            r["id"], subj, r.get("problem", r["title"]).replace("|", "/").replace("\n", " "),
            r.get("confidence", ""), "yes: check it" if anynote else "no", "; ".join(r["sources"])))
    open(HANDOFF, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    return len(gaps)


def write_status(recs):
    spec = json.load(open(PATCHES, encoding="utf-8"))
    by = collections.defaultdict(list)
    for r in recs.values():
        by[r["status"]].append(r)
    out = ["# Status (generated from bugs/ by tools/registry.py; do not edit)", "",
           "Build: %s. Patches in loader/patches.json: %d. Bugs: %d." % (spec["build"]["name"], len(spec["patches"]), len(recs)), "",
           "| Status | Count |", "|---|---|"]
    for s in STATUSES:
        out.append("| %s | %d |" % (s, len(by[s])))
    titles = {"patched": "Patched", "planned": "Planned (small edit known)", "needs-hook": "Needs hook code",
              "test-first": "Test in game first", "open": "Open (from errata vetting, not yet triaged)", "wontfix": "Not fixing"}
    for s in STATUSES:
        if not by[s]:
            continue
        out += ["", "## " + titles[s], "", "| Id | Title | Category | Confidence | Patch | App note | Sources |", "|---|---|---|---|---|---|---|"]
        for r in sorted(by[s], key=lambda r: r["id"]):
            out.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                r["id"], r["title"].replace("|", "/"), r["category"], r.get("confidence", ""), r.get("patch") or "",
                r.get("app_note", {}).get("status", "none"), "; ".join(r["sources"])))
    open(STATUS, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")


TESTS = os.path.join(ROOT, "IN_GAME_TESTS.md")
KIND_ORDER = ["relic", "trait", "perk", "spell", "card", "gem_property", "condition", "guild", "realm_property", "system",
              "unresolved"]
KIND_TITLE = {"relic": "Relics", "trait": "Traits", "perk": "Perks", "spell": "Spells", "card": "Cards",
              "gem_property": "Spell gem properties", "condition": "Conditions and minions", "guild": "Guilds",
              "realm_property": "Realm properties", "system": "Combat systems and other", "unresolved": "Other"}


def _group(r):
    kinds = [s.get("kind") for s in r["subjects"]] or ["system"]
    return min(kinds, key=lambda k: KIND_ORDER.index(k) if k in KIND_ORDER else 99)


def write_tests(recs):
    """One sheet for every in-game check: live fixes to confirm, test-first investigations, text corrections."""
    spec = json.load(open(PATCHES, encoding="utf-8"))
    ptitle = {p["id"]: (p["title"], p.get("default", 1)) for p in spec["patches"]}
    out = ["# In-game tests (generated from bugs/ by tools/registry.py; do not edit)", "",
           "Record results in the bug's `builds[\"2.0.38\"].verified_in_game` (or tell the patch session).",
           "Switch any fix off in `suucp.ini` ([fixes] SU-xxxx=0; text: [text] SU-xxxx=0).", ""]

    def section(title, rows):
        out.extend(["## " + title, ""])
        byg = collections.defaultdict(list)
        for r, line in rows:
            byg[_group(r)].append(line)
        for g in sorted(byg, key=lambda k: KIND_ORDER.index(k) if k in KIND_ORDER else 99):
            out.extend(["### " + KIND_TITLE.get(g, g), ""] + sorted(byg[g]) + [""])

    live = []
    for r in recs.values():
        if r["status"] == "patched" and r.get("patch") in ptitle and ptitle[r["patch"]][1]:
            v = r.get("builds", {}).get("2.0.38", {}).get("verified_in_game")
            mark = "x" if v else " "
            live.append((r, "- [%s] **%s** %s. Expect: %s%s" % (mark, r["id"], r["title"], ptitle[r["patch"]][0],
                                                                   (" *(last result: %s)*" % v.get("result", "")[:140]) if v else "")))
    section("1. Confirm the live fixes", live)
    inv = []
    for r in recs.values():
        if r["status"] == "test-first":
            t = re.search(r"In-game test: (.*?)(?: Fix:|$)", r.get("notes", ""))
            inv.append((r, "- [ ] **%s** %s. %s Test: %s" % (r["id"], r["title"], r.get("problem", "")[:200],
                                                            t.group(1).strip() if t else "see the bug record")))
    section("2. Investigate (code is certain, intent or impact needs a look)", inv)
    tx = []
    for r in recs.values():
        for t in r.get("text_fix", []):
            tx.append((r, "- [ ] **%s** `%s` (%s) should read: \"%s\"" % (r["id"], t["key"], t["file"], t["en_proposed"])))
    if tx:
        out.extend(["## 3. Text corrections", "",
                    "First check once: one corrected description shows the new text, and a description from the same file",
                    "that was NOT corrected still shows its normal text (the override must add to the game text, not replace it).", ""])
        section("3. Text corrections (each)", tx)
    open(TESTS, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    return len(live), len(inv), len(tx)


def main():
    recs = load()
    errs = validate(recs)
    for e in errs:
        print("ERROR", e)
    if "--check" in sys.argv:
        sys.exit(1 if errs else 0)
    write_status(recs)
    nl, ni, nt = write_tests(recs)
    n = write_handoff(load(include_private=True))       # private handoff: the app needs notes for everything
    print("%d bugs, %d errors; STATUS.md and IN_GAME_TESTS.md (%d live, %d investigate, %d text) written; "
          "%d need an app note (%s)" % (len(recs), len(errs), nl, ni, nt, n, HANDOFF))
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
