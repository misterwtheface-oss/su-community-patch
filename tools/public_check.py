"""Public-safety check: the repo is private now but may be published. Fails on anything that shouldn't go public.

python tools/public_check.py [files...]   (default: every file git would commit)
Flags: absolute local paths / user names, e-mail addresses, fenced code blocks in docs (no code listings),
long hex runs (game bytes; fingerprints keep seeds <= 32 hex chars and 64-char hashes), game binaries/CSVs/objects,
and in bug records and research files: a named hidden rule (user rule: hidden rules stay private), game-text quotes
longer than a short excerpt, and references to private record ids (_su_extract/patch_internal/bugs).
"""
import json, os, re, subprocess, sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BAD_EXT = (".exe", ".win", ".dll", ".csv", ".pak", ".obj", ".lib", ".exp", ".pdb")
RULES = [
    (re.compile(r"[A-Za-z]:\\?Users\\?|/c/Users/|\bmiste\b", re.I), "local path / user name"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "e-mail address"),
    (re.compile(r"\b[0-9a-fA-F]{65,}\b"), "long hex run (game bytes?)"),
]


HIDDEN = re.compile(r"hidden[ -]rule", re.I)
QUOTE = re.compile(r"Text: (.*?)\s(?=Evidence:|Fix sketch:|Reasoning:|App note|Source:|Test:|$)", re.S)
PRIVATE = os.path.normpath(os.path.join(ROOT, "..", "_su_extract", "patch_internal", "bugs"))
SCOPED = ("bugs/SU-", "research/")


def private_ids():
    try:
        return {f[:-5] for f in os.listdir(PRIVATE) if f.startswith("SU-") and f.endswith(".json")}
    except OSError:
        return set()


def files():
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True).stdout.split()
    return [os.path.join(ROOT, f) for f in out]


def main():
    fs = sys.argv[1:] or files()
    bad = 0
    priv = private_ids()
    for f in fs:
        rel = os.path.relpath(f, ROOT)
        if rel.lower().endswith(BAD_EXT):
            print("%s: game/binary file type must not be committed" % rel); bad += 1; continue
        try:
            text = open(f, encoding="utf-8").read()
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        if rel.replace("\\", "/") == "tools/public_check.py":
            continue
        if rel.replace("\\", "/").startswith(SCOPED):
            if HIDDEN.search(text):
                print("%s: names a hidden rule (keep hidden rules in the private registry)" % rel); bad += 1
            try:
                fields = [v for k, v in json.loads(text).items() if isinstance(v, str)] if rel.endswith(".json") else [text]
            except ValueError:
                fields = [text]
            for v in fields:
                for q in QUOTE.findall(v):
                    if len(q) > 220:
                        print("%s: game-text quote of %d chars (keep quotes short)" % (rel, len(q))); bad += 1
            for i in sorted(set(re.findall(r"SU-\d{4}", text)) & priv):
                print("%s: references private record %s" % (rel, i)); bad += 1
        for n, line in enumerate(text.splitlines(), 1):
            for rx, why in RULES:
                if rx.search(line):
                    print("%s:%d: %s" % (rel, n, why)); bad += 1
            if rel.endswith(".md") and line.startswith("```"):
                print("%s:%d: fenced code block in a doc (no code listings)" % (rel, n)); bad += 1
    print("public check: %d problem(s)" % bad)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
