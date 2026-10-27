"""Export the public release tree to dist/public (allowlist only), ready to become the first commit of a fresh public
repo. Nothing internal goes in: no registry, research, test sheets, dev tools or history.

python tools/export_public.py
Layout: README.md, PATCH_NOTES.pdf, release/{version.dll, suucp.ini}, source/{loader sources, generated headers,
build.cmd}. Then runs the public-safety check and an internal-term scan over the export.
"""
import glob, json, os, re, shutil, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry as R

ROOT = R.ROOT
LOADER = os.path.join(ROOT, "loader")
OUT = os.path.join(ROOT, "dist", "public")

SOURCE_FILES = ["suucp.c", "suucp.def", "text.c", "hooks.c", "patches_gen.h", "text_gen.h", "VERSION"]
BUILD_CMD = r"""@echo off
rem Builds version.dll (x64) from the patch source. Needs Visual Studio Build Tools (MSVC, x64).
setlocal
cd /d "%~dp0"
call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" >nul 2>nul
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set VS=%%i
if not defined VS (echo Visual Studio Build Tools not found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
if not exist build mkdir build
cl /nologo /O2 /W4 /MT /LD suucp.c /Fobuild\ /Febuild\version.dll /link /NOLOGO /DEF:suucp.def kernel32.lib || exit /b 1
echo built build\version.dll
"""


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(os.path.join(OUT, "release")); os.makedirs(os.path.join(OUT, "source"))
    # fresh build so release/ matches source/
    subprocess.run(["cmd", "/c", os.path.join(LOADER, "build.cmd")], cwd=LOADER, check=True, capture_output=True)
    shutil.copy(os.path.join(ROOT, "publish", "README.md"), OUT)
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_patch_notes.py"),
                    os.path.join(OUT, "PATCH_NOTES.pdf")], check=True)
    for f in ("version.dll", "suucp.ini"):
        shutil.copy(os.path.join(LOADER, "build", f), os.path.join(OUT, "release", f))
    srcs = SOURCE_FILES + sorted(os.path.basename(p) for p in glob.glob(os.path.join(LOADER, "hooks_*.c")))
    for f in srcs:
        shutil.copy(os.path.join(LOADER, f), os.path.join(OUT, "source", f))
    open(os.path.join(OUT, "source", "build.cmd"), "w", newline="\r\n").write(BUILD_CMD)
    open(os.path.join(OUT, ".gitignore"), "w").write("source/build/\n")

    # safety: public check + internal terms (titles of the private records) must not appear anywhere in the export
    files = [p for p in glob.glob(os.path.join(OUT, "**", "*"), recursive=True) if os.path.isfile(p)
             and not p.endswith((".dll", ".pdf"))]
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "public_check.py")] + files,
                       capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-1])
    terms = set()
    for p in glob.glob(os.path.join(R.PRIVATE_BUGS, "SU-*.json")):
        rec = json.load(open(p, encoding="utf-8"))
        terms.add(rec["id"])
    hits = [(os.path.relpath(f, OUT), t) for f in files for t in terms if re.search(r"\b%s\b" % re.escape(t),
            open(f, encoding="utf-8", errors="ignore").read())]
    if hits or r.returncode:
        raise SystemExit("export blocked: %s" % (hits or "public check failed"))
    print("exported %d files to %s" % (sum(len(fs) for _, _, fs in os.walk(OUT)), OUT))


if __name__ == "__main__":
    main()
