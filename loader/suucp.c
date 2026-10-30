/* Siralim Ultimate Unofficial Community Patch - loader.
 *
 * Built as version.dll and placed next to SiralimUltimate.exe. The game imports VERSION.dll, so Windows loads this
 * copy first. On load it checks the exe is the build the patch table was made for, then applies every enabled fix in
 * memory. The real version.dll functions are passed through from System32.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <share.h>

typedef struct { DWORD rva; DWORD len; BYTE expect[32]; BYTE write[32]; } SuucpEdit;
typedef struct { const char *id; int def; int first; int count; const char *group; } SuucpPatch;
#include <intrin.h>
#include "hooks.c"
typedef struct { const char *patch; DWORD slot_rva; void *fn; } SuucpHook;
#include "patches_gen.h"


static char g_dir[MAX_PATH];   /* folder of the game exe, with trailing backslash */
static FILE *g_log;

static void logf_(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) return;
    va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
}

static int build_matches(BYTE *base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    logf_("exe timestamp 0x%08X, size 0x%08X", nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage);
    return nt->FileHeader.TimeDateStamp == SUUCP_TIMESTAMP && nt->OptionalHeader.SizeOfImage == SUUCP_SIZE_OF_IMAGE;
}

/* All edits of one fix are checked before any is written, so a fix is applied whole or not at all. */
static int apply_patch(BYTE *base, const SuucpPatch *p)
{
    int i;
    for (i = 0; i < p->count; i++) {
        const SuucpEdit *e = &g_edits[p->first + i];
        if (memcmp(base + e->rva, e->expect, e->len) != 0) {
            if (memcmp(base + e->rva, e->write, e->len) == 0) continue;   /* already applied */
            logf_("  %s: bytes at rva 0x%08X are not what the patch expects, fix skipped", p->id, e->rva);
            return 0;
        }
    }
    for (i = 0; i < p->count; i++) {
        const SuucpEdit *e = &g_edits[p->first + i];
        DWORD old;
        if (!VirtualProtect(base + e->rva, e->len, PAGE_EXECUTE_READWRITE, &old)) {
            logf_("  %s: VirtualProtect failed (%lu)", p->id, GetLastError());
            return 0;
        }
        memcpy(base + e->rva, e->write, e->len);
        VirtualProtect(base + e->rva, e->len, old, &old);
        FlushInstructionCache(GetCurrentProcess(), base + e->rva, e->len);
    }
    return 1;
}

/* Crash logger: records where a fatal fault happened (game RVA / our cave / our DLL offset, plus code addresses found
 * on the stack) so a crash in battle can be traced to a fix. Never handles the exception. */
static BYTE *g_dll_base;
static SIZE_T g_dll_size, g_game_size;
static LONG g_crash_logs;
static __declspec(thread) int t_in_logger;

static const char *where_kind(ULONG_PTR a, ULONG_PTR *off)
{
    ULONG_PTR gb = (ULONG_PTR)g_base, db = (ULONG_PTR)g_dll_base;
    if (a >= gb && a < gb + g_game_size) {
        *off = a - gb;
        if (*off >= 0x88bf5e0 && *off < 0x88c0000) return "game code cave (patch)";
        {
            int k;
            for (k = 0; k < (int)(sizeof g_xcaves / sizeof g_xcaves[0]); k++)
                if (g_xcaves[k][1] && *off >= g_xcaves[k][0] && *off < g_xcaves[k][0] + g_xcaves[k][1])
                    return "game code cave (patch, section slack)";
        }
        if (*off >= 0x9ed81b0 && *off < 0x9ed8b00) return "game data cave (patch)";
        return "game";
    }
    if (db && a >= db && a < db + g_dll_size) { *off = a - db; return "loader dll (see build/version.map)"; }
    *off = a; return "other";
}

/* The game's own GML call stack (the trace its error box prints): a linked list of {prev, script name, line}; the
 * head is a global each YYC script updates on entry. Read-only, every pointer checked first. */
#define GML_TRACE_HEAD 0x149d53148
static int readable(const void *p, SIZE_T n)
{
    MEMORY_BASIC_INFORMATION mi;
    if (!p || !VirtualQuery(p, &mi, sizeof mi) || mi.State != MEM_COMMIT) return 0;
    if (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return (const char *)p + n <= (const char *)mi.BaseAddress + mi.RegionSize;
}

static void gml_trace(void)
{
    const char *e;
    int k;
    if (!g_base || !readable(RVA(GML_TRACE_HEAD), 8)) return;
    e = *(const char **)RVA(GML_TRACE_HEAD);
    for (k = 0; k < 24 && readable(e, 0x14); k++) {
        const char *name = *(const char *const *)(e + 8);
        char buf[80]; int j;
        for (j = 0; j < 79 && readable(name + j, 1) && name[j]; j++) buf[j] = name[j];
        buf[j] = 0;
        logf_("  gml: %s (line %d)", j ? buf : "?", *(const int *)(e + 0x10));
        e = *(const char *const *)e;
    }
}

static LONG CALLBACK crash_logger(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR off, *sp; int i, shown = 0;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_PRIV_INSTRUCTION &&
        code != EXCEPTION_STACK_OVERFLOW && code != EXCEPTION_INT_DIVIDE_BY_ZERO)
        return EXCEPTION_CONTINUE_SEARCH;
    if (t_in_logger || !g_log || InterlockedIncrement(&g_crash_logs) > 10) return EXCEPTION_CONTINUE_SEARCH;
    t_in_logger = 1;
    {
        const char *kind = where_kind((ULONG_PTR)ep->ExceptionRecord->ExceptionAddress, &off);   /* sets off first */
        logf_("FAULT 0x%08lX at %s +0x%llX", code, kind, (unsigned long long)off);
    }
    sp = (ULONG_PTR *)ep->ContextRecord->Rsp;
    {
        ULONG_PTR top = (ULONG_PTR)((NT_TIB *)NtCurrentTeb())->StackBase;     /* never read past the stack */
        int dll_shown = 0;
        for (i = 0; i < 4096 && (shown < 8 || dll_shown < 8) && (ULONG_PTR)&sp[i] + 8 <= top; i++) {
        ULONG_PTR v = sp[i];                                                   /* return-address candidates */
        if (shown < 8 && v >= (ULONG_PTR)g_base + 0x1000 && v < (ULONG_PTR)g_base + 0x88c0000) {
            logf_("  stack[%d]: game +0x%llX", i, (unsigned long long)(v - (ULONG_PTR)g_base)); shown++;
        } else if (dll_shown < 8 && g_dll_base && v >= (ULONG_PTR)g_dll_base && v < (ULONG_PTR)g_dll_base + g_dll_size) {
            logf_("  stack[%d]: dll +0x%llX", i, (unsigned long long)(v - (ULONG_PTR)g_dll_base)); dll_shown++;
        }
        }
    }
    if (g_su0275_step) logf_("  SU-0275 counter step %d", g_su0275_step);
    gml_trace();
    t_in_logger = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

static char g_ini[MAX_PATH];
static int text_enabled(const char *bug)
{
    int all = GetPrivateProfileIntA("text", "all", 1, g_ini);
    return GetPrivateProfileIntA("text", bug, all, g_ini) != 0;
}
#include "text.c"

static void run_patcher(void)
{
    char path[MAX_PATH], ini[MAX_PATH];
    BYTE *base = (BYTE *)GetModuleHandleW(NULL);
    g_base = base;
    {
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
        g_game_size = nt->OptionalHeader.SizeOfImage;
    }
    int i, on = 0, applied = 0;
    char *slash;

    GetModuleFileNameA(NULL, g_dir, MAX_PATH);
    slash = strrchr(g_dir, '\\');
    if (slash) slash[1] = 0;
    _snprintf_s(path, sizeof path, _TRUNCATE, "%ssuucp.log", g_dir);
    _snprintf_s(ini, sizeof ini, _TRUNCATE, "%ssuucp.ini", g_dir);
    {   /* keep the last session's log (a crash record survives one relaunch) */
        char prev[MAX_PATH];
        _snprintf_s(prev, sizeof prev, _TRUNCATE, "%ssuucp.prev.log", g_dir);
        MoveFileExA(path, prev, MOVEFILE_REPLACE_EXISTING);
    }
    g_log = _fsopen(path, "w", _SH_DENYWR);   /* others may read the log while the game runs */
    logf_("Siralim Ultimate Unofficial Community Patch %s", SUUCP_VERSION);

    if (!build_matches(base)) {
        logf_("This game version is not the one this patch was made for. No fixes applied.");
        return;
    }
    for (i = 0; i < (int)(sizeof g_patches / sizeof g_patches[0]); i++) {
        const SuucpPatch *p = &g_patches[i];
        if (!GetPrivateProfileIntA("fixes", p->id, p->def, ini)) { logf_("%s off", p->id); continue; }
        if (p->group && p->group[0] && !GetPrivateProfileIntA("groups", p->group, 1, ini)) {
            logf_("%s off (group %s off)", p->id, p->group); continue;
        }
        on++;
        if (apply_patch(base, p)) {
            int h;
            for (h = 0; h < (int)(sizeof g_hooks / sizeof g_hooks[0]); h++)   /* point the trampolines at our C hooks */
                if (g_hooks[h].fn && strcmp(g_hooks[h].patch, p->id) == 0)
                    *(void **)(base + g_hooks[h].slot_rva) = g_hooks[h].fn;
            applied++; logf_("%s applied", p->id);
        }
    }
    logf_("%d of %d enabled fixes applied", applied, on);
    for (i = 0; i < (int)(sizeof g_xcaves / sizeof g_xcaves[0]); i++) {   /* hook code in read-only section slack */
        DWORD old;
        if (g_xcaves[i][1] && !VirtualProtect(base + g_xcaves[i][0], g_xcaves[i][1], PAGE_EXECUTE_READ, &old))
            logf_("code cave %d: VirtualProtect failed (%lu)", i, GetLastError());
    }
    strcpy_s(g_ini, sizeof g_ini, ini);
    build_text_overrides(g_dir, text_enabled);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((BYTE *)inst + ((IMAGE_DOS_HEADER *)inst)->e_lfanew);
        DisableThreadLibraryCalls(inst);
        g_dll_base = (BYTE *)inst; g_dll_size = nt->OptionalHeader.SizeOfImage;
        run_patcher();
        AddVectoredExceptionHandler(1, crash_logger);
    } else if (reason == DLL_PROCESS_DETACH && g_log) {
        fclose(g_log); g_log = NULL;
    }
    return TRUE;
}

/* ---- version.dll pass-through (loaded from System32 on first use) ---- */
static HMODULE g_real;

static FARPROC real_proc(const char *name)
{
    if (!g_real) {
        wchar_t sys[MAX_PATH];
        UINT n = GetSystemDirectoryW(sys, MAX_PATH);
        if (n == 0 || n > MAX_PATH - 14) return NULL;
        wcscat_s(sys, MAX_PATH, L"\\version.dll");
        g_real = LoadLibraryW(sys);
        if (!g_real) return NULL;
    }
    return GetProcAddress(g_real, name);
}

#define PASS(ret, name, params, args, fail)                                        \
    ret WINAPI px_##name params  /* exported as <name> by suucp.def */            \
    {                                                                             \
        typedef ret (WINAPI *fn_t) params;                                        \
        static fn_t fn;                                                           \
        if (!fn) fn = (fn_t)real_proc(#name);                                     \
        if (!fn) { SetLastError(ERROR_PROC_NOT_FOUND); return fail; }             \
        return fn args;                                                           \
    }

PASS(BOOL, GetFileVersionInfoA, (LPCSTR f, DWORD h, DWORD l, LPVOID d), (f, h, l, d), FALSE)
PASS(BOOL, GetFileVersionInfoW, (LPCWSTR f, DWORD h, DWORD l, LPVOID d), (f, h, l, d), FALSE)
PASS(BOOL, GetFileVersionInfoExA, (DWORD fl, LPCSTR f, DWORD h, DWORD l, LPVOID d), (fl, f, h, l, d), FALSE)
PASS(BOOL, GetFileVersionInfoExW, (DWORD fl, LPCWSTR f, DWORD h, DWORD l, LPVOID d), (fl, f, h, l, d), FALSE)
PASS(DWORD, GetFileVersionInfoSizeA, (LPCSTR f, LPDWORD h), (f, h), 0)
PASS(DWORD, GetFileVersionInfoSizeW, (LPCWSTR f, LPDWORD h), (f, h), 0)
PASS(DWORD, GetFileVersionInfoSizeExA, (DWORD fl, LPCSTR f, LPDWORD h), (fl, f, h), 0)
PASS(DWORD, GetFileVersionInfoSizeExW, (DWORD fl, LPCWSTR f, LPDWORD h), (fl, f, h), 0)
PASS(BOOL, VerQueryValueA, (LPCVOID b, LPCSTR s, LPVOID *p, PUINT n), (b, s, p, n), FALSE)
PASS(BOOL, VerQueryValueW, (LPCVOID b, LPCWSTR s, LPVOID *p, PUINT n), (b, s, p, n), FALSE)
PASS(DWORD, VerLanguageNameA, (DWORD l, LPSTR s, DWORD n), (l, s, n), 0)
PASS(DWORD, VerLanguageNameW, (DWORD l, LPWSTR s, DWORD n), (l, s, n), 0)
PASS(DWORD, VerFindFileA, (DWORD fl, LPCSTR a, LPCSTR b, LPCSTR c, LPSTR d, PUINT e, LPSTR f, PUINT g),
     (fl, a, b, c, d, e, f, g), 0)
PASS(DWORD, VerFindFileW, (DWORD fl, LPCWSTR a, LPCWSTR b, LPCWSTR c, LPWSTR d, PUINT e, LPWSTR f, PUINT g),
     (fl, a, b, c, d, e, f, g), 0)
PASS(DWORD, VerInstallFileA, (DWORD fl, LPCSTR a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPSTR f, PUINT g),
     (fl, a, b, c, d, e, f, g), 0)
PASS(DWORD, VerInstallFileW, (DWORD fl, LPCWSTR a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPWSTR f, PUINT g),
     (fl, a, b, c, d, e, f, g), 0)
